"""AutoPENT GUI server — local web console for the simulation-only PoC.

A small, dependency-free HTTP server (Python stdlib only) that exposes the
PoC's functionality to a browser:

    GET  /                          the single-page console (gui/static/)
    GET  /api/health                feature flags (z3, matplotlib, engine)
    GET  /api/scenarios             baked demo scenarios + ground truth
    GET  /api/samples               gui/samples/*.json catalog
    POST /api/run                   one controlled engagement (baked / sample
                                    / custom state); <1 s, synchronous
    POST /api/demo                  narrative walkthrough (same as CLI demo)
    POST /api/experiments           background job: N seeds table-2 pipeline
    GET  /api/jobs/<id>             poll a background job
    POST /api/selftest              background job: the 9 PoC invariants
    POST /api/validate-state        structural validation of a custom state
    GET  /api/results               past GUI runs & experiment jobs
    GET  /api/file?path=...         whitelisted artifact/result file serving

Server binds 127.0.0.1 by default (never exposed to the network). Every
endpoint delegates the actual work to the poc/ package — the GUI is a thin
shell; it adds no planning, verification or execution logic of its own.

Launch:  ./run_gui.sh   (or  python3 -m gui.server). Open http://127.0.0.1:8787
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import threading
import time
import traceback
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import quote, urlparse, parse_qs

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:          # run from any working directory
    sys.path.insert(0, str(ROOT))

import poc                                            # noqa: E402
from poc.pipeline import run_pipeline                  # noqa: E402
from poc.selftest import selftest as poc_selftest      # noqa: E402
from poc.state import DEMO_STATES, Surface             # noqa: E402
from poc.verifier import engine_name                   # noqa: E402

APP_NAME = "AutoPENT Console"
APP_VERSION = poc.__version__
SCENARIOS = ("web", "ad", "cloud")
CONFIGS = ("full", "without_verifier", "unconstrained",
           "baseline_random_walk")
OPERATORS = ("scripted-standard", "scripted-cautious")
STATIC_DIR = Path(__file__).resolve().parent / "static"
SAMPLES_DIR = Path(__file__).resolve().parent / "samples"

MAX_BODY = 8 * 1024 * 1024          # 8 MiB request cap
MAX_TOKEN = 4096

SAMPLE_META: Dict[str, str] = {
    "state_web.json":
        "Baked web cluster (Juice-Shop-like, 12 nodes + decoys; L_opt=6).",
    "state_ad.json":
        "Baked Active Directory domain (40 nodes; paper's 4-hop kill chain).",
    "state_cloud.json":
        "Baked cloud lab (7 nodes; localstack-style misconfig chain).",
    "state_mini_custom.json":
        "MINI custom lab (4 nodes, 3 edges) — the smallest valid state; use "
        "to test the custom-state path quickly.",
    "state_invalid_demo.json":
        "Deliberately BROKEN state (typo scenario, dangling edge, missing "
        "objective) — use it on the States tab to see what validation catches.",
}

FILE_EXTS = {".json", ".jsonl", ".csv", ".png", ".txt", ".log", ".md",
             ".yml", ".yaml"}
STATIC_MIME = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
}
FILE_MIME = {
    ".json": "application/json; charset=utf-8",
    ".jsonl": "text/plain; charset=utf-8",
    ".csv": "text/csv; charset=utf-8",
    ".png": "image/png",
    ".txt": "text/plain; charset=utf-8",
    ".log": "text/plain; charset=utf-8",
    ".md": "text/plain; charset=utf-8",
    ".yml": "text/plain; charset=utf-8",
    ".yaml": "text/plain; charset=utf-8",
}


# ---------------------------------------------------------------------------
# background jobs
# ---------------------------------------------------------------------------
class Job:
    def __init__(self, jid: str, kind: str, total: int):
        self.id = jid
        self.kind = kind
        self.status = "running"                # running | done | error
        self.done = 0
        self.total = total
        self.label = "queued"
        self.result: Optional[Dict[str, Any]] = None
        self.error: Optional[str] = None
        self.started = time.time()

    def snapshot(self) -> Dict[str, Any]:
        return {"id": self.id, "kind": self.kind, "status": self.status,
                "done": self.done, "total": self.total, "label": self.label,
                "result": self.result, "error": self.error,
                "elapsed": round(time.time() - self.started, 1)}


class JobStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._jobs: Dict[str, Job] = {}

    def submit(self, kind: str, total: int,
               target: Callable[[Job], None]) -> Job:
        with self._lock:
            if kind == "experiments" and any(
                    j.status == "running" and j.kind == "experiments"
                    for j in self._jobs.values()):
                raise RuntimeError(
                    "an experiments job is already running; wait for it "
                    "or use a smaller seed count")
            jid = uuid.uuid4().hex[:10]
            job = Job(jid, kind, total)
            self._jobs[jid] = job

        def runner() -> None:
            try:
                target(job)
                job.status = "done"
                job.label = "done"
            except Exception as exc:            # noqa: BLE001 (surface to UI)
                job.status = "error"
                job.error = "{}: {}".format(type(exc).__name__, exc)
                job.label = "error"

        threading.Thread(target=runner, daemon=True, name="job-" + jid).start()
        return job

    def get(self, jid: str) -> Optional[Job]:
        with self._lock:
            return self._jobs.get(jid)

    def any_experiment_running(self) -> bool:
        with self._lock:
            return any(j.status == "running" and j.kind == "experiments"
                       for j in self._jobs.values())


JOBS = JobStore()


# ---------------------------------------------------------------------------
# state validation (the GUI's "required fields" contract, exercised in tests)
# ---------------------------------------------------------------------------
def validate_state(state: Any) -> Dict[str, Any]:
    """Structural + graph validation of a state dict.

    Mirrors what poc.pipeline.run_pipeline needs, so users get feedback BEFORE
    launching a run. Returns {ok, errors, warnings, info}.
    """
    errors: List[str] = []
    warnings: List[str] = []
    info: Dict[str, Any] = {}
    if not isinstance(state, dict):
        return {"ok": False,
                "errors": ["state must be a JSON object at the top level"],
                "warnings": warnings, "info": info}

    scenario = state.get("scenario")
    if scenario not in SCENARIOS:
        errors.append("field 'scenario' is required and must be one of "
                      + ", ".join(SCENARIOS)
                      + " (got {!r})".format(scenario))

    nodes = state.get("nodes")
    node_ids: List[str] = []
    if not isinstance(nodes, list) or not nodes:
        errors.append("field 'nodes' is required: an array of "
                      "{\"id\", \"type\"[, ...attribute]} objects")
    else:
        seen: set = set()
        for n in nodes:
            if not isinstance(n, dict) or not n.get("id"):
                errors.append("every node needs at least an 'id' "
                              "(bad node: {!r})".format(n))
                continue
            if n["id"] in seen:
                errors.append("duplicate node id: {}".format(n["id"]))
            seen.add(n["id"])
            node_ids.append(n["id"])

    edges = state.get("edges")
    if not isinstance(edges, list) or not edges:
        errors.append("field 'edges' is required: an array of "
                      "{\"from\", \"to\", \"rel\"[, \"technique\"]} objects")
    else:
        for e in edges[:2000]:
            if not isinstance(e, dict):
                errors.append("every edge must be an object: {!r}".format(e))
                continue
            missing = [k for k in ("from", "to", "rel") if not e.get(k)]
            if missing:
                errors.append("edge missing field(s) {} "
                              "(edge: {!r})".format(missing, e))

    if node_ids and isinstance(edges, list):
        idset = set(node_ids)
        for e in edges:
            if isinstance(e, dict):
                for k in ("from", "to"):
                    ref = e.get(k)
                    if ref and ref not in idset:
                        errors.append("edge {} references unknown node {!r}"
                                      .format(k, ref))
        if "ATTACKER" not in idset:
            errors.append("a starting node 'ATTACKER' is required (planning "
                          "anchor of every chain)")

    policies = state.get("policies")
    if not isinstance(policies, dict):
        warnings.append("no 'policies' object — DEFAULT_POLICY from "
                        "poc/state.py will be applied (scope, max_impact, "
                        "requires_approval, stealth_budget, "
                        "credential_attempts_max)")
    else:
        for k in ("scope", "max_impact", "requires_approval",
                  "stealth_budget", "credential_attempts_max"):
            if k not in policies:
                warnings.append("policies.'{}' missing — default is used"
                                .format(k))

    gt = state.get("ground_truth")
    if not isinstance(gt, dict):
        errors.append("field 'ground_truth' is required: an object with "
                      "'objective_node', 'optimal_path_length', "
                      "'recon_targets'")
    else:
        objective = gt.get("objective_node")
        if not objective:
            errors.append("ground_truth.'objective_node' is required — it is "
                          "the planning anchor (Eq. 11)")
        elif node_ids and objective not in set(node_ids):
            errors.append("ground_truth.'objective_node' {!r} is not one of "
                          "the defined nodes".format(objective))

        l_opt = gt.get("optimal_path_length")
        if not isinstance(l_opt, int) or l_opt < 0:
            warnings.append("ground_truth.'optimal_path_length' should be an "
                            "int >= 0 (Ep = L_opt / L_obs is gated on it)")

        if not isinstance(gt.get("recon_targets"), list):
            warnings.append("ground_truth.'recon_targets' should be a list "
                            "of node ids for the recon-precision metric")

        # graph feasibility (only when the topology parsed cleanly)
        if objective and node_ids and isinstance(edges, list) and \
                all(isinstance(e, dict) for e in edges) and \
                "ATTACKER" in set(node_ids):
            try:
                surf = Surface(state)
                path = surf.shortest_path("ATTACKER", objective)
                if not path:
                    errors.append("objective {!r} is NOT reachable from "
                                  "ATTACKER — planning would fail; every "
                                  "objective needs an edge path from "
                                  "ATTACKER (see the planner's REL_ACTION "
                                  "relations)".format(objective))
                else:
                    info["computed_path_hops"] = len(path)
                    info["computed_path_relations"] = [
                        e["rel"] for e in path]
                    if isinstance(l_opt, int):
                        if abs(len(path) - l_opt) > 2:
                            warnings.append(
                                "optimal_path_length={} but the graph's "
                                "shortest ATTACKER->objective path is {} "
                                "hops — Ep only maxes out if these match"
                                .format(l_opt, len(path)))
                    known_rels = set()
                    try:
                        from poc.planner import REL_ACTION
                        known_rels = set(REL_ACTION)
                    except Exception:
                        pass
                    if known_rels:
                        unknown = [e["rel"] for e in path
                                   if e.get("rel") not in known_rels]
                        if unknown:
                            errors.append("path relations not in the "
                                          "planner's REL_ACTION map: {} "
                                          "(mapping exists for: {})"
                                          .format(unknown,
                                                  sorted(known_rels)))
            except Exception as exc:
                warnings.append("graph feasibility could not be checked: "
                                "{}".format(exc))

    if node_ids:
        info["node_count"] = len(node_ids)
        info["edge_count"] = len(edges) if isinstance(edges, list) else None
        if scenario in SCENARIOS and isinstance(edges, list):
            try:
                info["v_total"] = len(Surface(state).v_total())
            except Exception:
                pass
    return {"ok": not errors, "errors": errors, "warnings": warnings,
            "info": info}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


def _slug(name: str, maxlen: int = 40) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "-",
                  name)[:maxlen].strip("-") or "run"


def _new_run_dir(results_root: str, scenario: str, seed: int,
                 config: str) -> str:
    base = "{ts}-{scen}-s{seed:04d}-{cfg}".format(
        ts=time.strftime("%Y%m%d-%H%M%S"), scen=_slug(scenario, 16),
        seed=seed, cfg=_slug(config, 22))
    run_dir = os.path.join(results_root, "runs", base)
    n = 2
    while os.path.exists(run_dir):          # collision-safe (same-second runs)
        run_dir = "{}-{}".format(os.path.join(results_root, "runs",
                                              base), n)
        n += 1
    return run_dir


def _artifact_links(run_dir: str) -> Dict[str, str]:
    files = ("plan.json", "verifier.json", "approvals.jsonl",
             "exec_trace.json", "metrics.json", "surface_focus.csv")
    links: Dict[str, str] = {}
    for fn in files:
        if os.path.exists(os.path.join(run_dir, fn)):
            links[fn] = "/api/file?path=" + quote(os.path.join(run_dir, fn))
    return links


def _narrate(rec: Dict[str, Any]) -> str:
    """The CLI demo's narrative text, rebuilt from the record (GUI version)."""
    m = rec["metrics"]
    v = rec["verification"]
    lines: List[str] = []
    lines.append("== DEMO  scenario={}  config={}  seed={}  (engine {})"
                 .format(rec["scenario"], rec["config"], rec["seed"],
                         rec["engine"]))
    lines.append("-- plan ({}): {} steps in -> {} steps after verification"
                 .format(rec["plan_name"], v["n_steps_in"], v["n_steps_out"]))
    for s in rec["plan_final_steps"]:
        lines.append("   {:>2}. [{:<25}] {:<22} T={:<9} impact={:<8} "
                     "cvss={:.1f} r={}".format(
                         s["step_id"], s["action"], s["target"]["id"],
                         s["technique"], s["impact"], s["cvss"] or 0.0,
                         s["stealth_cost"]))
    if v.get("blocked"):
        lines.append("-- verifier BLOCKED:")
        for b in v["blocked"]:
            lines.append("   step {}: {}".format(b["step_id"],
                                                 "; ".join(b["reasons"])))
    if v.get("holds"):
        lines.append("-- HITL holds (impact >= requires_approval):")
        for h in v["holds"]:
            lines.append("   step {}: {} -> {}".format(
                h["step_id"], h["token"],
                rec["holds_resolved"].get(h["step_id"], "?")))
    lines.append("")
    lines.append("-- simulated execution (JSON-RPC child, session {}):"
                 .format(rec["session"]["session"]))
    for r in rec["trace"]:
        if r.get("skipped"):
            lines.append("   {:>2}. SKIP   ({})".format(
                r.get("step_id"), r["reason"]))
            continue
        det = "  [ALERT]" if r.get("detected") else ""
        lines.append("   {:>2}. {} target={:<26} p_obs={:.2f} {} D={:.2f}{}"
                     .format(r["step_id"], "OK " if r["success"] else "FAIL",
                             r.get("target_id", "?"), r["p_obs"],
                             "reached" if r.get("compromised") else "      ",
                             r["d_score"], det))
    lines.append("")
    lines.append("-- metrics (Eqs. 2-11):")
    for k in ("coverage", "path_efficiency", "safety", "stealth",
              "composite_r", "detection_rate", "recon_precision",
              "recon_recall", "mttd_sim_seconds"):
        lines.append("   {:<20} = {}".format(k, m.get(k)))
    lines.append("   objective reached      = {}".format(m["objective_reached"]))
    lines.append("note: simulation-only — telemetry and times are simulated")
    return "\n".join(lines)


def _safe_sample_path(name: str) -> Optional[Path]:
    if not re.fullmatch(r"[A-Za-z0-9_.\-]+", name or ""):
        return None
    p = (SAMPLES_DIR / name).resolve()
    if SAMPLES_DIR.resolve() not in p.parents and p != SAMPLES_DIR:
        return None
    if p.suffix != ".json":
        return None
    return p


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "AutoPENT/" + APP_VERSION
    protocol_version = "HTTP/1.1"
    results_root = str(ROOT / "results" / "poc" / "gui")

    # quiet, concise logging -------------------------------------------------
    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: N802
        sys.stderr.write("[gui] {} {}\n".format(
            time.strftime("%H:%M:%S"), fmt % args))

    # -- response helpers ----------------------------------------------------
    def _send(self, status: int, body: bytes, ctype: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, obj: Any, status: int = 200) -> None:
        self._send(status,
                   json.dumps(obj, indent=2, sort_keys=True,
                              default=str).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _body(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            raise ValueError("empty request body (expected JSON object)")
        if length > MAX_BODY:
            raise ValueError("request body too large ({} bytes > cap)"
                             .format(length))
        raw = self.rfile.read(length)
        try:
            obj = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise ValueError("invalid JSON body: {}".format(exc))
        if not isinstance(obj, dict):
            raise ValueError("JSON body must be an object")
        return obj

    # -- routing -------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        try:
            parsed = urlparse(self.path)
            path = parsed.path
            query = parse_qs(parsed.query)

            if path in ("/", "/index.html"):
                return self._static("index.html")
            if path.startswith("/static/"):
                return self._static(path[len("/static/"):])
            if path.startswith("/favicon"):
                return self._send(204, b"", "image/x-icon")

            if path == "/api/health":
                return self._api_health()
            if path == "/api/scenarios":
                return self._api_scenarios()
            if path == "/api/samples":
                return self._api_samples()
            if path == "/api/results":
                return self._api_results()
            if path == "/api/jobs" and query.get("id"):
                return self._api_job(query["id"][0])
            if path.startswith("/api/jobs/"):
                return self._api_job(path[len("/api/jobs/"):])
            if path == "/api/file" and query.get("path"):
                return self._api_file(query["path"][0])

            return self._json({"error": "unknown endpoint " + path}, 404)
        except Exception as exc:  # noqa: BLE001
            return self._json({"error": "internal: {}".format(exc)}, 500)

    def do_POST(self) -> None:  # noqa: N802
        try:
            path = urlparse(self.path).path
            body = self._body()
            if path == "/api/run":
                return self._api_run(body)
            if path == "/api/demo":
                return self._api_demo(body)
            if path == "/api/experiments":
                return self._api_experiments(body)
            if path == "/api/selftest":
                return self._api_selftest(body)
            if path == "/api/validate-state":
                return self._json(validate_state(body.get("state")))
            return self._json({"error": "unknown endpoint " + path}, 404)
        except ValueError as exc:
            return self._json({"error": str(exc)}, 400)
        except RuntimeError as exc:
            return self._json({"error": str(exc)}, 409)
        except Exception as exc:  # noqa: BLE001
            return self._json({"error": "internal: {}".format(exc),
                               "trace": traceback.format_exc(limit=4)}, 500)

    # -- basic routes ----------------------------------------------------------
    def _static(self, name: str) -> None:
        fname = os.path.basename(name)
        p = STATIC_DIR / fname
        if not p.is_file() or p.suffix not in STATIC_MIME:
            return self._json({"error": "no such static file " + fname}, 404)
        self._send(200, p.read_bytes(), STATIC_MIME[p.suffix])

    def _api_file(self, relpath: str) -> None:
        # serve files from the repository tree OR the configured results root
        # (tests run with a temp results root outside the repo).
        # NOTE: no lstrip here — an absolute path must stay absolute; the
        # containment check below is the security boundary.
        candidate = relpath.replace("\\", "/")
        real = os.path.realpath(candidate if os.path.isabs(candidate)
                                else os.path.join(str(ROOT), candidate))
        allowed_roots = [os.path.realpath(str(ROOT)),
                         os.path.realpath(self.results_root)]
        if not any(real.startswith(r + os.sep) and os.path.isfile(real)
                   for r in allowed_roots):
            return self._json({"error": "path not served (outside the "
                               "repo / results root, missing, or a "
                               "directory)"}, 403)
        ext = os.path.splitext(real)[1].lower()
        if ext == ".py" or ext not in FILE_EXTS:
            return self._json({"error": "file type {!r} is not exposed "
                              "(allowed: {})".format(
                                  ext, sorted(FILE_EXTS))}, 403)
        if ext == ".png":
            with open(real, "rb") as fh:
                self._send(200, fh.read(), FILE_MIME[ext])
            return
        with open(real, "r", encoding="utf-8", errors="replace") as fh:
            self._send(200, fh.read().encode("utf-8"), FILE_MIME[ext])

    # -- GET APIs --------------------------------------------------------------
    def _api_health(self) -> None:
        import importlib.util
        import platform
        self._json({
            "ok": True, "app": APP_NAME, "version": APP_VERSION,
            "python": "{} {}".format(platform.python_implementation(),
                                     platform.python_version()),
            "verifier_engine": engine_name(),
            "z3_available": importlib.util.find_spec("z3") is not None,
            "matplotlib_available":
                importlib.util.find_spec("matplotlib") is not None,
            "results_root": self.results_root,
            "simulation_only": "no live targets contacted; all telemetry "
                               "simulated; sandbox-scoped",
            "scenarios": list(SCENARIOS),
            "configs": list(CONFIGS),
        })

    def _api_scenarios(self) -> None:
        out = []
        for name in SCENARIOS:
            st = DEMO_STATES[name]()
            gt = st["ground_truth"]
            surf = Surface(st)
            out.append({
                "id": name,
                "name": st.get("meta", {}).get("name", name),
                "nodes": len(st["nodes"]),
                "edges": len(st["edges"]),
                "objective": gt.get("objective"),
                "objective_node": gt.get("objective_node"),
                "optimal_path_length": gt.get("optimal_path_length"),
                "l_opt_chains": len(surf.shortest_path("ATTACKER",
                                                       gt["objective_node"])),
                "v_total": len(surf.v_total()),
                "critical_nodes": sorted(surf.critical_nodes())[:8],
            })
        self._json({"scenarios": out})

    def _api_samples(self) -> None:
        out = []
        for fn in sorted(os.listdir(SAMPLES_DIR)):
            if fn.endswith(".json") and fn in SAMPLE_META:
                p = SAMPLES_DIR / fn
                st = json.loads(p.read_text(encoding="utf-8"))
                out.append({
                    "file": fn,
                    "bytes": p.stat().st_size,
                    "description": SAMPLE_META[fn],
                    "valid": validate_state(st)["ok"],
                    "link": "/api/file?path=gui/samples/" + fn,
                })
        self._json({"samples": out})

    def _api_results(self) -> None:
        runs_dir = os.path.join(self.results_root, "runs")
        exp_dir = os.path.join(self.results_root, "experiments")
        runs = []
        if os.path.isdir(runs_dir):
            for name in sorted(os.listdir(runs_dir), reverse=True)[:25]:
                d = os.path.join(runs_dir, name)
                if os.path.isdir(d):
                    links = _artifact_links(d)
                    runs.append({"name": name, "dir": d,
                                 "artifacts": sorted(links),
                                 "links": links})
        experiments = []
        if os.path.isdir(exp_dir):
            for name in sorted(os.listdir(exp_dir), reverse=True)[:25]:
                d = os.path.join(exp_dir, name)
                if os.path.isdir(d):
                    experiments.append({
                        "name": name, "dir": d,
                        "has_summary":
                            os.path.isfile(os.path.join(d, "summary.json")),
                        "has_figures":
                            os.path.isdir(os.path.join(d, "figures")),
                        "links": {
                            "summary.json": "/api/file?path=" + quote(
                                os.path.join(d, "summary.json")),
                            "table2.csv": "/api/file?path=" + quote(
                                os.path.join(d, "table2.csv")),
                            "figures": ["/api/file?path=" + quote(
                                os.path.join(d, "figures", fn))
                                for fn in sorted(os.listdir(
                                    os.path.join(d, "figures")))
                                if fn.endswith(".png")]
                                if os.path.isdir(os.path.join(d, "figures"))
                                else [],
                        },
                    })
        self._json({"runs": runs, "experiments": experiments})

    def _api_job(self, jid: str) -> None:
        job = JOBS.get(jid)
        if not job:
            return self._json({"error": "unknown job id " + jid}, 404)
        self._json(job.snapshot())

    # -- POST APIs ---------------------------------------------------------------
    def _resolve_state(self, body: Dict[str, Any]
                       ) -> Tuple[str, Optional[Dict[str, Any]]]:
        """Return (scenario_for_label, state_or_None) from the body source."""
        if body.get("state_name"):
            p = _safe_sample_path(str(body["state_name"]))
            if not p:
                raise ValueError("unknown sample state {!r}".format(
                    body["state_name"]))
            with open(p, "r", encoding="utf-8") as fh:
                return os.path.splitext(p.name)[0], json.load(fh)
        if body.get("state_json_string"):
            raw = str(body["state_json_string"])
            if len(raw) > MAX_TOKEN:
                raise ValueError("pasted state too large")
            return "custom", json.loads(raw)
        if body.get("state"):
            if not isinstance(body["state"], dict):
                raise ValueError("'state' must be a JSON object")
            return "custom", body["state"]
        scen = body.get("scenario")
        if scen not in SCENARIOS:
            raise ValueError("'scenario' must be one of {} (or supply a "
                             "state / sample)".format(list(SCENARIOS)))
        return str(scen), None

    def _api_run(self, body: Dict[str, Any]) -> None:
        label, state = self._resolve_state(body)
        config = body.get("config", "full")
        if config not in CONFIGS:
            raise ValueError("config must be one of {}".format(list(CONFIGS)))
        try:
            seed = int(body.get("seed", 1))
        except (TypeError, ValueError):
            raise ValueError("seed must be an integer")
        if not (1 <= seed <= 10 ** 6):
            raise ValueError("seed must be in [1, 1000000]")
        operator = body.get("operator", "scripted-standard")
        if operator not in OPERATORS:
            raise ValueError("operator must be one of {}".format(OPERATORS))
        approve_all = bool(body.get("approve_all", False))
        tokens = [t.strip() for t in (body.get("approve_tokens") or [])
                  if t and t.strip()]

        if state is not None:
            v = validate_state(state)
            if not v["ok"]:
                raise ValueError("state validation failed: "
                                 + " | ".join(v["errors"]))
            scenario_for_run = state.get("scenario") or body.get("scenario")
            if scenario_for_run not in SCENARIOS:
                scenario_for_run = scenario_for_run or "web"
            label = str(scenario_for_run)
        run_dir = _new_run_dir(self.results_root, label, seed, config)
        try:
            rec = run_pipeline(
                scenario=label if state is None else
                str(state.get("scenario") or body.get("scenario") or "web"),
                config=config, seed=seed,
                outdir=run_dir,                 # run_pipeline writes artifacts
                operator=operator, approve_all=approve_all,
                approve_tokens=tokens,
                state=state)
        except Exception:
            if os.path.isdir(run_dir) and not os.listdir(run_dir):
                os.rmdir(run_dir)               # don't leave empty shells
            raise

        self._json({
            "run_dir": run_dir,
            "artifact_links": _artifact_links(run_dir),
            "record": rec,
        })

    def _api_demo(self, body: Dict[str, Any]) -> None:
        scenario = body.get("scenario")
        if scenario not in SCENARIOS:
            raise ValueError("scenario must be one of {}"
                             .format(list(SCENARIOS)))
        try:
            seed = int(body.get("seed", 7))
        except (TypeError, ValueError):
            raise ValueError("seed must be an integer")
        outdir = os.path.join(self.results_root, "demo", str(scenario))
        rec = run_pipeline(scenario=str(scenario), config="full",
                           seed=seed, outdir=outdir)
        self._json({
            "scenario": scenario, "seed": seed, "run_dir": outdir,
            "artifact_links": _artifact_links(outdir),
            "narrative": _narrate(rec),
            "metrics": rec["metrics"],
        })

    def _api_experiments(self, body: Dict[str, Any]) -> None:
        try:
            seeds = int(body.get("seeds", 30))
        except (TypeError, ValueError):
            raise ValueError("seeds must be an integer")
        if not (1 <= seeds <= 200):
            raise ValueError("seeds must be in [1, 200] (30 ~ 20-40 s)")
        scenarios = body.get("scenarios") or list(SCENARIOS)
        if (not isinstance(scenarios, list) or not scenarios
                or any(s not in SCENARIOS for s in scenarios)):
            raise ValueError("scenarios must be a subset of {}"
                             .format(list(SCENARIOS)))
        if not _spec_available("matplotlib"):
            raise ValueError("matplotlib is not installed in this "
                             "environment — experiments regenerate figures "
                             "with it (pip install matplotlib)")

        stamp = time.strftime("%Y%m%d-%H%M%S")
        outdir = os.path.join(self.results_root, "experiments",
                              "{}-s{}".format(stamp, seeds))
        _ensure_dir(outdir)

        def target(job: Job) -> None:
            from poc.exp import run_experiments

            def cb(done: int, total: int, scen: str, cfg: str, seed_: int
                   ) -> None:
                job.done = done
                job.total = total
                job.label = "{}/{}  {} seed {}".format(done, total,
                                                        cfg, seed_)

            summary = run_experiments(scenarios=list(scenarios),
                                      n_seeds=seeds, outdir=outdir,
                                      progress_cb=cb)
            figs = sorted(os.listdir(os.path.join(outdir, "figures"))) \
                if os.path.isdir(os.path.join(outdir, "figures")) else []
            job.result = {
                "outdir": outdir,
                "summary": summary,
                "links": {
                    "summary.json": "/api/file?path=" + quote(
                        os.path.join(outdir, "summary.json")),
                    "table2.csv": "/api/file?path=" + quote(
                        os.path.join(outdir, "table2.csv")),
                    "figures": ["/api/file?path=" + quote(
                        os.path.join(outdir, "figures", fn))
                        for fn in figs if fn.endswith(".png")],
                },
            }

        job = JOBS.submit("experiments", len(scenarios) * 4 * seeds, target)
        self._json({"job_id": job.id, "poll": "/api/jobs/" + job.id}, 202)

    def _api_selftest(self, body: Dict[str, Any]) -> None:
        del body  # no parameters

        def target(job: Job) -> None:
            job.label = "running 9 PoC invariant checks..."
            res = poc_selftest()
            job.result = res

        job = JOBS.submit("selftest", 9, target)
        self._json({"job_id": job.id, "poll": "/api/jobs/" + job.id}, 202)


def _spec_available(mod: str) -> bool:
    import importlib.util
    return importlib.util.find_spec(mod) is not None


# ---------------------------------------------------------------------------
def build_server(host: str = "127.0.0.1", port: int = 8787,
                 results_root: Optional[str] = None) -> ThreadingHTTPServer:
    handler = type("BoundHandler", (Handler,), {
        "results_root": results_root or str(ROOT / "results" / "poc" / "gui")
    })
    httpd = ThreadingHTTPServer((host, port), handler)  # daemon threads on
    httpd.daemon_threads = True
    return httpd


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="gui.server", description=APP_NAME + " (simulation-only PoC)")
    ap.add_argument("--host", default="127.0.0.1",
                    help="bind address (default: 127.0.0.1 — local only)")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--no-browser", action="store_true",
                    help="do not auto-open the browser tab")
    ap.add_argument("--results", default=None,
                    help="GUI results root (default: results/poc/gui)")
    args = ap.parse_args(argv)

    httpd = build_server(host=args.host, port=args.port,
                         results_root=args.results)
    url = "http://{}:{}".format(args.host, httpd.server_address[1])
    print("=" * 64)
    print("{}  v{}  (simulation-only PoC console)".format(
        APP_NAME, APP_VERSION))
    print("  open        : {}".format(url))
    print("  results root: {}".format(
        args.results or str(ROOT / "results" / "poc" / "gui")))
    print("  verifier    : {}".format(engine_name()))
    print("  boundaries  : binds {} only; simulation-only; no live targets"
          .format(args.host))
    print("  Ctrl+C      : stop the server")
    print("=" * 64)
    if not args.no_browser:
        try:
            threading.Thread(target=webbrowser.open_new_tab(url),
                             daemon=True).start()
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[gui] stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
