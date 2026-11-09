"""HTTP-level tests for gui/server.py (the local web console).

Runs the server on an ephemeral port against a temporary results root and
exercises every endpoint path the console uses. Stdlib-only; pytest
compatible. Expected runtime: ~ 30 s (dominated by the selftest + experiments
jobs).

    python3 tests/test_gui.py          # standalone runner
    pytest -q tests/                   # or via pytest
"""
from __future__ import annotations

import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gui.server import build_server            # noqa: E402

PASS, FAIL = [], []


def check(name: str, cond: bool, detail="") -> None:
    (PASS if cond else FAIL).append(name)
    print("[{}] {}{}".format("PASS" if cond else "FAIL", name,
                             (" — " + str(detail)) if (detail and not cond)
                             else ""))


def get(base: str, path: str) -> tuple:
    try:
        with urllib.request.urlopen(base + path, timeout=30) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def post_json(base: str, path: str, payload: dict, timeout: int = 60) -> tuple:
    req = urllib.request.Request(
        base + path, data=__import__("json").dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, __import__("json").loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, __import__("json").loads(e.read().decode())
        except Exception:
            return e.code, {}


def get_json(base: str, path: str) -> dict:
    import json
    return json.loads(get(base, path)[1].decode())


def wait_job(base: str, jid: str, deadline: float) -> dict:
    while time.time() < deadline:
        job = get_json(base, "/api/jobs/" + jid)
        if job["status"] in ("done", "error"):
            return job
        time.sleep(0.3)
    return {"status": "timeout"}


# ---------------------------------------------------------------------------
def run_all() -> int:
    tmp = tempfile.mkdtemp(prefix="autopent-gui-test-")
    httpd = build_server(host="127.0.0.1", port=0, results_root=tmp)
    port = httpd.server_address[1]
    base = "http://127.0.0.1:{}".format(port)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()

    try:
        # -- 1 health ------------------------------------------------------
        st, h = get(base, "/api/health")
        h = __import__("json").loads(h.decode())
        check("health 200 + ok", st == 200 and h.get("ok") is True, (st, h))
        check("health exposes engine + scenarios",
              h.get("verifier_engine") in ("z3-smt", "python-bfs-smt-style")
              and h.get("scenarios") == ["web", "ad", "cloud"], h)

        # -- 2 static shell ------------------------------------------------
        st, body = get(base, "/")
        check("index.html served", st == 200 and b"app.js" in body, st)
        st, body = get(base, "/static/app.js")
        check("app.js served", st == 200 and b"api/run" in body, st)
        st, body = get(base, "/static/style.css")
        check("style.css served", st == 200 and b"data-theme" in body, st)

        # -- 3 scenarios + samples ------------------------------------------
        scen = get_json(base, "/api/scenarios")
        check("scenarios list", len(scen["scenarios"]) == 3 and
              all(s["objective_node"] and s["optimal_path_length"]
                  for s in scen["scenarios"]), scen)
        samples = get_json(base, "/api/samples")
        names = {s["file"] for s in samples["samples"]}
        check("samples catalog (5 files)", names == {
            "state_web.json", "state_ad.json", "state_cloud.json",
            "state_mini_custom.json", "state_invalid_demo.json"}, names)

        # -- 4 validate-state ------------------------------------------------
        import json as _json
        good = _json.loads((Path("gui/samples/state_mini_custom.json")
                            .read_text()))
        v = post_json(base, "/api/validate-state", {"state": good})[1]
        check("validate good mini state", v["ok"] is True, v["errors"])
        bad = _json.loads((Path("gui/samples/state_invalid_demo.json")
                           .read_text()))
        v = post_json(base, "/api/validate-state", {"state": bad})[1]
        check("validate broken state flags errors",
              v["ok"] is False and len(v["errors"]) >= 3, v["errors"])

        # -- 5 single run (baked scenario) -----------------------------------
        st, r = post_json(base, "/api/run",
                          {"scenario": "ad", "config": "full", "seed": 3})
        check("run ad seed 3 ok", st == 200 and "record" in r, (st, r))
        if st == 200:
            m = r["record"]["metrics"]
            check("run metrics sane", 0 <= m["coverage"] <= 1 and
                  m["safety"] == 1.0 and m["objective_reached"] is True, m)
            check("run artifacts written", set(r["artifact_links"]) >= {
                "plan.json", "verifier.json", "exec_trace.json",
                "metrics.json", "approvals.jsonl"}, r["artifact_links"])

        # -- 6 single run (sample state) --------------------------------------
        st, r = post_json(base, "/api/run",
                          {"state_name": "state_mini_custom.json",
                           "config": "full", "seed": 11})
        check("run sample mini state ok", st == 200, (st, r))
        if st == 200 and r.get("record"):
            check("mini state run reaches objective",
                  r["record"]["metrics"]["objective_reached"] is True,
                  r["record"]["metrics"])

        # -- 7 run failure modes ----------------------------------------------
        st, r = post_json(base, "/api/run", {"scenario": "nope"})
        check("bad scenario -> 400", st == 400 and "scenario" in r["error"],
              (st, r))
        st, r = post_json(base, "/api/run", {"config": "banana",
                                             "scenario": "web"})
        check("bad config -> 400", st == 400, (st, r))
        st, r = post_json(base, "/api/run",
                          {"state": {"scenario": "web", "nodes": []}})
        check("state missing objective -> 400 with hint", st == 400 and
              "objective_node" in r["error"], (st, r))

        # -- 8 demo ---------------------------------------------------------
        st, d = post_json(base, "/api/demo", {"scenario": "web", "seed": 7})
        check("demo narrative", st == 200 and "-- metrics" in d["narrative"]
              and "objective reached" in d["narrative"], st)

        # -- 9 file endpoint -------------------------------------------------
        links = list(r.get("artifact_links", {}).values()) or \
            list(d.get("artifact_links", {}).values())
        st, body = get(base, links[0] if links else "/api/file?path=x")
        check("artifact served via /api/file", st == 200 and (
            body.startswith(b"{") or body.startswith(b"")), st)
        st, body = get(base, "/api/file?path=poc/pipeline.py")
        check(".py excluded (403)", st == 403, st)
        st, body = get(base, "/api/file?path=" +
                       "x/../../etc/passwd")
        check("traversal blocked", st == 403, st)

        # -- 10 experiments job-------------------------------------------------
        st, r = post_json(base, "/api/experiments", {"seeds": 2})
        check("experiments job accepted", st == 202 and "job_id" in r, (st, r))
        job = wait_job(base, r["job_id"], time.time() + 240)
        check("experiments job completes", job["status"] == "done",
              job.get("error"))
        if job["status"] == "done":
            s = job["result"]["summary"]
            check("summary has scenarios + welch",
                  set(s["scenarios"]) == {"web", "ad", "cloud"} and
                  "welch_tests" in s["scenarios"]["web"], list(s))
            figs = job["result"]["links"]["figures"]
            check("3 figures generated", len(figs) == 3, figs)
            st, body = get(base, figs[0])
            check("figure is a PNG", st == 200 and body[:4] == b"\x89PNG", st)
            st, body = get(base, job["result"]["links"]["table2.csv"])
            check("table2.csv served", st == 200 and
                  body.split(b"\n")[0].startswith(b"scenario,config"),
                  st)
            check("progress counters sane", job["total"] == 24
                  and job["done"] == 24, (job["done"], job["total"]))

        # -- 11 selftest job ---------------------------------------------------
        st, r = post_json(base, "/api/selftest", {})
        check("selftest job accepted", st == 202, (st, r))
        job = wait_job(base, r["job_id"], time.time() + 180)
        check("selftest 9/9", job["status"] == "done" and
              job["result"]["pass"] == 9 and job["result"]["fail"] == 0,
              job.get("result"))

        # -- 12 results listing -------------------------------------------------
        res = get_json(base, "/api/results")
        check("results lists runs + experiments",
              len(res["runs"]) >= 2 and len(res["experiments"]) >= 1
              and res["runs"][0]["links"], res)
    finally:
        httpd.shutdown()
        httpd.server_close()

    print("\n{} passed, {} failed".format(len(PASS), len(FAIL)))
    if FAIL:
        for f in FAIL:
            print("  FAILED:", f)
        return 1
    return 0


def test_gui_smoke():            # pytest entry point
    assert run_all() == 0


if __name__ == "__main__":
    raise SystemExit(run_all())
