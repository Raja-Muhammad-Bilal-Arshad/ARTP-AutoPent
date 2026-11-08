"""End-to-end PoC pipeline: plan -> verify -> HITL -> isolated execution ->
post-hoc audit -> metrics -> artifacts.

This is the single entry point used by the demo runner, the CLI and the
experiment driver, so every reported run was produced by exactly this code
path (fixing the paper's reproducibility gaps found in the audit).
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from . import metrics as M
from .executor import SimExecutor  # noqa: F401 (type reference only)
from .hitl import ApprovalLedger, apply_decisions
from .planner import Planner
from .rpc import RPCClient
from .state import DEMO_STATES, Surface
from .verifier import audit_run, engine_name, unverifier, verify_plan


def plan_objective() -> Dict[str, str]:
    """Objective node ids come from each state's ground_truth (Eq. 11 anchor)."""
    return {s: DEMO_STATES[s]().get("ground_truth", {}).get("objective_node", "")
            for s in DEMO_STATES}


def run_pipeline(scenario: str, config: str = "full", seed: int = 1,
                 outdir: Optional[str] = None,
                 operator: str = "scripted-standard",
                 approve_all: bool = False,
                 approve_tokens: Optional[List[str]] = None,
                 interactive: bool = False,
                 state: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """One deterministic engagement in the sandbox. Returns the run record.

    ``state`` (optional) replaces a baked demo scenario with a caller-supplied
    state dict (real-lab export, AD topology from BloodHound, custom sandbox).
    Same pipeline — planner, verifier, HITL, isolated RPC execution and
    metrics — runs unchanged against that topology. The state dict must
    provide: ``scenario`` (web|ad|cloud), ``nodes``, ``edges``,
    ``policies``, and ``ground_truth`` with ``objective_node``,
    ``optimal_path_length`` and ``recon_targets``.
    """
    assert config in ("full", "without_verifier", "unconstrained",
                      "baseline_random_walk")

    # 1 -- surface + policy -------------------------------------------------
    state_provided = state is not None
    if state is None:
        assert scenario in DEMO_STATES, "unknown scenario " + scenario
        state = DEMO_STATES[scenario]()
    else:
        scenario = state.get("scenario", scenario)
    surf = Surface(state)
    gt = state.get("ground_truth") or {}
    objective = gt.get("objective_node")
    if not objective:
        raise ValueError(
            "state '{}': ground_truth.objective_node is required "
            "(planning anchor, Eq. 11)".format(
                (state.get("meta") or {}).get("name", scenario)))

    # 2 -- planning ---------------------------------------------------------
    planner = Planner(seed=seed, config=config)
    plan = planner.build(surf, objective)

    # 3 -- verification + approval holds ------------------------------------
    # Only the `full` configuration runs the complete framework (Sec. 4.2
    # ablations): without_verifier / unconstrained / random-walk baseline all
    # operate WITHOUT the verifier layer.
    if config == "full":
        vres = verify_plan(plan, surf)
    else:
        vres = unverifier(plan)          # verifier layer switched OFF
    plan_final = vres["plan_final"]

    # 4 -- human-in-the-loop gate ------------------------------------------
    approvals_path = os.path.join(outdir, "approvals.jsonl") if outdir else None
    ledger = ApprovalLedger(path=approvals_path)
    mode = "interactive" if interactive else (
        "explicit-token" if (approve_all or approve_tokens) else operator)
    decisions = ledger.resolve(vres["holds"], mode=mode,
                               plan_name=plan.get("plan_name", "?"),
                               approve_all=approve_all,
                               approve_tokens=approve_tokens or [])
    executed_plan = apply_decisions(plan_final["steps"], decisions)
    approved_ids = [sid for sid, d in decisions.items() if d == "approved"]

    # 5 -- isolated execution over JSON-RPC ---------------------------------
    init_params: Dict[str, Any] = {"scenario": scenario}
    if state_provided:
        init_params["state"] = state          # child process runs THIS topology
    with RPCClient(seed=seed) as rpc:
        session_info = rpc.call("initialize", init_params)
        trace: List[Dict[str, Any]] = []
        terminated = False
        for step in executed_plan:
            if terminated:
                trace.append({"step_id": step.get("step_id"), "skipped": True,
                              "reason": "session terminated after detection"})
                continue
            res = rpc.call("exec.action", {"step": step})
            trace.append(res)
            if res.get("terminated_session"):
                terminated = True
        summary = rpc.call("exec.finish", {})

    # 6 -- post-hoc audit (runs even when the verifier was disabled) --------
    executed_ids = [r["step_id"] for r in trace if not r.get("skipped")]
    flags = audit_run(executed_plan, executed_ids, surf,
                      approved_ids=approved_ids,
                      verifier_enabled=vres["enabled"])

    # 7 -- metrics (M = {Coverage, Efficiency, Safety, Stealth}, Eq. 2-11) ---
    compromised = summary.get("compromised", [])
    m = M.compute_run_metrics(surf, {"steps": executed_plan}, trace,
                              compromised, flags)
    if summary.get("mttd_sim_seconds") is not None:
        m["mttd_sim_seconds"] = summary["mttd_sim_seconds"]

    record = {
        "engine": "poc-" + engine_name(),
        "plan_name": plan.get("plan_name"),
        "scenario": scenario,
        "config": config,
        "seed": seed,
        "operator": mode,
        "session": session_info,
        "verification": {k: vres[k] for k in
                         ("enabled", "engine", "z3_available", "z3_verdict",
                          "n_steps_in", "n_steps_out", "blocked", "holds",
                          "checks")},
        "holds_resolved": decisions,
        "audit_flags": {str(k): v for k, v in flags.items()},
        "metrics": m,
        "plan": plan,
        "plan_final_steps": executed_plan,
        "trace": trace,
        "summary": summary,
        "detected_events": len([r for r in trace if r.get("detected")]),
        "sim_notes": {
            "epsilon_noise": 0.05,
            "prng": "random.Random(seed) + random.Random(seed*100003+7)",
            "simulation_only": "no live targets contacted; all telemetry "
                               "simulated, times are simulated seconds",
        },
    }

    # 8 -- artifacts ----------------------------------------------------------
    if outdir:
        _write_artifacts(record, outdir, surf)
    return record


def _write_artifacts(record: Dict[str, Any], outdir: str,
                     surf: Surface) -> None:
    os.makedirs(outdir, exist_ok=True)
    # approvals.jsonl is written by the ledger when holds exist; materialize
    # an empty file regardless so every run dir has the full artifact set
    approvals_path = os.path.join(outdir, "approvals.jsonl")
    if not os.path.exists(approvals_path):
        open(approvals_path, "a", encoding="utf-8").close()
    _json_dump(os.path.join(outdir, "plan.json"),
               {"plan": record["plan"],
                "plan_final_steps": record["plan_final_steps"],
                "objective_node": record["plan"].get("objective_node"),
                "ground_truth": record["plan"].get("ground_truth")})
    _json_dump(os.path.join(outdir, "verifier.json"),
               {k: v for k, v in record["verification"].items()
                if k != "plan_final"})
    _json_dump(os.path.join(outdir, "exec_trace.json"),
               {"session": record["session"], "trace": record["trace"],
                "summary": record["summary"]})
    _json_dump(os.path.join(outdir, "metrics.json"), record["metrics"])
    # surface-focus CSV (Table-4 style) for the AD scenario
    if surf.scenario == "ad":
        _write_surface_focus(surf, record, os.path.join(outdir,
                                                        "surface_focus.csv"))


def _write_surface_focus(surf: Surface, record: Dict[str, Any],
                         path: str) -> None:
    """Paper Table 4-style: BFS ego-graph of the objective (hop distance)."""
    obj = record["plan"].get("objective_node")
    dist = {obj: 0}
    frontier = [obj]
    while frontier:
        nxt: List[str] = []
        for n in frontier:
            for e in surf.edges:
                other = e["to"] if e["from"] == n else (
                    e["from"] if e["to"] == n else None)
                if other and other not in dist and other != "ATTACKER":
                    dist[other] = dist[n] + 1
                    nxt.append(other)
        frontier = nxt
        if max(dist.values()) >= 3:
            break
    compromised = set(record["summary"].get("compromised", []))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("node_id,hops_from_objective,in_scope,compromised\n")
        for nid, hops in sorted(dist.items(), key=lambda kv: (kv[1], kv[0])):
            fh.write("{},{},{},{}\n".format(
                nid, hops, int(surf.is_in_scope(nid)),
                int(nid in compromised)))


def _json_dump(path: str, payload: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True, default=str)
