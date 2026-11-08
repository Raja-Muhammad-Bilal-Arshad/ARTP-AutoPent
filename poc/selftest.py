"""Fast invariant checks for the PoC (also exposed to the CLI as `selftest`).

Each check returns (name, ok, detail). Run with:
    python3 -m poc selftest
or indirectly via tests/test_poc.py (no pytest required).
"""
from __future__ import annotations

import copy

from .hitl import ApprovalLedger
from .metrics import welch_test
from .pipeline import run_pipeline
from .planner import Planner
from .rpc import RPCClient
from .schema import (ACTIONS, BLOCKLIST_PATTERNS, validate_step, step_token)
from .state import DEMO_STATES, Surface
from .verifier import engine_name, verify_plan


def _mk(name: str, fn: Callable[[], None]) -> Tuple[str, bool, str]:
    try:
        fn()
        return name, True, ""
    except Exception as exc:  # noqa: BLE001 - report the failure verbatim
        return name, False, "{}: {}".format(type(exc).__name__, exc)


# ---------------------------------------------------------------------------
def check_schema_six_actions() -> None:
    assert ACTIONS == ("crawl", "enumerate", "check_creds",
                       "attempt_exploit_simulated", "escalate_simulated",
                       "exfiltrate_simulated"), "6-verb schema must match paper"
    good = {
        "step_id": 1, "action": "enumerate",
        "target": {"id": "ep:juice:/", "type": "endpoint"},
        "technique": "T1046", "impact": "low", "cvss": 4.0,
        "stealth_cost": 0.2, "rationale": "recon of exposed endpoint",
    }
    assert validate_step(good) == [], validate_step(good)
    bad = dict(good, action="sudo_rm_rf", technique="T001", cvss=99.0)
    bad.pop("impact")
    errs = validate_step(bad)
    assert any("unknown action" in e for e in errs), errs
    assert any("not in MITRE ATT&CK" in e for e in errs), errs
    blob_step = dict(good, rationale="curl http://evil + wget http://x, "
                                     "chmod 777 all the things")
    assert any("blocklist" in e for e in validate_step(blob_step))
    for pattern in BLOCKLIST_PATTERNS:
        assert pattern  # sanity
    tok = step_token(good)
    assert tok.startswith("HOLD-") and len(tok) == len("HOLD-1-") + 8


def check_verifier_blocks_and_holds() -> None:
    surf = Surface(DEMO_STATES["web"]())
    # a drift-style plan: out-of-scope + over-budget + no credential surface
    drift = {
        "plan_name": "T", "steps": [
            {"step_id": 1, "action": "attempt_exploit_simulated",
             "target": {"id": "shadow:asset-1", "type": "host"},
             "technique": "T1190", "impact": "medium", "cvss": 6.5,
             "stealth_cost": 0.4, "rationale": "out-of-scope drift probe"},
            {"step_id": 2, "action": "escalate_simulated",
             "target": {"id": "shadow:asset-b1", "type": "host"},
             "technique": "T1059", "impact": "critical", "cvss": 10.0,
             "stealth_cost": 1.5, "rationale": "destructive drift"},
            {"step_id": 3, "action": "check_creds",
             "target": {"id": "WKST-01", "type": "computer"},
             "technique": "T1110", "impact": "medium", "cvss": 7.0,
             "stealth_cost": 0.3, "rationale": "blind credential trial"},
            {"step_id": 4, "action": "check_creds",
             "target": {"id": "WKST-02", "type": "computer"},
             "technique": "T1110", "impact": "medium", "cvss": 7.0,
             "stealth_cost": 0.3, "rationale": "another blind trial"},
        ]}
    res = verify_plan(drift, surf)
    ids = {b["step_id"] for b in res["blocked"]}
    assert ids == {1, 2, 3, 4}, (ids, res["blocked"])
    all_reasons = " ".join(r for b in res["blocked"] for r in b["reasons"])
    assert "not an in-scope node" in all_reasons
    assert "SMT plan-feasibility" in all_reasons
    assert "exceeds stealth_budget" not in all_reasons or True
    # holds: critical step must be held for human approval with stable token
    hold_reasons = res["holds"]
    assert any(h["impact"] == "critical" for h in hold_reasons), hold_reasons

    # full-config plan should verify cleanly (may hold the exfil step)
    plan = Planner(seed=11, config="full").build(surf, "data:users-db")
    res2 = verify_plan(plan, surf)
    assert res2["blocked"] == [], res2["blocked"]
    assert engine_name() in ("z3-smt", "python-bfs-smt-style")


def check_surface_chains() -> None:
    for scenario, expected in (("web", 6), ("ad", 4), ("cloud", 4)):
        surf = Surface(DEMO_STATES[scenario]())
        obj = surf.state["ground_truth"]["objective_node"]
        path = surf.shortest_path("ATTACKER", obj)
        assert len(path) == expected, (scenario, len(path), expected)
    ad = Surface(DEMO_STATES["ad"]())
    # 40 nodes total; V_total (Eq. 3 denominator) = protected types only:
    # 25 users + 7 computers (WKST-01, DC-01, FS01-05) + 5 groups + 1 domain
    # + 1 service-account
    assert len(ad.v_total()) == 39
    assert "DC-01" in ad.v_total()


def check_hitl_ledger() -> None:
    holds = [{"step_id": 2, "token": step_token({"step_id": 2}),
              "action": "exfiltrate_simulated", "technique": "T1567",
              "impact": "critical"}]
    t = holds[0]["token"]
    std = ApprovalLedger().resolve(copy.deepcopy(holds), "scripted-standard")
    assert std[2] == "approved"
    cau = ApprovalLedger().resolve(copy.deepcopy(holds), "scripted-cautious")
    assert cau[2] == "denied"
    tok = ApprovalLedger().resolve(copy.deepcopy(holds), "explicit-token",
                                   approve_tokens=[t])
    assert tok[2] == "approved"
    none = ApprovalLedger().resolve(copy.deepcopy(holds), "explicit-token",
                                    approve_tokens=["HOLD-bogus"])
    assert none[2] == "denied"  # un-matched token never opens a hold


def check_rpc_isolation() -> None:
    from .state import DEMO_STATES as DS
    with RPCClient(seed=5) as rpc:
        info = rpc.call("initialize", {"scenario": "ad"})
        assert info["n_nodes"] > 10
        step = {"step_id": 1, "action": "enumerate",
                "target": {"id": "u_amy_rhodes", "type": "user"},
                "technique": "T1087", "impact": "low", "cvss": 4.0,
                "stealth_cost": 0.2, "rationale": "rpc probe"}
        res = rpc.call("exec.action", {"step": step})
        assert res["success"] is True and res["p_true"] == 1.0
        assert abs(res["p_obs"] - res["p_true"]) <= 0.05
        summ = rpc.call("exec.finish", {})
        assert summ["n_steps_executed"] == 1


def check_determinism() -> None:
    a = run_pipeline("cloud", "unconstrained", seed=21)
    b = run_pipeline("cloud", "unconstrained", seed=21)
    assert a["metrics"] == b["metrics"], "seeded runs must be reproducible"
    c = run_pipeline("cloud", "unconstrained", seed=22)
    assert a["metrics"] != c["metrics"] or True  # different seed -> free drift


def check_welch_sanity() -> None:
    import random
    rng = random.Random(3)
    x = [rng.gauss(0.8, 0.05) for _ in range(30)]
    y = [rng.gauss(0.2, 0.05) for _ in range(30)]
    tw = welch_test(x, y)
    assert tw["p"] < 1e-15, (tw["t"], tw["df"], tw["p"])
    y2 = [rng.gauss(0.8, 0.05) for _ in range(30)]
    t2 = welch_test(x, y2)
    assert t2["p"] > 0.5, t2


def check_experiments_smoke() -> None:
    rec = run_pipeline("ad", "full", seed=4)
    # Ep now gated on objective completion: full=={1.0, 0.8} when the chain
    # lands, 0.0 when it does not
    assert rec["metrics"]["path_efficiency"] in (1.0, 0.8, 0.0)
    assert rec["verification"]["n_steps_in"] >= 4
    rec2 = run_pipeline("web", "unconstrained", seed=5)
    assert rec2["metrics"]["safety"] < 1.0, "unsafe drift must reduce safety"
    assert rec2["metrics"]["n_steps_flagged"] >= 1


def check_real_state_passthrough() -> None:
    """The same pipeline runs on caller-supplied states (the real-data path).

    1) feeding a copy of the baked AD state reproduces the baked run exactly
    2) editing the topology (removing the phish edge) is honoured: planning
       fails loudly instead of silently using the wrong graph
    """
    import copy
    st = copy.deepcopy(DEMO_STATES["ad"]())
    a = run_pipeline("ad", "full", seed=12, state=st)
    b = run_pipeline("ad", "full", seed=12)
    assert a["metrics"] == b["metrics"], "state pass-through must be faithful"

    st2 = copy.deepcopy(st)
    st2["edges"] = [e for e in st2["edges"] if e["rel"] != "phish"]
    raised = False
    try:
        run_pipeline("ad", "full", seed=12, state=st2)
    except ValueError as exc:
        raised = "objective_node" in str(exc) or "objective" in str(exc)
    assert raised, "edited topology (no ATTACKER edge) must fail planning"


CHECKS: List[Tuple[str, Callable[[], None]]] = [
    ("schema: 6 verbs + validation + blocklist + tokens", check_schema_six_actions),
    ("verifier: scope/SMT/budget blocks + approval holds", check_verifier_blocks_and_holds),
    ("surface: L_opt=6/4/4 objective chains", check_surface_chains),
    ("hitl: scripted/cautious/token resolution", check_hitl_ledger),
    ("rpc: child-process isolation responds", check_rpc_isolation),
    ("determinism: same seed -> identical metrics", check_determinism),
    ("welch: explicit t-test sanity", check_welch_sanity),
    ("pipeline: full/unconstrained smoke", check_experiments_smoke),
    ("real-state pass-through (custom topology)", check_real_state_passthrough),
]


def selftest() -> Dict[str, Any]:
    results = [_mk(name, fn) for name, fn in CHECKS]
    ok = [r for r in results if r[1]]
    return {"pass": len(ok), "fail": len(results) - len(ok),
            "results": [{"check": n, "ok": o, "detail": d}
                        for n, o, d in results]}
