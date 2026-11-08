"""Tests for the poc package (pytest-compatible, but also runs standalone:
    python3 tests/test_poc.py
    or:  python3 -m poc selftest )
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

from poc import metrics as M                      # noqa: E402
from poc.hitl import ApprovalLedger               # noqa: E402
from poc.planner import Planner                   # noqa: E402
from poc.pipeline import run_pipeline             # noqa: E402
from poc.schema import validate_step, step_token  # noqa: E402
from poc.state import DEMO_STATES, Surface        # noqa: E402
from poc.verifier import verify_plan              # noqa: E402
from poc.metrics import welch_test                # noqa: E402


def test_schema_six_verbs():
    good = {
        "step_id": 1, "action": "exfiltrate_simulated",
        "target": {"id": "data:users-db", "type": "data"},
        "technique": "T1567", "impact": "critical", "cvss": 9.3,
        "stealth_cost": 0.7, "rationale": "simulated exfiltration of "
                                          "the objective data store",
    }
    assert validate_step(good) == []
    bad = dict(good, action="nuke")
    assert validate_step(bad)
    assert step_token(good).startswith("HOLD-1-")


def test_verifier_blocks_out_of_scope_and_unreachable():
    surf = Surface(DEMO_STATES["web"]())
    plan = Planner(seed=2, config="unconstrained").build(surf, "data:users-db")
    res = verify_plan(plan, surf)   # verifying the verifier against drift
    reasons = " ".join(r for b in res["blocked"] for r in b["reasons"])
    assert "not an in-scope node" in reasons
    assert "SMT plan-feasibility" in reasons
    assert res["holds"]              # critical drift steps are held


def test_hitl_cautious_operator_denies_critical():
    holds = [{"step_id": 1, "token": step_token({"step_id": 1}),
              "action": "exfiltrate_simulated", "technique": "T1567",
              "impact": "critical"}]
    dec = ApprovalLedger().resolve(list(holds), "scripted-cautious")
    assert dec[1] == "denied"
    dec2 = ApprovalLedger().resolve(list(holds), "scripted-standard")
    assert dec2[1] == "approved"


def test_chain_lengths_match_ground_truth():
    for scenario, l_opt in (("web", 6), ("ad", 4), ("cloud", 4)):
        surf = Surface(DEMO_STATES[scenario]())
        obj = surf.state["ground_truth"]["objective_node"]
        assert len(surf.shortest_path("ATTACKER", obj)) == l_opt


def test_determinism_same_seed_same_metrics():
    a = run_pipeline("ad", "full", seed=99)
    b = run_pipeline("ad", "full", seed=99)
    assert a["metrics"] == b["metrics"]


def test_unconstrained_executes_unsafe_steps():
    rec = run_pipeline("web", "unconstrained", seed=8)
    # audited unsafe executions (drift + unverapproved critical) MUST erode Eq.5
    assert rec["metrics"]["safety"] < 1.0
    assert rec["metrics"]["n_steps_flagged"] >= 4
    full = run_pipeline("web", "full", seed=8)
    assert full["metrics"]["safety"] == 1.0


def test_ci95_and_welch_math():
    agg = M.mean_sd_ci([0.4, 0.5, 0.6, 0.5])
    assert agg["mean"] == 0.5 and agg["n"] == 4
    x = [0.8, 1.0, 1.2, 0.9, 1.1]
    y = [1.8, 2.0, 2.2, 1.9, 2.1]
    res = welch_test(x, y)
    assert res["p"] < 0.001, res
    res2 = welch_test([0.5, 0.51, 0.49, 0.5], [0.5, 0.52, 0.48, 0.51])
    assert res2["p"] > 0.2, res2


def test_real_state_passthrough():
    import copy
    st = copy.deepcopy(DEMO_STATES["ad"]())
    a = run_pipeline("ad", "full", seed=12, state=st)
    b = run_pipeline("ad", "full", seed=12)
    assert a["metrics"] == b["metrics"]
    st2 = copy.deepcopy(st)
    st2["edges"] = [e for e in st2["edges"] if e["rel"] != "phish"]
    raised = False
    try:
        run_pipeline("ad", "full", seed=12, state=st2)
    except ValueError:
        raised = True
    assert raised


def _run_all() -> int:
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failures = 0
    for fn in fns:
        try:
            fn()
            print("PASS {}".format(fn.__name__))
        except Exception as exc:  # noqa: BLE001
            failures += 1
            print("FAIL {} -> {}: {}".format(fn.__name__, type(exc).__name__,
                                             exc))
    print("{}/{} passed".format(len(fns) - failures, len(fns)))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())
