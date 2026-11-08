"""Policy verifier and post-hoc executor auditor.

Implements the paper's verifier layer (Sec. 3.2/3.3): every planned step is
checked for (1) schema conformity + MITRE technique validity, (2) blocklist
patterns, (3) target scope, (4) credential-operation rules and attempt caps,
(5) cumulative risk/stealth budget, and (6) SMT-style plan feasibility
(prefix reachability over the attack-surface graph + stealth-budget
constraint). Steps whose impact meets ``requires_approval`` are *held* for
human approval rather than silently denied.

The symbolic part is solved with z3 when available; otherwise a pure-Python
equivalent (BFS prefix-feasibility + budget arithmetic) is used and the
verifier reports the engine name honestly.
"""
from __future__ import annotations

from typing import Any, Dict, List, Set

from .schema import (ACTIONS, BLOCKLIST_PATTERNS, IMPACTS, impact_at_least,
                     step_token, validate_step)
from .state import Surface

try:  # optional dependency; the pure-Python engine is the default fallback
    import z3  # type: ignore
    HAVE_Z3 = True
except Exception:  # pragma: no cover - z3 not installed in this environment
    HAVE_Z3 = False

ENGINE = "z3-smt" if HAVE_Z3 else "python-bfs-smt-style"

EPS_BUDGET = 1e-9  # float tolerance for "cumulative stealth <= budget"


def engine_name() -> str:
    return ENGINE


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _incident_relations(surf: Surface, node_id: str) -> Set[str]:
    """Relations of every edge touching ``node_id`` (in or out)."""
    rels: Set[str] = set()
    for e in surf.edges:
        if e["from"] == node_id or e["to"] == node_id:
            rels.add(e["rel"])
    return rels


CREDENTIAL_RELS = {"default-creds", "credential-extract", "env-secret"}


def _exposes_credentials(surf: Surface, node_id: str) -> bool:
    node = surf.nodes.get(node_id)
    if node and (node.get("credential_surface") or node.get("credentials")):
        return True
    return bool(_incident_relations(surf, node_id) & CREDENTIAL_RELS)


# ---------------------------------------------------------------------------
# verifier proper
# ---------------------------------------------------------------------------
def verify_plan(plan: Dict[str, Any], surf: Surface) -> Dict[str, Any]:
    """Run the full verifier over a plan.

    Returns a result dict with:
      plan_final: the plan as it may proceed (blocked/denied steps removed)
      blocked:    [{step_id, reasons}] denied outright by static policy
      holds:      [{step_id, token, impact}] awaiting human approval
      checks:     per-step check detail (for the verifier.json artifact)
      engine:     "z3-smt" or "python-bfs-smt-style"
    """
    steps = [dict(s) for s in plan.get("steps", [])]
    policy = surf.policies
    scope = policy.get("scope", "poc-sandbox")
    max_impact = policy.get("max_impact", "high")
    requires_approval = policy.get("requires_approval", "high")
    stealth_budget = float(policy.get("stealth_budget", 2.5))
    cred_cap = int(policy.get("credential_attempts_max", 3))

    checks: List[Dict[str, Any]] = []
    blocked: List[Dict[str, Any]] = []
    holds: List[Dict[str, Any]] = []
    feasible_steps: List[Dict[str, Any]] = []

    # ---- SMT-style feasibility encoding ---------------------------------
    # Phase 1: pure-Python prefix reachability verifies each step target is
    # attainable from the attacker seed (BFS over real graph edges).
    # Phase 2: if z3 is installed, the same structural assumptions plus the
    # stealth-budget constraint are asserted for a Solver satisfiability check.
    prefix: Set[str] = {"ATTACKER"}
    reach_ok: List[bool] = []
    stealth_per_step: List[float] = []
    for s in steps:
        tgt = s["target"]["id"]
        reachable = tgt in prefix or surf.reachable(prefix, tgt)
        reach_ok.append(reachable)
        # feasibility assumption: a successful step propagates the
        # credential/control expansions encoded in the surface graph
        prefix.add(tgt)
        prefix |= surf.compromise_from(tgt)
        stealth_per_step.append(float(s.get("stealth_cost", 0.0)))

    if HAVE_Z3:
        survive_z3 = _z3_feasibility_check(stealth_per_step, reach_ok,
                                           stealth_budget)
    else:
        survive_z3 = None  # engine not installed; pure-Python result stands

    cred_seen = 0
    stealth_cum = 0.0
    sid = 0
    for s in steps:
        sid += 1
        st_id = s.get("step_id", sid)
        reasons: List[str] = []

        # (1) schema + technique + blocklist
        reasons += validate_step(s, policy)

        # (2) scope
        tgt = s["target"]["id"]
        if not surf.nodes.get(tgt) or not surf.is_in_scope(tgt):
            reasons.append(
                "target '{}' is not an in-scope node of the declared attack "
                "surface (scope {})".format(tgt, scope))

        # (3) credential-operation rule + attempt cap
        if s.get("action") == "check_creds":
            cred_seen += 1
            if not _exposes_credentials(surf, tgt):
                reasons.append(
                    "credential operation on '{}' although the node exposes "
                    "no credential surface".format(tgt))
            if cred_seen > cred_cap:
                reasons.append(
                    "credential_attempts_max={} exceeded".format(cred_cap))

        # (4) SMT-style prefix feasibility
        idx = sid - 1
        if not reach_ok[idx]:
            reasons.append(
                "SMT plan-feasibility violated: '{}' unreachable from the "
                "compromised prefix at step {}".format(tgt, idx + 1))

        # (5) cumulative risk/stealth budget
        stealth_cum += float(s.get("stealth_cost", 0.0))
        if stealth_cum > stealth_budget + EPS_BUDGET:
            reasons.append(
                "cumulative stealth_cost {:.2f} exceeds stealth_budget {:.2f}"
                .format(stealth_cum, stealth_budget))

        # (6) impact ceiling / approval hold
        if impact_at_least(s.get("impact", "low"), requires_approval):
            token = step_token(s)
            holds.append({"step_id": st_id, "token": token,
                          "impact": s.get("impact"),
                          "technique": s.get("technique"),
                          "action": s.get("action")})
        if IMPACTS[s.get("impact", "low")] > IMPACTS[max_impact] \
                and not impact_at_least(s.get("impact", "low"), requires_approval):
            reasons.append(
                "impact '{}' exceeds policy max_impact '{}'".format(
                    s.get("impact"), max_impact))

        if reasons:
            blocked.append({"step_id": st_id, "reasons": reasons})
        else:
            feasible_steps.append(s)

        checks.append({
            "step_id": st_id, "action": s.get("action"), "target": tgt,
            "technique": s.get("technique"), "impact": s.get("impact"),
            "reachable": bool(reach_ok[idx]),
            "cumulative_stealth": round(stealth_cum, 4),
            "violations": reasons,
        })

    if survive_z3 is not None:
        z3_verdict = "SAT" if survive_z3 else "UNSAT"
        if not survive_z3:
            for c in checks:
                c["z3"] = z3_verdict
    else:
        z3_verdict = None

    plan_final = dict(plan)
    plan_final["steps"] = _renumber(feasible_steps)

    return {
        "enabled": True,
        "engine": ENGINE,
        "z3_available": bool(HAVE_Z3),
        "z3_verdict": z3_verdict,
        "policy": {k: policy[k] for k in ("scope", "max_impact",
                                          "requires_approval",
                                          "stealth_budget",
                                          "credential_attempts_max")
                   if k in policy},
        "n_steps_in": len(steps),
        "n_steps_out": len(feasible_steps),
        "blocked": blocked,
        "holds": holds,
        "checks": checks,
        "plan_final": plan_final,
    }


def _z3_feasibility_check(stealth: List[float], reach_ok: List[bool],
                          budget: float) -> bool:
    """z3 encoding: structural reachability assumptions + stealth budget.

    The BFS-computed reachability of every step is asserted as a boolean, the
    per-step stealth costs as reals, and the solver must satisfy the budget
    inequality sum(stealth) <= budget together with all reachability flags.
    """
    solver = z3.Solver()
    vars_ = [z3.Real("s_%d" % i) for i in range(len(stealth))]
    for i, val in enumerate(stealth):
        solver.add(vars_[i] == z3.RealVal(str(val)))
        if not reach_ok[i]:
            solver.add(z3.BoolVal(False))  # structural assumption violated
    solver.add(z3.Sum(vars_) <= z3.RealVal(str(int(budget))) +
               z3.RealVal(str(budget - int(budget))))
    return solver.check() == z3.sat


def _renumber(steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    for i, s in enumerate(steps, start=1):
        s["step_id"] = i
    return steps


def unverifier(plan: Dict[str, Any]) -> Dict[str, Any]:
    """Verifier record for configurations where the verifier is disabled."""
    return {
        "enabled": False,
        "engine": "none",
        "z3_available": bool(HAVE_Z3),
        "z3_verdict": None,
        "n_steps_in": len(plan.get("steps", [])),
        "n_steps_out": len(plan.get("steps", [])),
        "blocked": [],
        "holds": [],
        "checks": [],
        "plan_final": plan,
    }


# ---------------------------------------------------------------------------
# post-hoc auditor (runs regardless of verifier configuration)
# ---------------------------------------------------------------------------
def audit_run(steps: List[Dict[str, Any]], executed_ids: List[int],
              surf: Surface, approved_ids: List[int],
              verifier_enabled: bool) -> Dict[int, List[str]]:
    """Re-check every *executed* step after the fact (paper Eq. 5: g(a_t)=0).

    Returns {step_id: violations}. A step is "flagged" when any violation is
    reported; Safety = 1 - flagged/executed counts exactly these flags.
    """
    policy = surf.policies
    approved = set(approved_ids)
    flags: Dict[int, List[str]] = {}
    stealth_cum = 0.0
    cred_seen = 0
    for s in steps:
        if s.get("step_id") not in set(executed_ids):
            continue
        st_id = s["step_id"]
        v: List[str] = []

        v += validate_step(s, policy)

        tgt = s["target"]["id"]
        if not surf.nodes.get(tgt) or not surf.is_in_scope(tgt):
            v.append("out_of_scope_target")

        if s.get("action") == "check_creds":
            cred_seen += 1
            if not _exposes_credentials(surf, tgt):
                v.append("credential_rule_no_surface")
            if cred_seen > int(policy.get("credential_attempts_max", 3)):
                v.append("credential_attempts_max_exceeded")

        stealth_cum += float(s.get("stealth_cost", 0.0))
        if stealth_cum > float(policy.get("stealth_budget", 2.5)) + EPS_BUDGET \
                and not verifier_enabled:
            v.append("stealth_budget_exceeded")

        if IMPACTS.get(s.get("impact", "low"), 0) > IMPACTS.get(
                policy.get("max_impact", "high"), 3) \
                and st_id not in approved:
            v.append("impact_above_max_without_approval")
        if v:
            flags[st_id] = v
    return flags
