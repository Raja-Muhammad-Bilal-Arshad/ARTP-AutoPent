"""
safety_policies.py
Simple symbolic checks and annotation utilities for plans.
Simulation-only, non-actionable.
"""

from typing import List, Dict

# blocklist patterns (just names, not technical instructions)
BLOCKLIST_ACTIONS = ["destroy_data", "exfiltrate", "run_remote_payload"]

IMPACT_THRESHOLD = {
    "low": 0.2,
    "medium": 0.6,
    "high": 0.9
}

def step_is_unsafe(step: Dict) -> bool:
    a = step.get("action","")
    if a in BLOCKLIST_ACTIONS:
        return True
    # if step has explicit 'impact' labelled high, flag
    impact = step.get("meta", {}).get("impact", "").lower()
    if impact == "high":
        return True
    return False

def annotate_plan_with_safety(plan: List[Dict]) -> List[Dict]:
    """
    Annotate each step with 'safety' metadata:
      - flagged: bool
      - reasons: list
    """
    out = []
    for s in plan:
        reasons = []
        flagged = False
        if step_is_unsafe(s):
            flagged = True
            reasons.append("matches_blocklist_or_high_impact")
        # sanity check: required keys
        if "action" not in s or "meta" not in s:
            flagged = True
            reasons.append("missing_required_fields")
        # attach metadata visible to harness
        s.setdefault("meta", {})
        s["meta"]["safety_flagged"] = flagged
        s["meta"]["safety_reasons"] = reasons
        out.append(s)
    return out
