"""
planner_ai.py
Safe stub for AI-based planner. For now it uses the rule planner logic
and adds "LLM-like" justification fields. Replace with real LLM calls
in controlled environments and record model/version in Appendix.
"""

from core.planner_rule import rule_plan_from_state
from core.utils_artp import now_iso

def ai_plan_from_state(state, seed=42):
    # In this release we don't call external LLMs (safety + reproducibility).
    # Instead, call rule planner and append an explanation stub per step.
    plan = rule_plan_from_state(state, seed=seed)
    for s in plan:
        s.setdefault("meta", {})
        s["meta"]["llm_stub"] = {
            "explanation": "Simulated LLM justification: step chosen based on heuristic patterns in state.",
            "generated_at": now_iso()
        }
    return plan
