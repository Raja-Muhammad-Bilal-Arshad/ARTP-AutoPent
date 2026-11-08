"""
planner_rule.py
Deterministic, explainable rule-based planner for ARTP.
Generates JSON plan from sanitized harness state.
"""

import random
from typing import List, Dict
from core.utils_artp import now_iso

ALLOWED_ACTIONS = ["crawl","enumerate","check_creds","attempt_exploit_simulated","escalate_simulated"]

def _make_step(step_id:int, action:str, target:Dict, params:Dict=None, confidence:float=0.8, impact:str="unknown"):
    return {
        "step_id": step_id,
        "action": action,
        "target": target,
        "params": params or {},
        "meta": {
            "confidence": confidence,
            "impact": impact,
            "timestamp": now_iso()
        }
    }

def rule_plan_from_state(state: Dict, seed: int=42) -> List[Dict]:
    """
    Build a simple plan:
      - crawl root for each http host
      - enumerate discovered endpoints (forms, dirs)
      - if /admin or /login found, attempt simulated exploit (low-impact)
      - enumerate services (ldap, msrpc) with info checks
    """
    random.seed(seed)
    plan = []
    step = 1

    hosts = state.get("hosts", [])
    endpoints = state.get("endpoints", [])  # list of dicts with 'host','path','protocol'
    services = state.get("services", [])

    # For each host, create a crawl + enumerate
    for h in hosts:
        target = {"host": h.get("ip", h.get("name", "unknown"))}
        # crawl root
        plan.append(_make_step(step, "crawl", {**target, "url":"/"}, params={"depth":2}, confidence=0.9))
        step += 1
        # enumerate host services if HTTP known
        plan.append(_make_step(step, "enumerate", {**target, "service":"http"}, params={"checks":["dirs","forms"]}, confidence=0.85))
        step += 1

    # process endpoint-level guidance
    for ep in endpoints:
        path = ep.get("path","/")
        target = {"host": ep.get("host"), "url": path}
        plan.append(_make_step(step, "crawl", target, params={"depth":2}, confidence=0.9))
        step += 1
        plan.append(_make_step(step, "enumerate", target, params={"checks":["forms","dirs"]}, confidence=0.8))
        step += 1
        # heuristics: admin/login -> simulated exploit attempt
        if any(x in path.lower() for x in ["/admin", "/login", "/manage"]):
            plan.append(_make_step(step, "attempt_exploit_simulated", {**target, "endpoint":path}, params={"exploit_sim_id":"sim-default-001"}, confidence=0.6, impact="medium"))
            step += 1

    # service enumeration rules (ldap, msrpc)
    for svc in services:
        svcname = svc.get("name","")
        target = {"host": svc.get("host"), "service": svcname}
        if svcname.lower() in ["ldap","msrpc","smb"]:
            plan.append(_make_step(step, "enumerate", target, params={"checks":["version","users"]}, confidence=0.7))
            step += 1

    # add a small random check_creds step with low confidence (simulated)
    if random.random() < 0.3:
        plan.append(_make_step(step, "check_creds", {"scope":"discovered_accounts"}, params={}, confidence=0.4, impact="low"))
        step += 1

    return plan
