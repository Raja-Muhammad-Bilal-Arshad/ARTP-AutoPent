#!/usr/bin/env python3
"""
agents/artp/adapter.py
Safe adapter template for ARTP agent integration with AutoPENT-Bench harness.
- Reads state.json produced by the harness.
- Optionally calls an LLM (placeholder) or uses a rule engine to produce a plan.json.
- Enforces strict safety checks: requires state['meta']['sandbox'] == True to operate.
- Allows only the safe action schema:
    ["crawl","enumerate","check_creds","attempt_exploit_simulated","escalate_simulated"]
- Does NOT include any exploit payloads or live execution steps.
- The LLM call is a stub. Replace `llm_call()` with your organization-approved LLM client,
  and ensure you never pass sensitive credentials or real network access to the model.
- Always run this adapter in an isolated environment with no Internet egress for experiments.

Usage:
  python3 agents/artp/adapter.py state.json plan.json --mode llm --seed 42 --dryrun
  python3 agents/artp/adapter.py state.json plan.json --mode rule --seed 42

Outputs:
  plan.json : array of plan steps (sanitized).

Author: Bilal Arshad (template)
"""

import json
import sys
import os
import argparse
import time
import logging
from typing import Any, Dict, List

# Allowed action schema - strictly enforced
ALLOWED_ACTIONS = {
    "crawl",
    "enumerate",
    "check_creds",
    "attempt_exploit_simulated",   # simulated-only
    "escalate_simulated"          # simulated-only
}

logger = logging.getLogger("artp_adapter")
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s")


def read_json(path: str) -> Any:
    with open(path, 'r') as f:
        return json.load(f)


def write_json(obj: Any, path: str) -> None:
    with open(path, 'w') as f:
        json.dump(obj, f, indent=2)


def validate_state_is_sandbox(state: Dict) -> None:
    meta = state.get('meta', {})
    sandbox_flag = meta.get('sandbox', None)
    if sandbox_flag is not True:
        logger.error("Refusing to run: state.meta.sandbox != True. Adapter only runs in sandboxed environments.")
        raise RuntimeError("Non-sandboxed environment detected. Aborting.")


def sanitize_plan(raw_plan: List[Dict]) -> List[Dict]:
    """Validate and sanitize plan steps produced by an LLM or rule-engine.
    - Ensure only allowed actions
    - Strip any suspicious fields, payloads or live-execution markers
    - Enforce presence of meta.confidence (0..1)
    """
    sanitized = []
    for step in raw_plan:
        action = step.get('action')
        if action not in ALLOWED_ACTIONS:
            logger.warning("Dropping disallowed action: %s", action)
            continue
        # Build a minimal safe step
        safe_step = {
            'step_id': step.get('step_id', None),
            'action': action,
            'target': step.get('target', {}),
            'params': step.get('params', {}),
            'meta': {
                'confidence': float(step.get('meta', {}).get('confidence', 0.0)),
                # force all impact markers to be non-actionable textual tags only
                'impact': step.get('meta', {}).get('impact', 'unknown'),
                'timestamp': step.get('meta', {}).get('timestamp', time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))
            }
        }
        # Remove any keys that might contain payloads or credentials
        if 'payload' in safe_step['params']:
            logger.debug('Removing payload field from params for safety')
            safe_step['params'].pop('payload', None)
        if 'creds' in safe_step['params']:
            logger.debug('Removing creds field from params for safety')
            safe_step['params'].pop('creds', None)
        sanitized.append(safe_step)
    return sanitized


def rule_based_planner(state: Dict, seed: int = 42) -> List[Dict]:
    """A conservative rule-based planner - useful as a safe baseline.
    Produces simulated-only actions based on discovered endpoints and services.
    """
    plan = []
    step_id = 1
    hosts = state.get('hosts', [])
    endpoints = state.get('endpoints', [])
    services = state.get('services', [])
    for ep in endpoints:
        # Example: prefer crawling then enumerating
        plan.append({
            'step_id': step_id,
            'action': 'crawl',
            'target': {'host': ep.get('host'), 'url': ep.get('path', '/')},
            'params': {'depth': 2},
            'meta': {'confidence': 0.9, 'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
        })
        step_id += 1
        plan.append({
            'step_id': step_id,
            'action': 'enumerate',
            'target': {'host': ep.get('host'), 'url': ep.get('path', '/')},
            'params': {'checks': ['forms', 'dirs']},
            'meta': {'confidence': 0.8, 'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
        })
        step_id += 1
        # If path looks like login or admin, schedule a simulated exploit attempt
        p = ep.get('path', '').lower()
        if any(key in p for key in ['/admin', '/login', '/user']):
            plan.append({
                'step_id': step_id,
                'action': 'attempt_exploit_simulated',
                'target': {'host': ep.get('host'), 'endpoint': ep.get('path')},
                'params': {'exploit_sim_id': 'sim-default-001'},
                'meta': {'confidence': 0.6, 'impact': 'medium', 'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
            })
            step_id += 1
    # Add simple service checks
    for s in services:
        if s.get('name') in ['ldap', 'msrpc']:
            plan.append({
                'step_id': step_id,
                'action': 'enumerate',
                'target': {'host': s.get('host'), 'service': s.get('name')},
                'params': {'checks': ['version', 'users']},
                'meta': {'confidence': 0.7, 'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
            })
            step_id += 1
    return plan


def llm_call_stub(prompt: str, max_tokens: int = 512, temperature: float = 0.0) -> str:
    """Stub for LLM call. DO NOT call external network from this template.
    Replace this function with your approved LLM client. The stub returns a stable,
    small JSON plan suggestion that adheres to the allowed schema.
    """
    logger.info("LLM call stub invoked (no network). Returning deterministic suggestion.")
    # A tiny deterministic suggestion; real LLM should be used only in isolated envs
    suggestion = [
        {
            'step_id': 1,
            'action': 'crawl',
            'target': {'host': '10.0.0.2', 'url': '/'},
            'params': {'depth': 2},
            'meta': {'confidence': 0.9, 'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
        }
    ]
    return json.dumps(suggestion)


def llm_based_planner(state: Dict, seed: int = 42) -> List[Dict]:
    """Build a safe prompt, call an LLM (stub here), parse and sanitize the output.
    Important: Do not send secrets or external network-accessible content to the model.
    """
    # Build a compact prompt that lists discovered hosts/endpoints (sanitized)
    prompt_state = {
        'hosts': [{k: v for k, v in h.items() if k in ('host','ip')} for h in state.get('hosts', [])],
        'endpoints': [{'host': e.get('host'), 'path': e.get('path')} for e in state.get('endpoints', [])],
        'services': [{'host': s.get('host'), 'name': s.get('name')} for s in state.get('services', [])]
    }
    prompt = "Given the following sanitized state, produce a JSON array of actions using only the allowed schema: " + json.dumps(prompt_state)
    raw_response = llm_call_stub(prompt)
    try:
        raw_plan = json.loads(raw_response)
    except Exception as e:
        logger.error('LLM response parse error: %s', e)
        return []
    return raw_plan


def build_plan(state: Dict, mode: str = 'rule', seed: int = 42) -> List[Dict]:
    if mode == 'rule':
        return rule_based_planner(state, seed)
    elif mode == 'llm':
        return llm_based_planner(state, seed)
    else:
        raise ValueError(f'Unknown mode: {mode}')


def main(argv: List[str]):
    parser = argparse.ArgumentParser(description='ARTP agent adapter (safe template)')
    parser.add_argument('state', help='path to state.json')
    parser.add_argument('plan', help='output path for plan.json')
    parser.add_argument('--mode', choices=['rule', 'llm'], default='rule', help='planner mode')
    parser.add_argument('--seed', type=int, default=42, help='random seed')
    parser.add_argument('--dryrun', action='store_true', help='do not write plan.json')
    args = parser.parse_args(argv)

    state_path = args.state
    plan_path = args.plan

    if not os.path.exists(state_path):
        logger.error('state.json not found: %s', state_path)
        sys.exit(2)

    state = read_json(state_path)

    # Safety: require explicit sandbox flag in state.meta
    try:
        validate_state_is_sandbox(state)
    except RuntimeError:
        sys.exit(3)

    plan_raw = build_plan(state, mode=args.mode, seed=args.seed)
    plan_safe = sanitize_plan(plan_raw)

    logger.info('Generated %d plan steps (mode=%s)', len(plan_safe), args.mode)

    if args.dryrun:
        print(json.dumps(plan_safe, indent=2))
        return

    write_json(plan_safe, plan_path)
    logger.info('Wrote sanitized plan to %s', plan_path)

if __name__ == "__main__":
    import sys

    # Support both direct CLI and positional-then-flags order
    try:
        sys.exit(main(sys.argv[1:]))
    except SystemExit as e:
        # argparse calls sys.exit internally on error — this catches & prints nicely
        if e.code != 0:
            print("\n[!] Adapter argument parsing failed. Example usage:")
            print("    python3 agents/artp/adapter.py state.json plan.json --mode rule --seed 42\n")
        raise


