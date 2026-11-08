#!/usr/bin/env python3
"""
agents/artp/adapter_llm.py
Simple LLM adapter that:
 - loads state.json
 - ensures sandbox flag (state['meta']['sandbox'] == True)
 - loads planner_prompt.txt template and substitutes <<STATE_JSON>>
 - calls llm_client.generate(...)
 - extracts JSON array from response, validates minimal schema, writes plan.json
CLI:
    adapter_llm.py <state.json> <out_plan.json> --mode llm --model MODEL --llm-mode local|api [--sandbox] [--seed N]
"""
import sys, os, json, logging, argparse, re
from typing import Any
from llm_client import generate as llm_generate

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
log = logging.getLogger("adapter_llm")

def load_json(path):
    with open(path, "r") as f:
        return json.load(f)

def write_json(obj, path):
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)
    log.info("Wrote plan: %s", path)

def extract_json_array(raw: str):
    # Try to find the first JSON array in the output
    m = re.search(r'(\[.*\])', raw, flags=re.DOTALL)
    if not m:
        raise ValueError("No JSON array found in LLM output.")
    cand = m.group(1)
    # attempt to clean common wrapper text
    try:
        return json.loads(cand)
    except Exception as e:
        # try to remove trailing commas etc:
        cand2 = re.sub(r',\s*]', ']', cand)
        return json.loads(cand2)

def validate_plan(plan):
    if not isinstance(plan, list):
        raise ValueError("Plan must be a JSON array.")
    allowed_actions = {"crawl","enumerate","check_creds","attempt_exploit_simulated","escalate_simulated"}
    for i, step in enumerate(plan):
        if not isinstance(step, dict):
            raise ValueError(f"Step {i} not an object.")
        if "step_id" not in step or "action" not in step or "target" not in step or "meta" not in step:
            raise ValueError(f"Step {i} missing required fields.")
        if step["action"] not in allowed_actions:
            raise ValueError(f"Step {i} action '{step['action']}' not allowed.")
        conf = step["meta"].get("confidence", None)
        if conf is None or not (0.0 <= float(conf) <= 1.0):
            raise ValueError(f"Step {i} invalid confidence: {conf}")
    return True

def main():
    p = argparse.ArgumentParser()
    p.add_argument("state", help="state.json path")
    p.add_argument("plan", help="output plan.json path")
    p.add_argument("--mode", default="llm", help="adapter mode (llm)")
    p.add_argument("--model", default="gpt-4o", help="model name")
    p.add_argument("--llm-mode", default="api", choices=("api","local"))
    p.add_argument("--sandbox", action="store_true", help="force treat state as sandbox")
    p.add_argument("--seed", type=int, default=None)
    args = p.parse_args()

    if not os.path.exists(args.state):
        log.error("state.json not found: %s", args.state)
        sys.exit(2)
    state = load_json(args.state)

    # enforce sandbox
    state_meta = state.get("meta", {})
    if not args.sandbox and (not state_meta.get("sandbox", False)):
        log.error("Refusing to run: state.meta.sandbox != True. Adapter only runs in sandboxed environments.")
        sys.exit(3)

    # load prompt template
    tpl_path = os.path.join(os.path.dirname(__file__), "prompts", "planner_prompt.txt")
    if not os.path.exists(tpl_path):
        log.error("Prompt template missing: %s", tpl_path)
        sys.exit(4)
    tpl = open(tpl_path,"r",encoding="utf-8").read()

    # produce prompt (embed STATE JSON)
    state_json = json.dumps(state, indent=2)
    prompt = tpl.replace("<<STATE_JSON>>", state_json)

    log.info("Calling LLM (mode=%s model=%s)...", args.llm_mode, args.model)
    try:
        raw = llm_generate(prompt, model=args.model, mode=args.llm_mode, temperature=0.0, max_tokens=1024)
    except Exception as e:
        log.exception("LLM call failed: %s", e)
        sys.exit(5)

    # extract json array
    try:
        plan = extract_json_array(raw)
    except Exception as e:
        log.exception("Failed to parse LLM output as JSON array: %s", e)
        sys.exit(6)

    # validate
    try:
        validate_plan(plan)
    except Exception as e:
        log.exception("Plan validation failed: %s", e)
        sys.exit(7)

    # write plan
    write_json(plan, args.plan)
    log.info("Adapter completed successfully")

if __name__ == "__main__":
    main()

