ARTP agent (simulation-only)

Usage examples:

# produce a plan using rule-based planner
python3 agents/artp/adapter.py agents/artp/state.json agents/artp/plan.json --mode rule

# produce a plan using AI stub (does not call external APIs)
python3 agents/artp/adapter.py agents/artp/state.json agents/artp/plan.json --mode ai

Output:
 - plan.json (list of steps)
 - agents/artp/results/summary.json

This agent is intentionally simulation-only and produces high-level
"simulated exploit" actions safe for sandboxed evaluation.
