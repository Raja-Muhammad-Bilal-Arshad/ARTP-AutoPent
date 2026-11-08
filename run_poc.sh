#!/usr/bin/env bash
# ARTP PoC one-command runner (simulation-only; no Docker, no live targets).
#   ./run_poc.sh            -> selftest + demo runs + full N=30 experiments
#   SEEDS=10 ./run_poc.sh   -> faster pass for reviewers in a hurry
set -euo pipefail
cd "$(dirname "$0")"

SEEDS="${SEEDS:-30}"
OUT="${OUT:-results/poc}"

echo "[run_poc.sh] 1/3 selftest (verifier engine: python-bfs SMT fallback unless z3 installed)"
python3 -m poc selftest

echo "[run_poc.sh] 2/3 demo engagements (web, ad, cloud; artifacts -> results/poc/demo)"
python3 -m poc demo

echo "[run_poc.sh] 3/3 experiments: 3 scenarios x 3 framework configs + baseline x ${SEEDS} seeds"
python3 -m poc experiments --seeds "${SEEDS}" --outdir "${OUT}"

echo "[run_poc.sh] artifacts:"
find "${OUT}" -maxdepth 2 -mindepth 1 | sort | head -30
echo "table2.csv / summary.json / runs.jsonl / figures are under ${OUT}"
echo "open ${OUT}/figures/fig2_web_metrics.png, fig3_cloud_mttd.png, fig4_ad_chain.png"
