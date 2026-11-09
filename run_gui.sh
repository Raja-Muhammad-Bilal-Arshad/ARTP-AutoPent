#!/usr/bin/env sh
# Launch the AutoPENT GUI — the local browser console for the simulation-only
# PoC. Example: ./run_gui.sh                 # opens http://127.0.0.1:8787
#              ./run_gui.sh --no-browser --port 9000
cd "$(dirname "$0")"
exec python3 -m gui.server "$@"
