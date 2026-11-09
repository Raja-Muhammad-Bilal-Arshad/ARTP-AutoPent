# gui — AutoPENT web console

A **local browser interface** over the simulation-only `poc/` package.
Zero new dependencies: the server is Python-stdlib-only; the frontend is
vanilla HTML/CSS/JS (no build step, no framework).

```
gui/
├── server.py          # stdlib HTTP server wrapping poc/ (thin shell only)
├── static/
│   ├── index.html     # single-page console (Run / Demo / Experiments /
│   │                  #  States / Selftest / Help)
│   ├── style.css      # minimal monochrome CSS; light + dark themes
│   └── app.js         # vanilla JS wiring for the console
└── samples/           # sample state files for quick testing
    ├── state_web.json          # baked web cluster (also selectable in Run tab)
    ├── state_ad.json           # baked AD domain (paper's 4-hop kill chain)
    ├── state_cloud.json        # baked cloud lab
    ├── state_mini_custom.json  # smallest valid custom state (test helper)
    └── state_invalid_demo.json # deliberately broken (validates the validator)
```

## Run it

```bash
./run_gui.sh                       # opens http://127.0.0.1:8787 automatically
./run_gui.sh --no-browser          # just print the URL
./run_gui.sh --port 9000           # any port
python3 -m gui.server --help       # same launcher, CLI flags
```

The server binds **127.0.0.1 only** — it is not reachable from the network.
Stop it with `Ctrl+C`.

## What requires what

| GUI tab | required inputs | optional inputs |
|---|---|---|
| Run | attack surface (baked scenario OR sample file OR custom JSON) + seed | config, operator, approve-all, HOLD tokens |
| Demo | scenario + seed | — |
| Experiments | seeds (N) | scenario subset (matplotlib required for figures) |
| Custom state (Run/States tabs) | `scenario`, `nodes[]`, `edges[]`, `ground_truth{objective_node,…}`; `ATTACKER` start node; edges must use planner `REL_ACTION` relations; objective reachable from ATTACKER | `policies` (defaults applied) |

The **Validate** button exercises these rules before any run; the same
validation is enforced server-side for every custom-state run.

## API surface (all JSON, all under `/api/*`)

See the module docstring of `server.py`. Highlights: `POST /api/run`
(single engagement, <1 s, synchronous), `POST /api/experiments` (background
job, progress via `GET /api/jobs/<id>`), `POST /api/validate-state`,
`POST /api/selftest`, `GET /api/file?path=…` (whitelisted artifact serving:
`.json/.jsonl/.csv/.png/...` only, repo + results-root scoped, `403`
otherwise).

## Where results go

GUI artifacts land under `results/poc/gui/` — `runs/`, `demo/`,
`experiments/<job>/` — next to (not overwriting) the CLI/regenerated
`results/poc/` study artifacts.
