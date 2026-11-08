# ARTP : A Safety-Conscious Red-Team Planner (AutoPENT)

**ARTP / AutoPENT** is an autonomous red-team planning system that plans and
executes penetration-network operations against an **attack-surface graph**
while enforcing safety policies (scope, impact ceilings, blocklists,
human-in-the-loop approvals) and reporting reproducible metrics
(Coverage, Path Efficiency, Safety, Stealth).

> **Status (2026-11):** the paper `ARTP.pdf` accompanies this repo. The
> **original pipeline** (`harness/`, `agents/`, `tools/`, legacy `results/`)
> predates the current paper and is kept **as-is for provenance** (it has known
> reproducibility gaps : see §5). A new, self-contained, **simulation-only PoC
> package** (`poc/`) re-implements every pipeline stage claimed by the paper
> with real, reproducible runs : that is what the editor asked for and what
> `POC.md` documents in depth.

**Everything under `poc/` is simulation-only.** No exploit payloads, no live
network attacks. Scenario states are baked sandbox graphs; outcomes come from a
seeded PRNG. Do **not** point this repository at systems you do not own.

---

## 1. Running the project & the PoC : full step-by-step

### 1.0 Fast path (if you already have Python ≥ 3.10 + matplotlib)

```bash
./run_poc.sh                     # selftest → demo runs → full 3×4×30 experiments
```
Runtime ≈ 40 s on a laptop; artifacts land in `results/poc/`.

### 1.1 Full runbook, step by step

| Step | Command | What it does / what you should see | Time |
|---|---|---|---|
| ① prerequisites | `python3 --version` | Python **≥ 3.10** (validated on 3.13.11), pip, Linux/macOS shell. **No Docker needed for the PoC.** | 1 min |
| ② setup | `git clone <repo> && cd AutoPENT`<br>`python3 -m venv .venv && source .venv/bin/activate`<br>`pip install -r requirements.txt`<br>`pip install z3-solver` *(optional)*<br>`chmod +x run_poc.sh` | matplotlib is the only hard PoC dependency. `z3-solver` upgrades the verifier engine (reported as `z3-smt` in `verifier.json`); without it the documented pure-Python engine (`python-bfs-smt-style`) runs. Do **not** use `myenv/` : that is the legacy pipeline's venv. | 2 min |
| ③ sanity | `python3 -m poc selftest` | **9 invariant checks, all PASS**: 6-verb schema, verifier blocks & holds, ground-truth chains (L_opt 6/4/4), HITL operator modes, RPC child-process isolation, seed determinism, Welch t-test math, pipeline smoke, real-state pass-through | ~5 s |
| ④ demo | `python3 -m poc demo`<br>*(or `--scenario ad` / `--interactive`)* | Narrative engagement per scenario: every planned step, verifier blocks, HITL approvals, alerts, metrics : written to `results/poc/demo/` | ~5 s |
| ⑤ single controlled run | `python3 -m poc run-poc --scenario ad --config full --seed 1 --out results/poc/quick` | One engagement with full artifact set. Useful flag combos:<br>• deny criticals: `--operator scripted-cautious`<br>• prompt per HOLD: `--interactive`<br>• explicit tokens: `--approve HOLD-5-009fb0e9 --approve HOLD-4-…`<br>• batch-approve: `--approve-all` | ~1 s |
| ⑥ experiments | `python3 -m poc experiments --seeds 30 --outdir results/poc`<br>*or `SEEDS=10 ./run_poc.sh` for a faster pass* | 3 scenarios × 4 configs × 30 seeds = **360 isolated JSON-RPC sessions** → `table2.csv`, `summary.json`, per-scenario `runs.jsonl`, `figures/fig{2,3,4}*.png`. Welch p-values print at the end | ~30 s |
| ⑦ inspect | open `results/poc/table2.csv`, `figures/*.png` | Table 2 layout: rows = (scenario, config), metrics = mean/SD/CI95/median/IQR + Welch blocks. One exemplar run dir: `results/poc/ad/full/seed-0001/` | : |
| ⑧ tests | `python3 tests/test_poc.py` | **8/8 unit tests PASS** (also pytest-compatible) | ~5 s |
| ⑨ regenerate | `rm -rf results/poc && ./run_poc.sh` | Reproduce *everything from scratch*; never hand-edit `results/poc/` | ~40 s |

### 1.2 Optional: the legacy pipeline (original repo, needs Docker)

Frozen provenance : run only if you specifically need live targets:

```bash
python3 -m venv myenv && source myenv/bin/activate && pip install -r requirements.txt
docker compose -f harness_targets_templates/web_cluster/docker-compose.yml up -d
./run_experiment.sh --agent artp --target web_cluster --runs 5 --auto-adapter --mode rule
./auto_run.sh          # legacy 30-run orchestrator (WEB + CLOUD, BlackHat mode)
./smoke_test.sh        # legacy end-to-end sanity check
```
Remember: legacy metrics produced this way are **not** the paper's reproducible
numbers (§6); use the PoC for anything you print.

### 1.3 Troubleshooting

| symptom | cause / fix |
|---|---|
| `ModuleNotFoundError: matplotlib` | `pip install matplotlib` (the only hard PoC dep) |
| verifier engine shows `python-bfs-smt-style` | z3 not installed : fine; `pip install z3-solver` to upgrade to `z3-smt` |
| `run_poc.sh: Permission denied` | `chmod +x run_poc.sh` |
| `selftest: N passed, M failed` | a M check failed → its `[FAIL]` line prints the detail; do not publish results until 9/9 |
| want a fresh results tree | `rm -rf results/poc` then rerun; artifacts are generated, not edited |
| child process died before responding (RPC error) | another `python3 -m poc.rpc` pinned the run dir? Not possible (stateless); rerun : if persistent, check `PYTHONPATH`/repo root |

---

## 2. Repository structure

```
AutoPENT/
├── ARTP.pdf                        # the paper (submitted manuscript)
├── POC.md                          # ★ PoC handout: claims → files → measured results
├── README.md                       # this file
├── run_poc.sh                      # ★ one-command PoC runner (selftest+demo+experiments)
├── requirements.txt                # dependencies (z3-solver optional, commented)
│
├── poc/                            # ★ NEW : Proof-of-Concept package (simulation-only)
│   ├── __init__.py                 #   package marker & simulation-only banner
│   ├── schema.py                   #   6-verb action schema, MITRE ATT&CK map,
│   │                               #   blocklists, approval tokens (HOLD-<sid>-<hash8>)
│   ├── state.py                    #   attack-surface graph + baked sandbox scenarios
│   ├── planner.py                  #   graph-aware planner, drift/aggressive probes,
│   │                               #   random-walk baseline
│   ├── verifier.py                 #   policy verifier + SMT-style plan feasibility
│   ├── hitl.py                     #   human-in-the-loop approval ledger (approvals.jsonl)
│   ├── executor.py                 #   simulated execution engine (CVSS-based p, ε=0.05,
│   │                               #   detector D(a), CloudTrail MTTD telemetry)
│   ├── rpc.py                      #   JSON-RPC 2.0 stdio server + client (process isolation)
│   ├── metrics.py                  #   Eqs. 2–11, CI95, composite R, Welch's t-test (no SciPy)
│   ├── pipeline.py                 #   plan→verify→HITL→execute→audit→metrics→artifacts
│   ├── exp.py                      #   experiment driver: Table 2 + Fig 2/3/4 + CSV exports
│   ├── selftest.py                 #   invariant checks (also usable without pytest)
│   └── __main__.py                 #   CLI: selftest / demo / run-poc / experiments
│
├── tests/
│   └── test_poc.py                 # unit tests (pytest-compatible, runs standalone)
│
├── results/                        # experiment outputs
│   ├── poc/                        # ★ NEW : PoC artifacts (regenerate at will)
│   │   ├── web|ad|cloud/<config>/seed-NNNN/   plan.json, verifier.json,
│   │   │                                      approvals.jsonl, exec_trace.json,
│   │   │                                      metrics.json (+ surface_focus.csv for AD)
│   │   ├── web|ad|cloud/runs.jsonl            one row per run (Eq. 7 aggregates)
│   │   ├── ad/full-exemplar/                  Table-4-style surface-focus exemplar
│   │   ├── demo/web|ad|cloud/                 narrative demo runs
│   │   ├── figures/                           fig2_web_metrics.png
│   │   │                                      fig3_cloud_mttd.png
│   │   │                                      fig4_ad_chain.png
│   │   ├── table2.csv                         Table 2 (mean/SD/CI95/median/IQR + Welch)
│   │   └── summary.json                       machine-readable aggregates
│   ├── ad_runs/, artp/, auto_run_*/…           legacy run dirs (PROVENANCE : do not edit)
│   └── actionable_paths.csv, …                 legacy analysis outputs
│
├── harness/                        # legacy execution harness (pre-PoC)
│   ├── harness.py                  #   orchestrates agents against dockerized targets
│   ├── executor.py / verifier.py   #   legacy step executor & policy checks
│   ├── cloud_harness.py            #   LocalStack/MinIO cloud variant
│   ├── state_exporter.py           #   live target → state.json exporter
│   ├── utils.py, logging.conf      #   shared helpers
│   ├── templates/                  #   report templates
│   └── harness_targets/            #   legacy per-target helpers
│
├── harness_targets_templates/      # docker-compose target definitions (legacy, optional
│   ├── web_cluster/                #   to run the legacy pipeline only)
│   ├── ad_lab/
│   └── cloud/                      #   docker-compose + LocalStack init script
│
├── agents/                         # legacy planners
│   ├── artp/                       #   LLM/prompt-driven agent (Prompts/, agents/)
│   └── rule_based/                 #   deterministic rule-based agent
│
├── tools/                          # legacy analysis & plotting scripts
│   ├── aggregate_metrics.py        #   metrics aggregation used by legacy runs
│   ├── analyze_ad_users*.py        #   BloodHound AD analyses (source of paper Fig. 4)
│   ├── bloodhound_to_state.py      #   BloodHound CSV → attack-surface state
│   ├── build_state*.py             #   live/web/cloud state builders
│   ├── exploit_simulator.py, …     #   step simulators
│   └── plot_*.py                   #   figure generators
│
├── outputs/                        # legacy AD analyses (incl. ad_user_vulnerabilities.png,
│   │                               #   the paper's Fig. 4 source) : provenance
├── reports/                        # legacy BloodHound-style HTML/CSV reports (AdminGroups, …)
├── plans/                          # legacy generated plans (plan.json, plan_ad.json, …)
├── tmp_orch/, tmp_orch_cloud/, tmp_run/   legacy scratch orchestration dirs
├── myenv/                          # legacy python virtualenv (do not activate/use; built
│                                   #   for the legacy pipeline)
│
├── state.json, state_bh.json, state_from_cloud.json,   legacy exported target states
│   state_from_live.json, temp_state.json
├── plan.json, test_plan_blackhat.json,                 legacy generated plans
│   ad_plan_blackhat.json
├── MODES.md                        # legacy: all modes + command reference (bash notes)
├── r2.md                           # legacy: BlackHat submission flavored README
├── auto_run.sh / cloud_run.sh / harness.sh /           legacy runner scripts
│   run_experiment.sh / smoke_test.sh
└── nano.2278.save                  # stray editor backup : safe to delete
```

★ marks the parts that are new in this revision (the PoC).
Everything in §“legacy” is kept **unmodified** for provenance; new work must go
into `poc/`, `tests/`, `results/poc/` or top-level docs.

---

## 3. What the PoC demonstrates (and what a "PoC" is)

A **Proof of Concept** is a minimal, runnable demonstration that a paper's
central claims describe *working behavior*, verifiable by an independent
reader. For ARTP that is **not** an exploit kit : it is the demonstration that
the **safety automation loop** exists and functions:

```
        ┌────────────────────────────────────────────────────────────┐
        │                                                            │
   attack-surface graph G=(V,E)  ──►  PLANNER (poc/planner.py)         │
        │                              │  6-verb schema steps,        │
        │                              │  MITRE ATT&CK techniques      │
        │                              ▼                               │
        │                     VERIFIER (poc/verifier.py)              │
        │                     schema · scope · blocklist ·            │
        │                     credential rules · stealth budget ·     │
        │                     SMT-style feasibility · HOLDS           │
        │                              │                              │
        │                              ▼                              │
        │                     HITL GATE (poc/hitl.py)                 │
        │                     impact ≥ "high" ⇒ HOLD-<sid>-<hash8>    │
        │                     approved/denied ⇒ approvals.jsonl       │
        │                              │                              │
        │                              ▼                              │
        │            EXECUTOR, isolated child process (poc/rpc.py)    │
        │            JSON-RPC 2.0 · seeded PRNG · CVSS-based p ·       │
        │            ε=0.05 noise · detector D(a) · MTTD telemetry    │
        │                              │                              │
        │                              ▼                              │
        │                     METRICS (poc/metrics.py)                │
        │                     Coverage · Ep · Safety · Stealth ·      │
        │                     CI95 · composite R · Welch t-test       │
        │                              │                              ▼
        └──────────────────────────────┴────────────► artifacts + figures
```

### 3.1 Sandbox scenarios (no Docker / LocalStack needed)

| Scenario | Graph | Ground-truth objective | L_opt |
|---|---|---|---|
| `web`   | 12 nodes (Juice-Shop-style chain + out-of-scope decoys) | `data:users-db` | 6 |
| `ad`    | 40 nodes : the paper's **4-hop kill chain** Phishing → Kerberoasting → AdminTo → DCSync (`u_amy_rhodes → svc_sql → WKST-01 → DC-01`) inside a realistic distractor org | `DC-01` | 4 |
| `cloud` | 7 nodes (public bucket → over-privileged role → function → secret) | `secret:api-prod-key` | 4 |

### 3.2 Configurations / ablations

| config | verifier | HITL | plan additions | note |
|---|---|---|---|---|
| `full` | ✔ | ✔ | graph path (+ survey step) | the complete framework |
| `without_verifier` | ✘ | ✔ | + 4 out-of-scope drift probes | verifier ablation |
| `unconstrained` | ✘ | ✘ | + 4 drift + 3 destructive critical steps | "agent without guardrails" |
| `baseline_random_walk` | ✘ | ✘ | 6-step uninformed walk | comparator |

### 3.3 Metrics (single implementation, `poc/metrics.py`)

```
Eq.3   Coverage  = |V_compromised| / |V_total|
Eq.4/11 Ep       = T_opt / T_obs                (credited only on objective completion)
Eq.5   Safety    = 1 − |{aₜ : g(aₜ)=0}| / T      (auditor flags = unsafe executed steps)
Eq.6   Stealth   = 1 − (1/T) Σ D(aₜ)
Eq.7/8 σ, CI95   = µ ± 1.96·σ/√N
Eq.9   R         = α(1−Safety) + β(1−Stealth) + γ(1−Coverage),  α=β=γ=⅓   (penalty; ↓ better)
        Recon     precision/recall vs declared recon targets
        Welch     two-tailed t-test via incomplete beta (Table 2 significance)
```

### 3.4 Headline results (N = 30 seeded runs; full tables in `POC.md` / `results/poc/table2.csv`)

| scenario | config | Coverage | Ep | Safety | R | objective reached |
|---|---|---|---|---|---|---|
| web | full | 0.4875 | 0.752 | **1.000** | **0.265** | 0.77 |
| web | unconstrained | 0.4875 | 0.351 | 0.389 | 0.495 | 0.77 |
| ad | full | 0.085 | **0.800** | **1.000** | 0.407 | **0.93** (28/30) |
| ad | baseline_random_walk | 0.095 | 0.411 | 1.000 | 0.369 | 0.47 (14/30) |
| cloud | full | **0.389** | 0.153 | **1.000** | **0.278** | 0.17 |
| cloud | baseline_random_walk | 0.283 | 0.200 | 0.889 | 0.338 | 0.20 |

Framework vs ablations separates on Safety with **Welch p ≈ 0** (web/ad, N=30).
Detailed numbers, stale-claim replacements, and interpretation caveats: **`POC.md`**.

### 3.5 How the PoC was generated on the simulated environment

The PoC is *constructed*, not recorded: every stage below is code you can read,
and nothing was tuned to make the paper's old numbers match.

1. **Source of truth** : each claim in `ARTP.pdf` is mapped to the module that
   implements it (`POC.md` §2 claim → file map) so the design is traceable.
2. **Sandbox states built deterministically** : `poc/state.py` bakes three
   JSON graphs from the paper's setup descriptions: a Juice-Shop-style web
   chain (12 nodes + out-of-scope decoys), the AD domain with the paper's
   **4-hop kill chain** (Phishing → Kerberoasting → AdminTo → DCSync) planted
   inside a 40-node realistic distractor org (users, FS servers, groups,
   including the alternative `u02 → GRP_DOMAIN_ADMINS → DC-01` route), and a
   cloud misconfiguration chain (public bucket → over-privileged role →
   function → secret). Each state ships its `policies` and `ground_truth`
   (objective node, L_opt, recon targets). The AD graph carries a probabilistic
   low-noise survey step (`GUARD_P = 0.70`) to reproduce the paper's
   "necessary lateral-movement check" deviation factor.
3. **Planning** : `poc/planner.py` walks the BFS-shortest path to the objective
   and maps each graph relation to a schema verb through `REL_ACTION`
   (e.g. `dcsync → attempt_exploit_simulated/T1003.006`,
   `adminTo → escalate_simulated/T1078`), attaching impact, CVSS and stealth
   cost per step.
4. **Policy layer** : `poc/verifier.py` runs the paper's checks in order:
   schema -> blocklist -> scope -> credential rules & attempt cap ->
   SMT-style feasibility (prefix = `{ATTACKER}` expanded with
   `compromise_from` after each step; each target must stay reachable; z3
   checks the same encoding plus the stealth-budget inequality when
   installed) -> risk budget -> impact ceiling -> HOLD generation.
5. **Human gate** : held steps wait in `poc/hitl.py` for an operator decision
   (`scripted-standard`, `scripted-cautious`, interactive prompt, or explicit
   tokens). Denials are *executed nowhere*; every decision is appended to
   `approvals.jsonl` before the run proceeds.
6. **Simulated execution** : the isolated child process applies the
   documented probability model:

   | step verb | p_true branch |
   |---|---|
   | crawl / enumerate | 1.0 (read-only recon) |
   | check_creds | 0.5 if credential surface exposed else 0.2 |
   | attempt_exploit_simulated | `0.3 + 0.06·CVSS` |
   | escalate_simulated | 0.85 **iff the predecessor foothold is compromised**, else 0 |
   | exfiltrate_simulated | 0.9 (critical pivot held) / 0.2 (target directly exposed) / 0.05 blind |

   Observed `p_obs = clip(p_true + U(−ε, +ε))`, ε = 0.05; detector
   `D(a) = clip(0.05 + 0.10·impact_idx + 0.15·is_attack + 0.05·stealth_cost)`;
   each executed step costs `dt = 2 + 2·impact_idx` simulated seconds and in
   the cloud scenario the first alert terminates the session (CloudTrail-style
   kill-switch). These formulas are the *simulation model*, stated openly :
   change them in one file (`executor.py`) and re-run to test a different
   threat model.
7. **Metrics & aggregation** : `poc/metrics.py` computes Eq. 2–11 from the
   trace (one implementation across all runs); `poc/exp.py` aggregates N=30
   per config, writes `table2.csv`/`summary.json`, and regenerates Figs 2–4.
8. **Reproduction contract** : plan/execution are pure functions of `seed`;
   the full suite is 3 scenarios × 4 configs × 30 seeds and regenerates every
   number in the paper's tables from `runs.jsonl` (nothing hand-entered).

### 3.6 From the simulated environment to real data

The PoC was deliberately layered so that migrating to a real lab changes
*what supplies the state and what executes steps* : and nothing else:

| layer | PoC (simulated, default) | real-data deployment (same schema) |
|---|---|---|
| state source | baked sandbox graphs (`poc/state.py`) | exported topology of the lab: BloodHound CSVs for AD (`tools/bloodhound_to_state.py`), `harness/state_exporter.py` for web, `tools/build_state_cloud.py` for cloud : any JSON conforming to the state contract |
| state format | same | same: `nodes[].id/type`, `edges[].from/to/rel/technique`, `policies`, `ground_truth{objective_node, optimal_path_length, recon_targets}`, `scenario ∈ {web, ad, cloud}` |
| planner | `poc/planner.py` | **unchanged** (graph-aware, same BFS) |
| verifier + HITL + tokens | `poc/verifier.py` / `poc/hitl.py` | **unchanged** : scope now reflects the *real lab's* declared scope; approvals bind real people |
| executor backend | simulated PRNG engine SimExecutor behind JSON-RPC (`poc/rpc.py`) → step outcomes rolled | **execution adapter**: replace the RPC server's executor with a driver that performs each allowed step against the lab (the legacy `harness` executor is the reference). The step dict (`action/target/technique/impact/cvss/stealth_cost`) is the interface contract |
| telemetry | simulated `D(a)`, dt, MTTD | real detections: SIEM/CloudTrail/EDR alert stream feeds the same fields (`detected`, `dt`, `mttd`) |
| metrics & artifacts | `poc/metrics.py`, same artifacts | **identical** : results stay comparable with the simulation study |

Bring-up procedure (`--state-file` mode, already implemented and tested):

```bash
# 1) export the lab state (example: AD from BloodHound CSVs)
python3 tools/bloodhound_to_state.py --help        # legacy exporter

# 2) (in the exported JSON) confirm scenario/policies/ground_truth.objective_node
#    exist : the ground_truth.objective_node is the planning anchor

# 3) plan + verify + HITL + simulated execution against the REAL topology
python3 -m poc run-poc --state-file real_ad_state.json --config full --seed 1 \
    --operator scripted-cautious --out results/poc/real-ad
#    `--scenario` is read from the state file; the isolated child process is
#    initialized with your topology (no baked demo state is touched), and the
#    selftest's "real-state pass-through" check proves identical-graph ⇒
#    identical-metrics and edited-graph ⇒ loud failure.

# 4) wire the real execution adapter (optional, authorized labs only):
#    subclass the poc/rpc.py server's executor with a driver for your lab;
#    verifier/HITL keep gating every step before it is sent live.
```

Ethics gate for Step 4: **written authorization, isolated lab network, and a
minimum-impact policy first** : the PoC's default remains simulation-only on
purpose; the safety stack (verifier, HITL, scope) is exactly the machinery
that makes a real deployment reviewable.

---

## 4. CLI reference (`python3 -m poc --help`)

| command | purpose | key flags |
|---|---|---|
| `selftest` | 9 invariant checks (incl. real-state pass-through) | : |
| `demo` | narrative engagement per scenario | `--scenario web\|ad\|cloud\|all`, `--seed N`, `--interactive` |
| `run-poc` | one controlled engagement | `--scenario`, `--config full\|without_verifier\|unconstrained\|baseline_random_walk`, `--seed`, `--operator scripted-standard\|scripted-cautious`, `--approve-all`, `--approve HOLD-…` (repeatable), `--interactive`, `--out DIR` |
| `experiments` | N×config runs → Table 2, Fig 2/3/4 | `--seeds 30`, `--outdir results/poc`, `--scenarios web,ad,cloud`, `--no-baseline` |

Artifacts per run directory (`results/poc/<scenario>/<config>/seed-NNNN/`):
`plan.json`, `verifier.json`, `approvals.jsonl`, `exec_trace.json`,
`metrics.json` (+ `surface_focus.csv` on AD).

---

## 5. The legacy pipeline (left as-is, provenance)

The original AutoPENT flow : live dockerized targets in, BloodHound/state
exporters, harness execution, analysis plots out:

```bash
# legacy usage (requires Docker + the harness_targets_templates targets)
./harness.sh --help
./run_experiment.sh --agent artp --target web_cluster --runs 5 --auto-adapter --mode rule
./auto_run.sh          # 30-run web+cloudBlackHat orchestrator
./cloud_run.sh         # cloud harness driver
./smoke_test.sh        # legacy end-to-end sanity check
```

Supporting chains: `agents/` (planners) → `harness/` (execution + verification)
→ `results/` (run logs) → `tools/` (aggregation/plots) → `outputs/` & `reports/`
(analyses; `outputs/ad_user_vulnerabilities.png` is the source of the paper's
Fig. 4) → root `state*.json` / `plan*.json` (sample states & plans).

**Caveat (documented by the pre-PoC audit):** legacy headline numbers in the
paper are *not reproducible from the committed artifacts* (mixture across
harness generations; three divergent metric implementations; several results
derived from analysis artifacts rather than runs). Use the PoC (`poc/`) for any
number you print; keep legacy outputs only as history. New code should **not**
import from `harness/`, `agents/` or `tools/`.

---

## 6. Environment & requirements

* **Python ≥ 3.10** (developed and validated on 3.13).
* Hard deps for the PoC: **matplotlib** only (figures). Everything else :
  SMT-style feasibility, Welch's t-test, CI95 : is dependency-free.
* **z3-solver: optional.** The verifier labels its engine (`z3-smt` vs
  `python-bfs-smt-style`) in `verifier.json`; installing `z3-solver` upgrades
  the engine automatically (see comment in `requirements.txt`).
* No pytest needed (`tests/test_poc.py` runs standalone; it also works under pytest).
* `myenv/` and `tools/myenv/` are legacy virtualenvs for the old pipeline.
* JSON-RPC isolation is stdlib-only (`subprocess`): each engagement runs in its
  own freshly spawned `python3 -m poc.rpc --seed N` child over stdio.

## 7. Reproducibility guarantees

* Plan and execution are fully determined by `seed`; two runs with the same
  seed produce byte-identical metrics (enforced in selftest/tests).
* The PRNG for execution is decoupled from the planner's (`Random(seed)`
  vs `Random(seed*100003+7)`), so planner/executor changes don't cross-contaminate.
* Every claimed number is regenerated by `poc/exp.py` from `runs.jsonl` :
  no hand-edited tables. `summary.json` is machine-readable for your CI.
* All scenario states, ground-truth chains (L_opt = 6/4/4) and policies are
  checked by tests.

## 8. Frequently asked

**Can it attack real systems?** No. There are no exploit payloads in the PoC;
targets are baked sandbox graphs; "success" is a simulated roll. It exists to
demonstrate the *safety loop*, not to run engagements.

**Why don't the numbers match the paper?** They are *not supposed to*: the
paper's committed artifacts could not reproduce them (see §5). The PoC's
numbers are the ones that are regenerable : replace the stale tables with
`POC.md` §5 / `results/poc/table2.csv`.

**Why does Safety drop in ablations?** By design: without the verifier,
out-of-scope drift and destructive-critical steps *execute*; the post-hoc
auditor flags them, and Eq. 5 counts the flags.

**How do I demo the human gate?** `python3 -m poc demo --scenario ad
--interactive` prompts `approve/deny` per HOLD token; or approve explicitly
with `--approve HOLD-4-<hash>` / `--approve-all`.

## 9. Contributing & safety policy

Contributions go through `poc/` + tests: keep plans/rationales free of
blocklist patterns (the verifier enforces this), keep scenarios sim-only, and
extend `selftest.py`/`tests/test_poc.py` with any new invariant. Additions to
`results/poc/` are regenerated artifacts : re-run `./run_poc.sh` rather than
editing them. Legacy directories are frozen provenance.
