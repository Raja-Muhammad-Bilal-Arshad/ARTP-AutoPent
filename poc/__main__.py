"""ARTP PoC command-line interface.

    python3 -m poc selftest                        run invariant checks
    python3 -m poc demo [--scenario web|ad|cloud|all] [--seed N]
                                                   narrative single runs
    python3 -m poc run-poc --scenario web --config full --seed 1
                       [--operator scripted-standard|scripted-cautious]
                       [--approve-all | --approve HOLD-...] [--out DIR]
                                                   one controlled engagement
    python3 -m poc experiments [--seeds 30] [--outdir results/poc]
                       [--scenarios web,ad,cloud] [--no-baseline]
                                                   Table 2 + Fig 2/3/4
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List

from .pipeline import run_pipeline
from .selftest import selftest

SCENARIOS = ("web", "ad", "cloud")


# ---------------------------------------------------------------------------
def cmd_selftest(_args: argparse.Namespace) -> int:
    print("PoC selftest  (verifier engine: {})".format(
        _engine_label()))
    res = selftest()
    for r in res["results"]:
        mark = "PASS" if r["ok"] else "FAIL"
        print("  [{}] {}".format(mark, r["check"]))
        if not r["ok"]:
            print("        {}".format(r["detail"]))
    print("selftest: {} passed, {} failed".format(res["pass"], res["fail"]))
    return 0 if res["fail"] == 0 else 1


def _engine_label() -> str:
    try:
        from .verifier import engine_name
        return engine_name()
    except Exception:
        return "?"


def cmd_demo(args: argparse.Namespace) -> int:
    scen = args.scenario if args.scenario != "all" else None
    for scenario in (scen,) if scen else SCENARIOS:
        outdir = os.path.join("results", "poc", "demo", scenario)
        print("\n" + "=" * 74)
        print("DEMO  scenario={}  config=full  seed={}  (artifacts: {})"
              .format(scenario, args.seed, outdir))
        print("=" * 74)
        rec = run_pipeline(scenario=scenario, config="full", seed=args.seed,
                           outdir=outdir,
                           interactive=args.interactive)
        _narrate(rec)
    return 0


def _narrate(rec: Dict[str, Any]) -> None:
    m = rec["metrics"]
    print("\n-- plan ({}): {} steps in -> {} steps after verification"
          .format(rec["plan_name"], rec["verification"]["n_steps_in"],
                  rec["verification"]["n_steps_out"]))
    for s in rec["plan_final_steps"]:
        print("   {:>2}. [{:<25}] {:<22} T={:<9} impact={:<8} "
              "cvss={:.1f} r={}".format(
                  s["step_id"], s["action"], s["target"]["id"],
                  s["technique"], s["impact"], s["cvss"] or 0.0,
                  s["stealth_cost"]))
    if rec["verification"]["blocked"]:
        print("-- verifier BLOCKED:")
        for b in rec["verification"]["blocked"]:
            print("   step {}: {}".format(b["step_id"], "; ".join(b["reasons"])))
    if rec["verification"]["holds"]:
        print("-- HITL holds (impact >= requires_approval):")
        for h in rec["verification"]["holds"]:
            print("   step {}: {} -> {}".format(
                h["step_id"], h["token"], rec["holds_resolved"]
                .get(h["step_id"], "?")))
    print("\n-- simulated execution (JSON-RPC child process, session {}):"
          .format(rec["session"]["session"]))
    for r in rec["trace"]:
        if r.get("skipped"):
            print("   {:>2}. SKIP   ({})".format(r.get("step_id"), r["reason"]))
            continue
        det = "  [ALERT]" if r.get("detected") else ""
        print("   {:>2}. {} target={:<26} p_obs={:.2f} {} "
              "D={:.2f}{}".format(
                  r["step_id"], "OK " if r["success"] else "FAIL",
                  r.get("target_id", "?"), r["p_obs"],
                  "reached" if r.get("compromised") else "      ",
                  r["d_score"], det))
    print("\n-- metrics (Eqs. 2-11):")
    for k in ("coverage", "path_efficiency", "safety", "stealth",
              "composite_r", "detection_rate", "recon_precision",
              "recon_recall", "mttd_sim_seconds"):
        print("   {:<20} = {}".format(k, m.get(k)))
    print("   objective reached      = {}".format(m["objective_reached"]))
    print("   write-up: plan.json / verifier.json / approvals.jsonl / "
          "exec_trace.json / metrics.json")


def cmd_run_poc(args: argparse.Namespace) -> int:
    state = None
    if args.state_file:
        with open(args.state_file, "r", encoding="utf-8") as fh:
            state = json.load(fh)
        if not args.scenario:
            args.scenario = state.get("scenario")
        if not args.scenario:
            raise SystemExit("--state-file has no 'scenario' field; "
                             "pass --scenario explicitly")
    if not args.scenario:
        raise SystemExit("--scenario is required (or pass --state-file)")
    rec = run_pipeline(scenario=args.scenario, config=args.config,
                       seed=args.seed, outdir=args.out,
                       operator=args.operator,
                       approve_all=args.approve_all,
                       approve_tokens=args.approve or [],
                       interactive=args.interactive,
                       state=state)
    _narrate(rec)
    print("\nartifacts -> {}".format(args.out or "(in-memory only)"))
    return 0


def cmd_experiments(args: argparse.Namespace) -> int:
    from .exp import run_experiments
    scenarios = [s for s in (args.scenarios or "").split(",") if s] \
        or list(SCENARIOS)
    print("experiments: scenarios={} seeds={} outdir={}".format(
        ",".join(scenarios), args.seeds, args.outdir))
    summary = run_experiments(scenarios=scenarios, n_seeds=args.seeds,
                              outdir=args.outdir,
                              baseline_random_walk=not args.no_baseline)
    print("\ncompleted. Table-2 headline (mean ± 95%-CI, Eq. 8):")
    for scenario, sblock in summary["scenarios"].items():
        for config, agg in sblock["configs"].items():
            c = agg["coverage"]
            sf = agg["safety"]
            r = agg["composite_r"]
            st = agg["stealth"]
            ep = agg["path_efficiency"]
            obj = agg["objective_success_rate"]
            print("  {:>5} {:<22} cov={:.3f}  Ep={:.3f}  safety={:.3f}"
                  "  stealth={:.3f}  R={:.3f}  objReached={:.2f}".format(
                      scenario, config, c["mean"], ep["mean"], sf["mean"],
                      st["mean"], r["mean"], obj))
    for scenario, sblock in summary["scenarios"].items():
        for name, tests in sblock["welch_tests"].items():
            for metric in ("composite_r", "safety"):
                t = tests[metric]
                print("  welch {} {} {}: t={:.3f} df={} p={:.2g}".format(
                    scenario, name.replace("_vs_full", " vs full"), metric,
                    t["t"], t["df"], t["p"]))
    print("figures + summary -> {}/figures, {}/table2.csv, {}/summary.json"
          .format(args.outdir, args.outdir, args.outdir))
    return 0


# ---------------------------------------------------------------------------
def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="poc",
                                 description="ARTP paper PoC "
                                             "(simulation-only)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("selftest", help="invariant checks")
    p.set_defaults(fn=cmd_selftest)

    p = sub.add_parser("demo", help="narrative single engagement")
    p.add_argument("--scenario", default="all",
                   choices=["web", "ad", "cloud", "all"])
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--interactive", action="store_true",
                   help="prompt for HITL approvals in the terminal")
    p.set_defaults(fn=cmd_demo)

    p = sub.add_parser("run-poc", help="single controlled engagement")
    p.add_argument("--scenario", default=None,
                   choices=list(SCENARIOS),
                   help="required unless --state-file provides one")
    p.add_argument("--state-file", default=None,
                   help="state JSON (e.g. real-lab export); pipeline runs "
                        "unchanged against that topology")
    p.add_argument("--config", default="full",
                   choices=["full", "without_verifier", "unconstrained",
                            "baseline_random_walk"])
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--operator", default="scripted-standard",
                   choices=["scripted-standard", "scripted-cautious"])
    p.add_argument("--approve-all", action="store_true")
    p.add_argument("--approve", action="append", default=[],
                   help="HITL approval token HOLD-<sid>-<hash>; repeatable")
    p.add_argument("--interactive", action="store_true")
    p.add_argument("--out", default=None,
                   help="artifact directory (defaults per scenario/seed)")
    p.set_defaults(fn=cmd_run_poc)

    p = sub.add_parser("experiments", help="N x config runs -> tables/figures")
    p.add_argument("--seeds", type=int, default=30)
    p.add_argument("--outdir", default="results/poc")
    p.add_argument("--scenarios", default="web,ad,cloud")
    p.add_argument("--no-baseline", action="store_true",
                   help="skip the baseline_random_walk comparator")
    p.set_defaults(fn=cmd_experiments)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
