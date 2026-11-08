"""Planner: attack-surface-graph aware, MITRE-mapped, seeded & deterministic.

The planner never invents attack payloads; it walks the supplied state graph
along the BFS-shortest path to the objective and emits the paper's 6-verb
schema steps. Where the graph is missing live exporter telemetry (a documented
PoC shortcut), the planner relies on the baked-in scenario state only.
"""
from __future__ import annotations

import random
from typing import Any, Dict, List, Optional, Tuple

from .state import Surface
from .schema import ACTIONS, ATTACK_TECHNIQUES, DEFAULT_TECHNIQUE, IMPACTS  # noqa: F401

# edge relationship -> (action verb, technique, impact, cvss, stealth_cost)
REL_ACTION: Dict[str, Tuple[str, str, str, float, float]] = {
    "http": ("crawl", "T1046", "low", 3.0, 0.10),
    "public-read": ("enumerate", "T1580", "low", 4.0, 0.20),
    "same-host": ("enumerate", "T1087", "medium", 5.0, 0.20),
    "internal-service": ("enumerate", "T1046", "low", 4.0, 0.20),
    "default-creds": ("check_creds", "T1110", "medium", 7.5, 0.30),
    "credential-extract": ("check_creds", "T1552.001", "medium", 8.5, 0.30),
    "env-secret": ("check_creds", "T1552.001", "medium", 9.0, 0.30),
    "rce": ("attempt_exploit_simulated", "T1210", "medium", 8.0, 0.40),
    "assume-role": ("attempt_exploit_simulated", "T1550", "high", 8.5, 0.40),
    "phish": ("attempt_exploit_simulated", "T1566.005", "low", 3.0, 0.30),
    "kerberoastable": ("attempt_exploit_simulated", "T1558.003", "medium", 7.5, 0.40),
    "adminTo": ("escalate_simulated", "T1078", "high", 8.0, 0.50),
    "dcsync": ("attempt_exploit_simulated", "T1003.006", "high", 8.5, 0.80),
    "attach-admin": ("escalate_simulated", "T1098", "critical", 9.0, 0.60),
    "exfil-target": ("exfiltrate_simulated", "T1567", "critical", 9.3, 0.70),
    "owns": ("attempt_exploit_simulated", "T1003.006", "high", 9.0, 0.50),
    "memberOf": ("enumerate", "T1087", "low", 4.0, 0.20),
    "manages": ("enumerate", "T1087", "low", 4.0, 0.20),
    "hasSession": ("attempt_exploit_simulated", "T1046", "medium", 5.0, 0.20),
}

# paper Sec 4.4-style "necessary lateral-movement check" insertion probability
GUARD_P = {"web": 0.15, "ad": 0.70, "cloud": 0.50}
GUARD_INDEX = 2  # insert the low-noise survey step after the 2nd planned step


def _mk_step(sid: int, action: str, target_id: str, target_type: str, technique: str,
             impact: str, cvss: float, stealth_cost: float, rationale: str,
             phase: str = "core") -> Dict[str, Any]:
    return {
        "step_id": sid,
        "action": action,
        "target": {"id": target_id, "type": target_type},
        "technique": technique,
        "impact": impact,
        "cvss": cvss,
        "stealth_cost": stealth_cost,
        "rationale": rationale,
        "phase": phase,
    }


def _plan_name(scenario: str, config: str, seed: int) -> str:
    return "POC_{}_{}_seed{}".format(scenario.upper(), config, seed)


class Planner:
    """Graph-aware planner with an optional random-walk baseline mode."""

    def __init__(self, seed: int, config: str = "full"):
        assert config in ("full", "without_verifier", "unconstrained",
                          "baseline_random_walk"), "unknown planner config"
        self.seed = seed
        self.config = config
        self.rng = random.Random(seed)

    # ------------------------------------------------------------------
    def build(self, surf: Surface, objective_node: str) -> Dict[str, Any]:
        if self.config == "baseline_random_walk":
            return self._random_walk(surf, objective_node)
        path = surf.shortest_path("ATTACKER", objective_node)
        if not path:
            raise ValueError("planner: no path from ATTACKER to objective "
                             + objective_node)

        steps: List[Dict[str, Any]] = []
        sid = 1
        for e in path:
            verb, tech, imp, cvs, sc = REL_ACTION[e["rel"]]
            target = surf.nodes[e["to"]]
            rationale = ("Follows relation '{}' from {} to {} using technique {} "
                         "({}) backed by graph-distance evidence.").format(
                e["rel"], e["from"], e["to"], tech, ATTACK_TECHNIQUES[tech])
            steps.append(_mk_step(sid, verb, e["to"], target.get("type", "unknown"),
                                  tech, imp, cvs, sc, rationale))
            sid += 1

        # a low-noise lateral-movement survey step (paper's 'deviation factor'):
        # planner behavior, present in every framework config (not the
        # random-walk baseline which is a different agent entirely)
        p = GUARD_P.get(surf.scenario, 0.0)
        if self.config != "baseline_random_walk" and steps \
                and self.rng.random() < p:
            guard_target = steps[min(GUARD_INDEX, len(steps) - 1)]["target"]["id"]
            if surf.nodes.get(guard_target):
                g = _mk_step(GUARD_INDEX + 1, "enumerate", guard_target,
                             surf.nodes[guard_target].get("type", "unknown"),
                             "T1018", "low", 4.0, 0.20,
                             "Lateral-movement survey: confirm exposure before "
                             "the higher-impact step on the same asset.",
                             phase="guard")
                steps.insert(GUARD_INDEX, g)
                steps = self._renumber(steps)

        if self.config in ("without_verifier", "unconstrained"):
            steps += self._drift(len(steps) + 1)
        if self.config == "unconstrained":
            steps += self._aggressive(len(steps) + 1)

        return {
            "plan_name": _plan_name(surf.scenario, self.config, self.seed),
            "scenario": surf.scenario,
            "seed": self.seed,
            "config": self.config,
            "objective_node": objective_node,
            "ground_truth": surf.state["ground_truth"],
            "L_opt": surf.state["ground_truth"].get("optimal_path_length",
                                                    len(path)),
            "steps": steps,
        }

    # ------------------------------------------------------------------
    @staticmethod
    def _renumber(steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        for i, s in enumerate(steps, start=1):
            s["step_id"] = i
        return steps

    def _drift(self, start_sid: int) -> List[Dict[str, Any]]:
        """Exploration-drift probes: out-of-scope, low-credential-value spins."""
        steps = []
        for k in range(4):
            steps.append(_mk_step(
                start_sid + k, "attempt_exploit_simulated",
                "shadow:asset-{}".format(k + 1), "host", "T1190", "medium", 6.5, 0.40,
                "Exploration drift: noisy probe against an asset outside the "
                "declared scope; wastes the error budget (paper failure mode 1).",
                phase="drift"))
        return steps

    def _aggressive(self, start_sid: int) -> List[Dict[str, Any]]:
        """Over-aggressive probing (paper failure mode 2): destructive drift."""
        steps = []
        for k in range(3):
            steps.append(_mk_step(
                start_sid + k, "escalate_simulated",
                "shadow:asset-b{}".format(k + 1), "host", "T1059", "critical", 10.0, 1.50,
                "Over-aggressive probing: high-impact destructive variant that "
                "the verifier would normally deny; no approval was sought.",
                phase="aggressive"))
        return steps

    # ------------------------------------------------------------------
    def _random_walk(self, surf: Surface, objective_node: str) -> Dict[str, Any]:
        """Uninformed random-walk baseline (paper Sec 4.4 comparator)."""
        budget = 6
        node = "ATTACKER"
        steps: List[Dict[str, Any]] = []
        sid = 1
        for _ in range(budget):
            outs = surf.out_edges(node)
            if not outs:
                break
            e = self.rng.choice(outs)
            verb, tech, imp, cvs, sc = REL_ACTION.get(
                e["rel"], ("attempt_exploit_simulated", "T1190", "medium", 6.0, 0.40))
            target = surf.nodes[e["to"]]
            steps.append(_mk_step(sid, verb, e["to"], target.get("type", "unknown"),
                                  tech, imp, cvs, sc,
                                  "Uninformed random-walk baseline step along "
                                  "relation '{}' (no graph-aware priority).".format(e["rel"]),
                                  phase="random-walk"))
            sid += 1
            node = e["to"]
            if node == objective_node:
                break
        return {
            "plan_name": _plan_name(surf.scenario, self.config, self.seed),
            "scenario": surf.scenario,
            "seed": self.seed,
            "config": self.config,
            "objective_node": objective_node,
            "ground_truth": surf.state["ground_truth"],
            "L_opt": surf.state["ground_truth"].get("optimal_path_length", 4),
            "steps": steps,
        }
