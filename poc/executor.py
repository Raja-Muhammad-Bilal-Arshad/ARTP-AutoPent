"""Simulated execution engine (the paper's 'CVSS-based, seeded simulator').

Deterministic with a seeded PRNG; no live targets are contacted. The engine
models success probabilities from the step verb, CVSS and prerequisite state,
adds observation noise epsilon = 0.05 (Eq. 8 context of Sec. 4.1), rolls the
detector D(a_t) (Eq. 6) per attack-step, and tracks the compromised set used
by Coverage (Eq. 3) plus CloudTrail-style detection telemetry for the cloud
scenario (MTTD / detection rate, Fig. 3).

Success model (documented in POC.md):
  crawl / enumerate          p = 1.0                          (read-only recon)
  check_creds                p = 0.5 credential surface exposed, else 0.2
  attempt_exploit_simulated  p = 0.3 + 0.06 * CVSS            (CVSS-based)
  escalate_simulated         p = 0.85 *requires the previous step's foothold*
  exfiltrate_simulated       p = 0.9 if a critical node is already compromised
                             else 0.2
Observed probability p_obs = clip(p_true + U(-eps, +eps), 0, 1); the step rolls
against p_obs, mirroring the paper's "observation realism based on noise
injection (epsilon = 0.05)".
"""
from __future__ import annotations

import random
from typing import Any, Dict, List, Optional, Set

EPS = 0.05

ATTACK_ACTIONS = {"check_creds", "attempt_exploit_simulated",
                  "escalate_simulated", "exfiltrate_simulated"}


def _d_score(step: Dict[str, Any]) -> float:
    """Detector's normalized alert probability D(a) for a step (Eq. 6)."""
    impact_idx = {"low": 0, "medium": 1, "high": 2, "critical": 3}[
        step.get("impact", "low")]
    is_attack = 1 if step.get("action") in ATTACK_ACTIONS else 0
    return max(0.0, min(1.0, 0.05 + 0.10 * impact_idx + 0.15 * is_attack
                        + 0.05 * float(step.get("stealth_cost", 0.0))))


class SimExecutor:
    """Holds per-session state; driven over JSON-RPC (process-isolated)."""

    def __init__(self, seed: int, surface: Any):
        self.seed = seed
        self.rng = random.Random(seed * 100003 + 7)  # decouple from planner RNG
        self.surf = surface
        self.session = "poc-sim-{:08x}".format(self.rng.getrandbits(32))
        self.compromised: Set[str] = {"ATTACKER"}
        self.results: List[Dict[str, Any]] = []
        self.prev_target: Optional[str] = None
        self.terminated = False         # detection cut the session short
        self.detected_events = 0
        self.cloud_timer = 0.0          # simulated seconds until first alert
        self.alert_at: Optional[float] = None

    # ------------------------------------------------------------------
    def p_true(self, step: Dict[str, Any]) -> tuple:
        """Return (p_true, note) for a step under the documented model."""
        action = step.get("action")
        tgt_id = step["target"]["id"]
        node = self.surf.nodes.get(tgt_id)
        cvss = float(step.get("cvss", 5.0))

        if action in ("crawl", "enumerate"):
            return 1.0, "read-only reconnaissance"

        if action == "check_creds":
            from .verifier import _exposes_credentials  # single source of rule
            if _exposes_credentials(self.surf, tgt_id):
                return 0.5, "credential surface exposed"
            return 0.2, "no exposed credential surface (blind vault trial)"

        if action == "attempt_exploit_simulated":
            return 0.3 + 0.06 * cvss, "CVSS-driven exploitation probability"

        if action == "escalate_simulated":
            if node is None or self.prev_target not in self.compromised:
                return 0.0, "escalation requires a foothold on the predecessor"
            return 0.85, "privilege escalation from established foothold"

        if action == "exfiltrate_simulated":
            if any(self._is_critical(n) for n in self.compromised):
                return 0.9, "critical pivot already compromised"
            node = self.surf.nodes.get(tgt_id)
            if node and (node.get("public") or node.get("credential_surface")):
                return 0.2, "target directly exposed; blind pull attempt"
            return 0.05, "no reachable store to pull from (blind attempt)"

        return 0.0, "unknown action"

    def _is_critical(self, node_id: str) -> bool:
        n = self.surf.nodes.get(node_id)
        return bool(n) and (bool(n.get("critical"))
                            or float(n.get("cvss", 0.0)) >= 9.5)

    # ------------------------------------------------------------------
    def execute_step(self, step: Dict[str, Any]) -> Dict[str, Any]:
        """Execute ONE step and return the per-step observation record."""
        if self.terminated:
            # session was cut short by the defender; nothing more executes
            return {"step_id": step.get("step_id"), "skipped": True,
                    "reason": "session terminated after detection"}

        p_true, note = self.p_true(step)
        p_obs = max(0.0, min(1.0, p_true + self.rng.uniform(-EPS, EPS)))
        success = self.rng.random() < p_obs

        tgt_id = step["target"]["id"]
        known = tgt_id in self.surf.nodes
        d_score = _d_score(step)
        is_attack = step.get("action") in ATTACK_ACTIONS
        impact_idx = {"low": 0, "medium": 1, "high": 2, "critical": 3}[
            step.get("impact", "low")]
        dt = 2.0 + 2.0 * impact_idx  # simulated seconds per executed step

        detected = False
        if is_attack and d_score > 0:
            detected = self.rng.random() < d_score

        if success:
            if known:
                self.compromised.add(tgt_id)

        rec = {
            "step_id": step.get("step_id"),
            "action": step.get("action"),
            "target_id": tgt_id,
            "technique": step.get("technique"),
            "impact": step.get("impact"),
            "cvss": step.get("cvss"),
            "p_true": round(p_true, 4),
            "p_obs": round(p_obs, 4),
            "epsilon": EPS,
            "success": bool(success),
            "d_score": round(d_score, 4),
            "detected": bool(detected),
            "dt_sim_seconds": dt,
            "note": note,
        }
        if not known:
            rec["note"] += " [target not in declared surface: nothing to compromise]"
        if success:
            rec["compromised"] = tgt_id

        self.results.append(rec)
        self.prev_target = tgt_id

        # cloud detection telemetry (Fig. 3): timer runs until first alert
        self.cloud_timer += dt
        if detected:
            self.detected_events += 1
            if self.alert_at is None:
                self.alert_at = self.cloud_timer
            if self.surf.scenario == "cloud":
                # CloudTrail-style loud action ends the engagement window
                self.terminated = True
                rec["terminated_session"] = True

        return rec

    # ------------------------------------------------------------------
    def summary(self) -> Dict[str, Any]:
        executed = [r for r in self.results if not r.get("skipped")]
        detected = [r for r in executed if r.get("detected")]
        det_rate = (len(detected) / len(executed)) if executed else 0.0
        return {
            "session": self.session,
            "seed": self.seed,
            "scenario": self.surf.scenario,
            "compromised": sorted(self.compromised),
            "n_steps_executed": len(executed),
            "n_steps_success": sum(1 for r in executed if r["success"]),
            "n_detected": len(detected),
            "detection_rate": round(det_rate, 4),
            "mttd_sim_seconds": round(self.alert_at, 2)
            if self.alert_at is not None else None,
            "mttd_note": "sum of dt until first alert; None = no alert in "
                         "simulation window",
            "terminated": self.terminated,
        }
