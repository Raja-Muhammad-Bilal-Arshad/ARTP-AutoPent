"""Human-in-the-loop approval gate (HITL).

High-impact steps (impact >= ``requires_approval``) are *held* by the verifier
and can only proceed with an explicit approval decision recorded in
``approvals.jsonl``. The gate is not bypassable in the pipeline: a hold that is
neither approved nor denied blocks the run.

Operator modes
--------------
- ``scripted-standard`` deterministic operator for experiments, approves holds.
- ``scripted-cautious`` approves ``high`` but denies ``critical`` steps.
- ``interactive``       prompts the operator at the terminal (live demo).
- explicit tokens       ``--approve HOLD-...`` / ``--approve-all`` on the CLI.
"""
from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List

OPERATORS = ("scripted-standard", "scripted-cautious",
             "interactive", "explicit-token")


def _token_for(holds: List[Dict[str, Any]], token: str) -> Dict[str, Any] | None:
    for h in holds:
        if h["token"] == token:
            return h
    return None


class ApprovalLedger:
    """Records every hold decision; decides nothing on its own."""

    def __init__(self, path: str | None = None):
        self.path = path
        self.records: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    def resolve(self, holds: List[Dict[str, Any]], mode: str,
                plan_name: str = "?", approve_all: bool = False,
                approve_tokens: List[str] | None = None) -> Dict[int, str]:
        """Return {step_id: "approved" | "denied"} for every hold.

        Every decision is appended to the ledger (and approvals.jsonl when a
        path was configured) BEFORE the pipeline proceeds.
        """
        decisions: Dict[int, str] = {}
        tokens = [t for t in (approve_tokens or []) if t]
        unknown: List[str] = []

        for h in holds:
            step_id = h["step_id"]
            decision = None
            reason = ""

            if approve_all:
                decision, reason = "approved", "--approve-all flag"
            elif any(h["token"] == t for t in tokens):
                decision, reason = "approved", "explicit approval token"
            elif tokens:
                # token mode was requested but this hold was not approved
                decision, reason = "denied", "no matching approval token"

            if decision is None:
                if mode == "scripted-standard":
                    decision, reason = "approved", "scripted-standard operator"
                elif mode == "scripted-cautious":
                    if h.get("impact") == "critical":
                        decision, reason = "denied", \
                            "scripted-cautious operator denies critical impact"
                    else:
                        decision, reason = "approved", \
                            "scripted-cautious operator grants high impact"
                elif mode == "interactive":
                    decision = self._prompt(h)
                    reason = "interactive operator decision"
                else:
                    decision, reason = "denied", \
                        "unknown operator mode '{}'".format(mode)

            decisions[step_id] = decision
            rec = {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "plan": plan_name,
                "step_id": step_id,
                "token": h["token"],
                "action": h.get("action"),
                "technique": h.get("technique"),
                "impact": h.get("impact"),
                "decision": decision,
                "operator": mode if mode != "explicit-token" or approve_all
                            else "explicit-token",
                "reason": reason,
            }
            self.records.append(rec)
            self._append(rec)

        # warnings for tokens that matched no hold (possible fat-finger)
        if not approve_all:
            for t in tokens:
                if _token_for(holds, t) is None and t != "all":
                    self._append({"ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                                  "plan": plan_name, "token": t,
                                  "decision": "ignored",
                                  "operator": "explicit-token",
                                  "reason": "token matched no open hold"})
        return decisions

    # ------------------------------------------------------------------
    @staticmethod
    def _prompt(hold: Dict[str, Any]) -> str:
        print("\n[HITL] approval required -------------------------------")
        print("  step_id   : {}".format(hold["step_id"]))
        print("  token     : {}".format(hold["token"]))
        print("  action    : {}".format(hold.get("action")))
        print("  technique : {} ({})".format(hold.get("technique"),
                                            hold.get("impact")))
        print("  impact    : {}".format(hold.get("impact")))
        try:
            ans = input("[HITL] approve this step? [y/N] > ").strip().lower()
        except EOFError:
            ans = ""
        return "approved" if ans in ("y", "yes") else "denied"

    # ------------------------------------------------------------------
    def _append(self, rec: Dict[str, Any]) -> None:
        if not self.path:
            return
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, sort_keys=True) + "\n")


def apply_decisions(steps: List[Dict[str, Any]],
                    decisions: Dict[int, str]) -> List[Dict[str, Any]]:
    """Drop denied holds from the executable plan (approved/blocked kept)."""
    denied = {sid for sid, d in decisions.items() if d == "denied"}
    if not denied:
        return steps
    out = [s for s in steps if s.get("step_id") not in denied]
    for i, s in enumerate(out, start=1):
        s["step_id"] = i
    return out
