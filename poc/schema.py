"""Action schema, MITRE ATT&CK mapping, blocklists, and approval-token helpers.

Implements the paper's constrained action schema A (Sec. 3.2): six verbs
(crawl, enumerate, check_creds, attempt_exploit_simulated, escalate_simulated,
exfiltrate_simulated), each a well-specified JSON object mapped to MITRE
ATT&CK techniques.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, List

IMPACTS = {"low": 0, "medium": 1, "high": 2, "critical": 3}
IMPACT_ORDER = ("low", "medium", "high", "critical")

ACTIONS = (
    "crawl",
    "enumerate",
    "check_creds",
    "attempt_exploit_simulated",
    "escalate_simulated",
    "exfiltrate_simulated",
)

REQUIRED_FIELDS = (
    "step_id",
    "action",
    "target",
    "technique",
    "impact",
    "cvss",
    "stealth_cost",
    "rationale",
)

# ---- MITRE ATT&CK mapping (used for technique selection + explanation) ----
ATTACK_TECHNIQUES: Dict[str, str] = {
    "T1046": "Network Service Discovery",
    "T1087": "Account Discovery",
    "T1018": "Remote System Discovery",
    "T1110": "Brute Force / Default Credentials",
    "T1190": "Exploit Public-Facing Application",
    "T1210": "Exploitation of Remote Services",
    "T1505": "Server Software Component",
    "T1558.003": "Kerberoasting",
    "T1003.006": "DCSync",
    "T1078": "Valid Accounts (local admin)",
    "T1566.005": "Phishing: Spearphishing Link",
    "T1550": "Alternate Authentication Material (AssumeRole)",
    "T1098": "Account Manipulation (attach admin)",
    "T1552.001": "Unsecured Credentials (keys in bucket)",
    "T1567": "Exfiltration Over Web Service",
    "T1059": "Command and Scripting Interpreter (destructive drift)",
    "T1580": "Cloud Infrastructure Discovery",
}

DEFAULT_TECHNIQUE = {
    "crawl": "T1046",
    "enumerate": "T1087",
    "check_creds": "T1110",
    "attempt_exploit_simulated": "T1190",
    "escalate_simulated": "T1078",
    "exfiltrate_simulated": "T1567",
}

# ---- Blocklist: patterns that must NEVER appear in any plan step ----
# These are strings the *verifier* rejects; the PoC never produces attack
# payloads itself. Detection patterns only.
BLOCKLIST_PATTERNS = (
    r"rm\s+-rf",
    r"mkfs(\.|\s|$)",
    r"nc\s+-e",
    r"bash\s+-i",
    r"drop\s+table",
    r"delete\s+from\s+\w+",
    r"shutdown\s+-h",
    r"wget\s+http",
    r"curl\s+http",
    r"curl\s+https",
    r"chmod\s+777",
    r"/etc/shadow",
    r" Powershell\s+-enc",
)

# Rcompromise relationship labels: an action on a node also compromises a
# direct neighbour when the edge expresses direct control.
CONTROL_RELS = {
    "rce",
    "assume-role",
    "attach-admin",
    "dcsync",
    "adminTo",
    "local-admin",
    "exfil-target",
    "credential-extract",
    "default-creds",
}


def step_token(step: Dict[str, Any]) -> str:
    """Stable approval-token for a high-impact step (HITL ledger key)."""
    h = hashlib.sha256(
        json.dumps(step, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()[:8]
    return "HOLD-{}-{}".format(step.get("step_id", "?"), h)


def validate_step(step: Any, policy: Dict[str, Any] | None = None) -> List[str]:
    """Return list of schema/shape errors ([] == conforming)."""
    if not isinstance(step, dict):
        return ["step is not a JSON object"]
    errs: List[str] = []
    for f in REQUIRED_FIELDS:
        if f not in step:
            errs.append("missing required field '{}'".format(f))
    if step.get("action") not in ACTIONS:
        errs.append("unknown action '{}' (schema = {})".format(step.get("action"), list(ACTIONS)))
    target = step.get("target")
    if not isinstance(target, dict) or "id" not in target or "type" not in target:
        errs.append("target must be an object with 'id' and 'type'")
    if step.get("impact") not in IMPACTS:
        errs.append("impact must be one of {}".format(sorted(IMPACTS)))
    cv = step.get("cvss")
    if not isinstance(cv, (int, float)) or isinstance(cv, bool) or not 0.0 <= cv <= 10.0:
        errs.append("cvss must be a number in [0, 10]")
    sc = step.get("stealth_cost")
    if not isinstance(sc, (int, float)) or isinstance(sc, bool) or not 0.0 <= sc <= 2.0:
        errs.append("stealth_cost must be a number in [0, 2]")
    if not isinstance(step.get("rationale"), str) or not step["rationale"].strip():
        errs.append("rationale must be a non-empty string")
    if step.get("technique") not in ATTACK_TECHNIQUES:
        errs.append("technique '{}' not in MITRE ATT&CK mapping".format(step.get("technique")))
    # Blocklist scan over the whole serialized step.
    blob = json.dumps(step, default=str).lower()
    for pat in BLOCKLIST_PATTERNS:
        if re.search(pat, blob):
            errs.append("blocklist pattern '{}' present in step".format(pat))
    return errs


def impact_at_least(impact: str, threshold: str) -> bool:
    return IMPACTS[impact] >= IMPACTS[threshold]


def risk_index(cvss: float, impact: str, stealth_cost: float) -> float:
    """Simple paper-style risk proxy: 0.5*CVSS/10 + 0.3*impact + 0.2*stealth."""
    return 0.5 * (cvss / 10.0) + 0.3 * (IMPACTS[impact] / 3.0) + 0.2 * (stealth_cost / 2.0)


def tech_name(tech: str) -> str:
    return ATTACK_TECHNIQUES.get(tech, "unknown technique: " + str(tech))
