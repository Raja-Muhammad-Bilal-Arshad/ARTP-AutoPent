"""
Rule-based deterministic agent for AutoPENT bench.

File: agents/rule_based/pipeline.py
Provides: RuleAgent class implementing the simple interface expected by harness.py

- Deterministic: accepts a `seed` to make decisions reproducible.
- Safe-by-design: produces only schema-conformant, simulated actions (no payloads, no real exploit binaries).
- Testable: `__main__` includes a smoke test using `example_state.json`-like structure.

Action JSON schema (per paper/harness expectations):
{
  "action": "exploit_simulated" | "enumerate" | "crawl" | "check_creds" | "escalate_simulated" | "exfiltrate_simulated",
  "target": {"host": "10.0.0.5", "service": "http", "port": 80, "path": "/login"},
  "params": { ... },
  "confidence": 0.0-1.0,
  "rationale": "Human-readable reason for selection"
}

Design goals:
* Keep logic readable and auditable (important for reproducible research and reviews).
* Use clear heuristics (version checks, default-credential checks, endpoint discovery) rather than opaque heuristics.
* No external network calls. Works on normalized state already produced by ingestors.

"""
from __future__ import annotations

import logging
import math
import random
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger("rule_agent")
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
ch.setFormatter(formatter)
logger.addHandler(ch)


# --- Typed aliases ---
State = Dict[str, Any]
Action = Dict[str, Any]


@dataclass
class RuleAgentConfig:
    # Added `mode` to accept adapter-provided config keys (e.g., --mode rule)
    seed: Optional[int] = 42
    mode: str = "rule"
    max_actions: int = 50
    confidence_decay: float = 0.9  # reduce confidence for chained actions
    verbosity: int = 0


class RuleAgent:
    """Deterministic rule-based agent.

    Typical usage from harness.py::
        agent = RuleAgent(config)
        plan = agent.propose_plan(state)

    The state parameter is expected to be the normalized canonical state
    produced by the ingestion phase (hosts, services, web_endpoints, accounts, telemetry_confidence).
    """

    def __init__(self, config: RuleAgentConfig | Dict[str, Any] | None = None):
        if isinstance(config, dict):
            config = RuleAgentConfig(**config)
        self.config: RuleAgentConfig = config or RuleAgentConfig()
        self.rng = random.Random(self.config.seed)
        if self.config.verbosity:
            logger.setLevel(logging.DEBUG)
        self._action_count = 0

    # --- Public API expected by harness ---
    def propose_plan(self, state: State) -> List[Action]:
        """Return an ordered list of actions (JSON-serializable) representing the rule-based plan."""
        logger.info("RuleAgent: Starting plan generation (seed=%s, mode=%s)", self.config.seed, self.config.mode)
        canonical = self._normalize_state(state)
        actions: List[Action] = []

        # Phase 1: initial reconnaissance actions (deterministic ordering)
        recon_actions = self._recon_phase(canonical)
        actions.extend(recon_actions)

        # Phase 2: enumerate discovered services/endpoints
        enum_actions = self._enumeration_phase(canonical)
        actions.extend(enum_actions)

        # Phase 3: credential checks (default creds heuristics)
        cred_actions = self._check_creds_phase(canonical)
        actions.extend(cred_actions)

        # Phase 4: scripted exploitation heuristics
        exploit_actions = self._exploit_phase(canonical)
        actions.extend(exploit_actions)

        # Phase 5: post-exploitation simulated steps (escalation/exfil)
        post_actions = self._post_exploit_phase(canonical)
        actions.extend(post_actions)

        # Trim to max actions
        if len(actions) > self.config.max_actions:
            actions = actions[: self.config.max_actions]

        logger.info("RuleAgent: Generated %d actions", len(actions))
        return actions

    # --- Internal helpers ---
    def _normalize_state(self, state: State) -> State:
        """Ensure the state contains expected keys with defaults and canonical ordering for determinism."""
        canonical: State = {}
        canonical["hosts"] = sorted(state.get("hosts", []), key=lambda h: h.get("ip", ""))
        canonical["services"] = {}
        for host in canonical["hosts"]:
            ip = host.get("ip")
            # support both dict-of-lists and list-of-services formats gracefully
            services_map = state.get("services", {})
            services = services_map.get(ip, []) if isinstance(services_map, dict) else [s for s in services_map if s.get("host") == ip]
            # sort services deterministically: by name then port (safe default port cast)
            def svc_sort_key(s):
                name = s.get("name", "")
                try:
                    port = int(s.get("port", 0))
                except Exception:
                    port = 0
                return (name, port)
            canonical["services"][ip] = sorted(services, key=svc_sort_key)
        canonical["web_endpoints"] = sorted(state.get("web_endpoints", []), key=lambda e: (e.get("host", ""), e.get("path", "")))
        canonical["accounts"] = state.get("accounts", {})
        canonical["telemetry_confidence"] = state.get("telemetry_confidence", 0.9)
        return canonical

    def _make_action(self, action: str, target: Dict[str, Any], params: Optional[Dict[str, Any]] = None, confidence: float = 0.9, rationale: str = "") -> Action:
        self._action_count += 1
        return {
            "action": action,
            "target": target,
            "params": params or {},
            "confidence": max(0.0, min(1.0, float(confidence))),
            "rationale": rationale,
        }

    # Recon
    def _recon_phase(self, canonical: State) -> List[Action]:
        actions: List[Action] = []
        # For each host, schedule an "enumerate" action to gather service details
        for host in canonical["hosts"]:
            ip = host.get("ip")
            target = {"host": ip}
            rationale = f"Deterministic recon for host {ip}"
            actions.append(self._make_action("enumerate", target, {}, confidence=0.95, rationale=rationale))
        # For each web endpoint, schedule a crawl action
        for ep in canonical.get("web_endpoints", []):
            target = {"host": ep.get("host"), "service": "http", "path": ep.get("path")}
            rationale = f"Crawl discovered web endpoint {ep.get('path')} on {ep.get('host')}"
            actions.append(self._make_action("crawl", target, {}, confidence=0.9, rationale=rationale))
        return actions

    def _enumeration_phase(self, canonical: State) -> List[Action]:
        actions: List[Action] = []
        for ip, services in canonical["services"].items():
            for svc in services:
                target = {"host": ip, "service": svc.get("name"), "port": svc.get("port")}
                rationale = f"Enumerate {svc.get('name')} on {ip}:{svc.get('port')}"
                actions.append(self._make_action("enumerate", target, {}, confidence=0.9, rationale=rationale))
        return actions

    def _check_creds_phase(self, canonical: State) -> List[Action]:
        actions: List[Action] = []
        # Heuristic: for certain services check default creds (http login pages, minio, mysql, ssh)
        default_services = {"http": "/login", "minio": None, "mysql": None, "ssh": None}
        for ip, services in canonical["services"].items():
            for svc in services:
                name = svc.get("name", "").lower()
                if name in default_services:
                    target = {"host": ip, "service": name, "port": svc.get("port")}
                    rationale = f"Check default/weak credentials for {name} on {ip}:{svc.get('port')}"
                    actions.append(self._make_action("check_creds", target, {}, confidence=0.8, rationale=rationale))
        return actions

    def _exploit_phase(self, canonical: State) -> List[Action]:
        """Scripted exploit heuristics. No raw payloads. Use simulator-friendly descriptors."""
        actions: List[Action] = []
        # Simple heuristic rules (explicit, reviewable):
        # - If a web endpoint contains typical injection vectors (/search, /login) -> attempt exploit_simulated with type 'sql_injection' or 'auth_bypass'
        # - If service version is known and older than threshold -> attempt exploit_simulated with 'known_rce'
        # - If check_creds found credentials (simulated) -> attempt escalate_simulated

        # Web heuristics
        for ep in canonical.get("web_endpoints", []):
            path = ep.get("path", "")
            host = ep.get("host")
            if any(k in path.lower() for k in ["login", "search", "query", "id="]):
                target = {"host": host, "service": "http", "path": path}
                rationale = f"Heuristic: endpoint {path} looks like input handling; try simulated SQLi/auth_bypass on {host}"
                actions.append(self._make_action("exploit_simulated", target, {"type": "auth_bypass_or_sqli"}, confidence=0.7, rationale=rationale))
            elif any(k in path.lower() for k in ["upload", "file"]):
                target = {"host": host, "service": "http", "path": path}
                rationale = f"Heuristic: file upload endpoint at {path}; attempt simulated file-upload exploit"
                actions.append(self._make_action("exploit_simulated", target, {"type": "file_upload"}, confidence=0.6, rationale=rationale))

        # Service-version heuristics
        for ip, services in canonical["services"].items():
            for svc in services:
                version = svc.get("version")
                name = svc.get("name", "").lower()
                if version:
                    # naive semantic version check: if major version <= 1 treat as potentially vulnerable (example rule)
                    try:
                        parts = [int(x) for x in version.split(".") if x.isdigit()]
                        if parts and parts[0] <= 1:
                            target = {"host": ip, "service": name, "port": svc.get("port")}
                            rationale = f"Heuristic: {name} version {version} on {ip} looks old; attempt known_rce simulated exploit"
                            actions.append(self._make_action("exploit_simulated", target, {"type": "known_rce"}, confidence=0.65, rationale=rationale))
                    except Exception:
                        # not a version we can parse; skip
                        pass

        # Credential-based escalation (we simulate that check_creds outcome may yield credentials in state.accounts)
        accounts: Dict[str, Any] = canonical.get("accounts", {})
        # Example accounts format: {"10.0.0.5": [{"service":"ssh","username":"admin","password":"admin"}], ...}
        for ip, acct_list in accounts.items():
            for acct in acct_list:
                svc = acct.get("service")
                if acct.get("password") in ("admin", "password", "123456") or acct.get("from_check_creds"):
                    target = {"host": ip, "service": svc}
                    rationale = f"Credential heuristic: found weak/default creds for {svc} on {ip}; attempt escalate_simulated"
                    actions.append(self._make_action("escalate_simulated", target, {}, confidence=0.85, rationale=rationale))

        return actions

    def _post_exploit_phase(self, canonical: State) -> List[Action]:
        actions: List[Action] = []
        # If escalation performed (we can't inspect executor state here), use conservative post-exploit attempts
        # For determinism, add exfiltrate_simulated for hosts with writable endpoints (heuristic: presence of /backup or /data)
        for ep in canonical.get("web_endpoints", []):
            path = ep.get("path", "")
            host = ep.get("host")
            if any(k in path.lower() for k in ["backup", "data", "download"]):
                target = {"host": host, "service": "http", "path": path}
                rationale = f"Post-exploit heuristic: exfiltrate from {path} on {host}"
                actions.append(self._make_action("exfiltrate_simulated", target, {"type": "download_sensitive"}, confidence=0.6, rationale=rationale))
        return actions


# --- Module smoke test / CLI usage ---
if __name__ == "__main__":
    import json
    import os

    # Sample minimal example_state mimic (similar shape to harness_targets/web_cluster/example_state.json)
    example_state = {
        "hosts": [{"ip": "10.0.0.2"}, {"ip": "10.0.0.3"}],
        "services": {
            "10.0.0.2": [{"name": "http", "port": 80, "version": "1.0"}, {"name": "ssh", "port": 22}],
            "10.0.0.3": [{"name": "minio", "port": 9000, "version": "2020.1"}]
        },
        "web_endpoints": [
            {"host": "10.0.0.2", "path": "/login"},
            {"host": "10.0.0.3", "path": "/data/backup"}
        ],
        "accounts": {
            "10.0.0.3": [{"service": "minio", "username": "admin", "password": "admin", "from_check_creds": True}]
        },
        "telemetry_confidence": 0.9,
    }

    agent = RuleAgent(RuleAgentConfig(seed=123, max_actions=100, verbosity=1))
    plan = agent.propose_plan(example_state)
    print("\nGenerated plan (JSON lines):\n")
    for step in plan:
        print(json.dumps(step))

    # Save an example plan to disk for quick manual harness integration
    outdir = os.path.join(os.getcwd(), "sample_outputs")
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "rule_plan.jsonl"), "w") as f:
        for step in plan:
            f.write(json.dumps(step) + "\n")

    logger.info("Sample plan saved to %s", outdir)

