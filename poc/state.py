"""Attack-surface graph G=(V,E) and sandbox demo scenario states.

The paper defines Coverage = |V_compromised| / |V_total| on an attack-surface
graph; this module is the single source of V for every scenario. Demo states
are baked deterministically here (no live targets required), which keeps the
PoC reproducible and offline.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Set

SCENARIOS = ("web", "ad", "cloud")

PROTECTED_TYPES = {
    "web": {"endpoint", "account", "service", "data"},
    "ad": {"user", "computer", "group", "domain", "service-account"},
    "cloud": {"bucket", "role", "function", "secret", "data"},
}

DEFAULT_POLICY = {
    "scope": "poc-sandbox",
    "max_impact": "high",          # impact past high requires human approval
    "requires_approval": "high",   # hold-for-human threshold
    "stealth_budget": 2.5,
    "credential_attempts_max": 3,
}


def _state(scenario: str, nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]],
           ground_truth: Dict[str, Any], name: str) -> Dict[str, Any]:
    return {
        "meta": {"name": name, "scenario": scenario, "sandbox": True,
                 "scope": "poc-sandbox", "poc_version": "1.0.0"},
        "scenario": scenario,
        "nodes": nodes,
        "edges": edges,
        "policies": dict(DEFAULT_POLICY),
        "ground_truth": ground_truth,
    }


# --------------------------------------------------------------------------
# Web cluster (Juice-Shop-like, synthetic; no live hosts needed)
# --------------------------------------------------------------------------
def demo_web_state() -> Dict[str, Any]:
    nodes = [
        {"id": "ATTACKER", "type": "attacker"},
        {"id": "ep:juice:/", "type": "endpoint"},
        {"id": "ep:juice:/api", "type": "endpoint"},
        {"id": "svc:orders-db", "type": "service", "cvss": 9.8, "critical": True},
        {"id": "ep:web2:/login", "type": "endpoint", "credential_surface": True},
        {"id": "acct:admin@web2", "type": "account", "cvss": 7.5},
        {"id": "ep:web2:/admin", "type": "endpoint", "cvss": 8.8},
        {"id": "web2", "type": "host", "cvss": 9.0, "critical": True},
        {"id": "ep:micro:/data/export", "type": "endpoint", "cvss": 9.3},
        {"id": "data:users-db", "type": "data", "critical": True},
        # noise/decoy nodes an unconstrained agent would drift onto
        {"id": "ep:shadow:/", "type": "endpoint", "tags": ["out_of_scope"]},
        {"id": "host:shadow", "type": "host", "tags": ["out_of_scope"]},
    ]
    edges = [
        {"from": "ATTACKER", "to": "ep:juice:/", "rel": "http"},
        {"from": "ep:juice:/", "to": "ep:juice:/api", "rel": "same-host"},
        {"from": "ep:juice:/api", "to": "svc:orders-db", "rel": "rce", "technique": "T1210"},
        {"from": "ATTACKER", "to": "ep:web2:/login", "rel": "http"},
        {"from": "ep:web2:/login", "to": "acct:admin@web2", "rel": "default-creds", "technique": "T1110"},
        {"from": "acct:admin@web2", "to": "ep:web2:/admin", "rel": "adminTo"},
        {"from": "ep:web2:/admin", "to": "web2", "rel": "rce", "technique": "T1210"},
        {"from": "web2", "to": "ep:micro:/data/export", "rel": "internal-service", "technique": "T1046"},
        {"from": "ep:micro:/data/export", "to": "data:users-db", "rel": "exfil-target", "technique": "T1567"},
    ]
    ground_truth = {
        "optimal_path_length": 6,
        "objective_node": "data:users-db",
        "recon_targets": ["ep:juice:/", "ep:juice:/api", "ep:web2:/login",
                          "ep:web2:/admin", "ep:micro:/data/export"],
        "objective": "Dump users table via orders-db chain",
    }
    return _state("web", nodes, edges, ground_truth, "poc-web-cluster")


# --------------------------------------------------------------------------
# Active-Directory graph with the paper's 4-hop kill chain
# (Phishing -> Kerberoasting -> AdminTo -> DCSync) plus realistic distractors.
# --------------------------------------------------------------------------
def demo_ad_state() -> Dict[str, Any]:
    nodes: List[Dict[str, Any]] = [
        {"id": "ATTACKER", "type": "attacker"},
        {"id": "DC-01", "type": "computer", "critical": True, "cvss": 10.0},
        {"id": "DOAZLAB-POC", "type": "domain", "critical": True, "cvss": 10.0},
        {"id": "u_amy_rhodes", "type": "user", "cvss": 6.0, "spn": False},
        {"id": "svc_sql", "type": "service-account", "cvss": 8.5,
         "spn": True, "becomes": "domain-admin-session-bearer"},
        {"id": "WKST-01", "type": "computer", "cvss": 8.0},
    ]
    # distractor users (managers have no sensitive direct edges to DC)
    for i in range(1, 25):
        nodes.append({"id": "u%02d" % i, "type": "user", "cvss": 4.0})
    for i in range(1, 6):
        nodes.append({"id": "FS%02d" % i, "type": "computer", "cvss": 5.0})
    for gid in ("GRP_IT", "GRP_HR", "GRP_HELPDESK", "GRP_DOMAIN_ADMINS", "GRP_ENTERPRISE_ADMINS"):
        nodes.append({"id": gid, "type": "group",
                      "cvss": 9.5 if "ADMIN" in gid else 5.5})

    edges: List[Dict[str, Any]] = [
        # ---- the paper's kill chain (4 hops) ----
        {"from": "ATTACKER", "to": "u_amy_rhodes", "rel": "phish",
         "technique": "T1566.005"},
        {"from": "u_amy_rhodes", "to": "svc_sql", "rel": "kerberoastable",
         "technique": "T1558.003"},
        {"from": "svc_sql", "to": "WKST-01", "rel": "adminTo", "technique": "T1078"},
        {"from": "WKST-01", "to": "DC-01", "rel": "dcsync", "technique": "T1003.006"},
        {"from": "DC-01", "to": "DOAZLAB-POC", "rel": "owns", "technique": "T1098"},
    ]
    # distractor edges: a normal HR/OU mess that a random walker gets lost in
    managers = ["u01", "u02", "u03"]
    for i in range(1, 25):
        edges.append({"from": managers[i % len(managers)] if i > 3 else "u_amy_rhodes",
                      "to": "u%02d" % i, "rel": "manages", "technique": "T1087"})
        edges.append({"from": "u%02d" % i,
                      "to": ("GRP_IT", "GRP_HR", "GRP_HELPDESK")[i % 3],
                      "rel": "memberOf", "technique": "T1087"})
    for i in range(1, 6):
        edges.append({"from": "GRP_IT", "to": "FS%02d" % i, "rel": "adminTo",
                      "technique": "T1078"})
        edges.append({"from": "u%02d" % i, "to": "FS%02d" % i, "rel": "hasSession",
                      "technique": "T1046"})
    edges.append({"from": "u02", "to": "GRP_DOMAIN_ADMINS", "rel": "memberOf",
                  "technique": "T1078"})
    edges.append({"from": "GRP_HELPDESK", "to": "GRP_DOMAIN_ADMINS", "rel": "memberOf",
                  "technique": "T1078"})
    edges.append({"from": "GRP_DOMAIN_ADMINS", "to": "DC-01", "rel": "adminTo",
                  "technique": "T1003.006"})

    ground_truth = {
        "optimal_path_length": 4,   # 4-hop kill chain per paper Sec. 4.4
        "objective_node": "DC-01",
        "recon_targets": ["u_amy_rhodes", "svc_sql", "WKST-01", "DC-01"],
        "objective": "Domain Dominance (DCSync against DC-01)",
        "chain": ["Phishing", "Kerberoasting", "AdminTo", "DCSync"],
    }
    return _state("ad", nodes, edges, ground_truth, "poc-ad-domain")


# --------------------------------------------------------------------------
# Cloud environment (LocalStack-style, synthetic)
# --------------------------------------------------------------------------
def demo_cloud_state() -> Dict[str, Any]:
    nodes = [
        {"id": "ATTACKER", "type": "attacker"},
        {"id": "bucket:financial-backups-prod", "type": "bucket", "cvss": 8.0,
         "public": True, "credential_surface": True},
        {"id": "bucket:dev-tfstate", "type": "bucket", "cvss": 7.0, "public": True},
        {"id": "role:deploy-bot", "type": "role", "cvss": 8.5, "critical": True},
        {"id": "fn:invoicer", "type": "function", "cvss": 8.2},
        {"id": "secret:api-prod-key", "type": "secret", "cvss": 9.5, "critical": True},
        {"id": "data:all_loot", "type": "data", "critical": True},
    ]
    edges = [
        {"from": "ATTACKER", "to": "bucket:financial-backups-prod", "rel": "public-read",
         "technique": "T1580"},
        {"from": "ATTACKER", "to": "bucket:dev-tfstate", "rel": "public-read",
         "technique": "T1580"},
        {"from": "bucket:financial-backups-prod", "to": "role:deploy-bot",
         "rel": "credential-extract", "technique": "T1552.001", "creds": "deploy-bot-keys"},
        {"from": "role:deploy-bot", "to": "fn:invoicer", "rel": "assume-role",
         "technique": "T1550"},
        {"from": "fn:invoicer", "to": "secret:api-prod-key", "rel": "env-secret",
         "technique": "T1552.001", "creds": "API_KEYS"},
        {"from": "role:deploy-bot", "to": "data:all_loot", "rel": "attach-admin",
         "technique": "T1098"},
        {"from": "data:all_loot", "to": "secret:api-prod-key", "rel": "exfil-target",
         "technique": "T1567"},
    ]
    ground_truth = {
        "optimal_path_length": 4,
        "objective_node": "secret:api-prod-key",
        "recon_targets": ["bucket:financial-backups-prod", "bucket:dev-tfstate",
                          "role:deploy-bot", "fn:invoicer"],
        "objective": "Exfiltrate cloud secrets via over-privileged role",
    }
    return _state("cloud", nodes, edges, ground_truth, "poc-cloud-lab")


# --------------------------------------------------------------------------
class Surface:
    """In-memory view over a scenario state."""

    def __init__(self, state: Dict[str, Any]):
        self.state = state
        self.scenario = state.get("scenario", "web")
        self.nodes: Dict[str, Dict[str, Any]] = {n["id"]: n for n in state["nodes"]}
        self.edges: List[Dict[str, Any]] = state["edges"]
        self.policies = state.get("policies", dict(DEFAULT_POLICY))
        self._adj: Dict[str, List[Dict[str, Any]]] = {}
        for e in self.edges:
            self._adj.setdefault(e["from"], []).append(e)

    # -- graph primitives ---------------------------------------------------
    def out_edges(self, node_id: str) -> List[Dict[str, Any]]:
        return self._adj.get(node_id, [])

    def reachable(self, start_ids: Set[str], target_id: str, max_depth: int = 16) -> bool:
        """BFS reachability (no external deps; sufficient for PoC graphs)."""
        if target_id in start_ids:
            return True
        seen: Set[str] = set(start_ids)
        frontier = set(start_ids)
        for _ in range(max_depth):
            nxt: Set[str] = set()
            for n in frontier:
                for e in self.out_edges(n):
                    if e["to"] not in seen:
                        seen.add(e["to"])
                        if e["to"] == target_id:
                            return True
                        nxt.add(e["to"])
            frontier = nxt
            if not frontier:
                return False
        return False

    def shortest_path(self, start: str, target: str,
                      edges_must_technique: bool = False) -> List[Dict[str, Any]]:
        """BFS shortest edge path; returns the list of edges."""
        if start == target:
            return []
        from collections import deque
        q = deque([(start, [])])
        seen = {start}
        while q:
            node, path = q.popleft()
            for e in self.out_edges(node):
                nxt = e["to"]
                if nxt in seen:
                    continue
                seen.add(nxt)
                npath = path + [e]
                if nxt == target:
                    return npath
                q.append((nxt, npath))
        return []

    def compromise_from(self, target_id: str) -> Set[str]:
        """Nodes that fall under scanner control when `target_id` is compromised."""
        comp: Set[str] = {target_id}
        for e in self.out_edges(target_id):
            if e["rel"] in ("credential-extract", "attach-admin", "dcsync"):
                comp.add(e["to"])
        for e in self.edges:
            if e["to"] == target_id and e["rel"] == "owns":
                comp.add(e["from"])
        return comp

    # -- metric helpers ---------------------------------------------------
    def v_total(self) -> Set[str]:
        """Protected (in-scope) nodes — the paper's |V_total|."""
        prot = PROTECTED_TYPES[self.scenario]
        return {nid for nid, n in self.nodes.items()
                if n.get("type") in prot and "out_of_scope" not in n.get("tags", [])}

    def is_in_scope(self, target_id: str) -> bool:
        n = self.nodes.get(target_id)
        return bool(n) and "out_of_scope" not in n.get("tags", [])

    def critical_nodes(self) -> Set[str]:
        return {nid for nid, n in self.nodes.items()
                if n.get("critical") or (n.get("cvss") or 0) >= 9.5}


# ---------------------------------------------------------------------------
def save(state: Dict[str, Any], path: str) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2, sort_keys=True)
    return path


DEMO_STATES = {"web": demo_web_state, "ad": demo_ad_state, "cloud": demo_cloud_state}


def load(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)
