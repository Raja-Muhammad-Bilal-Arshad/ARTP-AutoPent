#!/usr/bin/env python3
"""
AutoPENT Cloud State Builder (Black Hat Edition)
------------------------------------------------
Aggregates raw cloud reconnaissance data into a weaponized state object.
Performs automated "High Value Target" (HVT) identification and 
attack surface mapping before the Planner even starts.

Usage:
    python3 tools/build_state_cloud.py --cloud tmp_orch_cloud/cloud_recon.json --exploit tmp_orch_cloud/cloud_exploit.json --out state_from_cloud.json
"""

import argparse
import json
import os
import sys
import time
from typing import Dict, List, Any

# ---------------------------------------------------------------------
# Configuration: Keywords that trigger "High Value" tagging
# ---------------------------------------------------------------------
HVT_KEYWORDS = [
    "admin", "prod", "production", "secret", "key", "token", "backup", 
    "db", "database", "finance", "payment", "pci", "pii", "shadow"
]

def load_json_safe(path: str) -> Dict:
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except Exception as e:
        # It's okay if exploit file doesn't exist yet (recon only phase)
        return {}

def analyze_attack_surface(recon_data: Dict) -> Dict:
    """
    Enriches raw recon data with "Attacker Perspective" metadata.
    Tags assets as Critical/High/Medium/Low based on keywords and configuration.
    """
    stats = {"critical_assets": 0, "public_buckets": 0, "admin_roles": 0}
    
    # 1. Analyze S3 Buckets
    for bucket in recon_data.get("s3_buckets", []):
        score = 0
        tags = []
        name = bucket.get("name", "").lower()
        
        # Public access is critical
        if bucket.get("public"):
            score += 10
            tags.append("PUBLIC_ACCESS")
            stats["public_buckets"] += 1
            
        # Keyword matching
        if any(k in name for k in HVT_KEYWORDS):
            score += 5
            tags.append("HVT_KEYWORD")
            
        bucket["attack_priority"] = score
        bucket["tags"] = tags
        if score >= 10:
            bucket["classification"] = "CRITICAL"
            stats["critical_assets"] += 1
        elif score >= 5:
            bucket["classification"] = "HIGH"
        else:
            bucket["classification"] = "MEDIUM"

    # 2. Analyze IAM Roles
    roles = recon_data.get("iam_identities", {}).get("roles", [])
    for role in roles:
        score = 0
        name = role.get("name", "").lower()
        policy = str(role.get("trust_policy", "")).lower()
        
        if "admin" in name or "deploy" in name:
            score += 8
            stats["admin_roles"] += 1
        
        if "*" in policy: # Wildcard trust
            score += 5
            role["vulnerability"] = "Wildcard Trust"
            
        role["attack_priority"] = score
        if score >= 8:
            role["classification"] = "CRITICAL"
        else:
            role["classification"] = "STANDARD"

    # 3. Analyze Lambdas
    for func in recon_data.get("lambda_functions", []):
        if func.get("env_vars_exposed"):
            func["attack_priority"] = 10
            func["classification"] = "CRITICAL"
            stats["critical_assets"] += 1
        else:
            func["attack_priority"] = 1
            func["classification"] = "LOW"

    recon_data["analysis_summary"] = stats
    return recon_data

def main():
    parser = argparse.ArgumentParser(description="Cloud State Builder")
    parser.add_argument("--cloud", required=True, help="Path to cloud_recon.json")
    parser.add_argument("--exploit", help="Path to cloud_exploit.json (optional)")
    parser.add_argument("--out", required=True, help="Output state JSON path")
    args = parser.parse_args()

    # 1. Load Raw Data
    recon_data = load_json_safe(args.cloud)
    exploit_data = load_json_safe(args.exploit) if args.exploit else {}

    if not recon_data:
        # Fallback empty state to prevent crash
        recon_data = {"s3_buckets": [], "iam_identities": {"roles": []}, "lambda_functions": []}
    
    # 2. Enrich Data (The "Beast" Logic)
    enriched_recon = analyze_attack_surface(recon_data)

    # 3. Construct Unified State
    # This structure guarantees compatibility with adapter_cloud.py
    state = {
        "meta": {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "source": "AutoPENT Cloud Recon",
            "profile": "Black Hat Simulation",
            "sandbox": True
        },
        # Direct access for Adapter (High level keys)
        "s3_buckets": enriched_recon.get("s3_buckets", []),
        "iam_identities": enriched_recon.get("iam_identities", {}),
        "lambda_functions": enriched_recon.get("lambda_functions", []),
        
        # Context for Harness/Reporting
        "recon_data": enriched_recon, # Full copy
        "exploits_attempted": exploit_data.get("attempts", []),
        
        # Intelligence Summary
        "intelligence": enriched_recon.get("analysis_summary", {})
    }

    # 4. Save
    try:
        with open(args.out, "w") as f:
            json.dump(state, f, indent=2)
        print(f"[+] Intelligence built. Critical Assets: {state['intelligence'].get('critical_assets', 0)}")
    except Exception as e:
        sys.exit(1)

if __name__ == "__main__":
    main()
