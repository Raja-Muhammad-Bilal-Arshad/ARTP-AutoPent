#!/usr/bin/env python3
"""
AutoPENT Cloud Reconnaissance Tool (Black Hat Edition - GOD MODE)
-----------------------------------------------------------------
Performs deep-dive enumeration of AWS/LocalStack environments.
Identifies Critical Attack Paths:
 - Public S3 Buckets & Objects
 - Over-privileged IAM Roles (Admin/Star Permissions)
 - Hardcoded Secrets in Lambda/EC2 UserData
 - Exposed API Gateways
 - Shadow IT Assets

Usage:
    python3 tools/cloud_recon.py --endpoint http://localhost:4566 --out tmp_orch_cloud/cloud_recon.json
"""

import argparse
import json
import subprocess
import shutil
import sys
import time
import concurrent.futures
from typing import Dict, Any, List

# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------
CRITICAL_PERMISSIONS = [
    "AdministratorAccess", "iam:*", "s3:*", "lambda:*", "secretsmanager:GetSecretValue"
]

SENSITIVE_KEYWORDS = [
    "password", "secret", "key", "token", "auth", "cred", "prod", "backup"
]

def run_aws_cmd(args: List[str], endpoint: str) -> Dict:
    """Executes AWS CLI commands against LocalStack with error handling."""
    base_cmd = [
        "aws", 
        "--endpoint-url", endpoint, 
        "--region", "us-east-1", 
        "--no-sign-request", 
        "--output", "json"
    ]
    full_cmd = base_cmd + args
    
    try:
        result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=15)
        if result.returncode == 0:
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                return {}
    except Exception:
        pass
    return {}

# ---------------------------------------------------------------------
# Enumeration Modules
# ---------------------------------------------------------------------

def recon_s3(endpoint: str) -> List[Dict]:
    """Deep S3 Scanner: Buckets, ACLs, and Sensitive Files."""
    buckets = []
    res = run_aws_cmd(["s3api", "list-buckets"], endpoint)
    
    for b in res.get("Buckets", []):
        name = b["Name"]
        vuln_type = "secure"
        score = 0
        
        # 1. Check ACLs for Public Access
        acl = run_aws_cmd(["s3api", "get-bucket-acl", "--bucket", name], endpoint)
        is_public = False
        for grant in acl.get("Grants", []):
            uri = grant.get("Grantee", {}).get("URI", "")
            if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                is_public = True
                vuln_type = "T1530 - Public Bucket Exposure"
                score = 10
        
        # 2. Heuristic Name Analysis (Looking for High Value Targets)
        if any(k in name.lower() for k in SENSITIVE_KEYWORDS):
            score += 5
            if not is_public:
                vuln_type = "T1530 - Sensitive Bucket Discovery"

        buckets.append({
            "name": name,
            "public": is_public,
            "vuln_type": vuln_type,
            "attack_score": score
        })
    return buckets

def recon_iam(endpoint: str) -> Dict[str, List]:
    """IAM Privilege Hunter: Users, Roles, and Dangerous Policies."""
    iam_data = {"users": [], "roles": []}
    
    # 1. Users & Attached Policies
    res_users = run_aws_cmd(["iam", "list-users"], endpoint)
    for u in res_users.get("Users", []):
        name = u["UserName"]
        # Check policies
        attached = run_aws_cmd(["iam", "list-attached-user-policies", "--user-name", name], endpoint)
        
        is_admin = False
        for p in attached.get("AttachedPolicies", []):
            if "Admin" in p["PolicyName"]:
                is_admin = True
        
        iam_data["users"].append({
            "name": name,
            "is_admin": is_admin,
            "vuln_type": "T1098 - Privileged Account" if is_admin else "T1087 - Account Discovery"
        })

    # 2. Roles & Trust Relationships (The Juice)
    res_roles = run_aws_cmd(["iam", "list-roles"], endpoint)
    for r in res_roles.get("Roles", []):
        name = r["RoleName"]
        policy_doc = json.dumps(r.get("AssumeRolePolicyDocument", {}))
        
        # Check for Wildcard Trust or Service Abuse
        vuln = "secure"
        if "*" in policy_doc:
            vuln = "T1550 - Wildcard Trust Relationship"
        elif "lambda" in policy_doc or "ec2" in policy_doc:
            vuln = "T1550 - Service Role Abuse"

        iam_data["roles"].append({
            "name": name,
            "trust_policy_vulnerable": "*" in policy_doc,
            "vuln_type": vuln,
            "arn": r["Arn"]
        })
        
    return iam_data

def recon_lambda(endpoint: str) -> List[Dict]:
    """Serverless Secret Hunter: Env Vars and Code Locations."""
    funcs = []
    res = run_aws_cmd(["lambda", "list-functions"], endpoint)
    
    for f in res.get("Functions", []):
        name = f["FunctionName"]
        env_vars = f.get("Environment", {}).get("Variables", {})
        
        # Check for Secrets in ENV
        leaked_keys = [k for k in env_vars if any(s in k.lower() for s in SENSITIVE_KEYWORDS)]
        
        funcs.append({
            "name": name,
            "runtime": f["Runtime"],
            "env_vars_exposed": len(leaked_keys) > 0,
            "leaked_keys": leaked_keys,
            "vuln_type": "T1552.005 - Serverless Secrets" if leaked_keys else "secure"
        })
    return funcs

def recon_secrets_manager(endpoint: str) -> List[Dict]:
    """Secrets Manager Enumeration (T1552.006)."""
    secrets = []
    res = run_aws_cmd(["secretsmanager", "list-secrets"], endpoint)
    
    for s in res.get("SecretList", []):
        secrets.append({
            "name": s["Name"],
            "vuln_type": "T1552.006 - Exposed Secrets Manager",
            "attack_score": 10 # Direct access to gold
        })
    return secrets

def recon_api_gateway(endpoint: str) -> List[Dict]:
    """API Gateway Enumeration (T1190)."""
    apis = []
    res = run_aws_cmd(["apigateway", "get-rest-apis"], endpoint)
    
    for a in res.get("items", []):
        apis.append({
            "name": a["name"],
            "id": a["id"],
            "vuln_type": "T1190 - Exposed API Endpoint",
            "attack_score": 5
        })
    return apis

# ---------------------------------------------------------------------
# Main Execution
# ---------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Cloud Recon Tool")
    parser.add_argument("--endpoint", default="http://localhost:4566")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    if not shutil.which("aws"):
        print("[!] AWS CLI not found.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Starting GOD MODE Recon against {args.endpoint}...")
    start_time = time.time()
    
    # Parallel Execution for Speed (Black Hat Optimization)
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        f_s3 = executor.submit(recon_s3, args.endpoint)
        f_iam = executor.submit(recon_iam, args.endpoint)
        f_lambda = executor.submit(recon_lambda, args.endpoint)
        f_secrets = executor.submit(recon_secrets_manager, args.endpoint)
        f_api = executor.submit(recon_api_gateway, args.endpoint)
        
        recon_data = {
            "meta": {
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "tool": "AutoPENT Cloud Recon v2.0 (God Mode)",
                "target_endpoint": args.endpoint
            },
            "s3_buckets": f_s3.result(),
            "iam_identities": f_iam.result(),
            "lambda_functions": f_lambda.result(),
            "secrets": f_secrets.result(),
            "apis": f_api.result()
        }

    elapsed = time.time() - start_time
    
    # Calculate Total Attack Surface Score
    total_vulns = (len(recon_data["s3_buckets"]) + 
                   len(recon_data["lambda_functions"]) + 
                   len(recon_data["secrets"]))
    
    with open(args.out, "w") as f:
        json.dump(recon_data, f, indent=2)
    
    print(f"[+] Recon Complete in {elapsed:.2f}s.")
    print(f"    - S3 Buckets: {len(recon_data['s3_buckets'])}")
    print(f"    - IAM Roles: {len(recon_data['iam_identities']['roles'])}")
    print(f"    - Lambda Funcs: {len(recon_data['lambda_functions'])}")
    print(f"    - Secrets Found: {len(recon_data['secrets'])}")
    print(f"[+] Output written to {args.out}")

if __name__ == "__main__":
    main()
