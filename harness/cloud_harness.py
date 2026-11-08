#!/usr/bin/env python3
"""
AutoPENT Cloud Harness (Black Hat Edition)
------------------------------------------
Specialized execution engine for Cloud Exploitation scenarios.
Calculates Cloud-Specific metrics (CloudTrail Detection, Exfiltration Volume, MTTC).

Usage:
    python3 harness/cloud_harness.py --plan <plan> --exploit <exploit_json> --metrics <out> --run-info <info>
"""

import json
import argparse
import random
import sys
import os
from datetime import datetime

# Black Hat Configuration
# -----------------------
# Detection Thresholds: If noise exceeds this, CloudTrail alerts SOC.
CLOUDTRAIL_SENSITIVITY_THRESHOLD = 8.0 

def load_json(path):
    if not os.path.exists(path):
        return {}
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except:
        return {}

def calculate_cloud_metrics(plan_data, exploit_data):
    """
    Core Logic: Determines if the mission was a success based on
    Simulated Exploit results + Plan metadata.
    """
    # 1. Analyze Exploit Results (From cloud_exploit_simulator.py)
    attempts = exploit_data.get("attempts", [])
    
    successful_steps = [a for a in attempts if a.get("result") == "success"]
    failed_steps = [a for a in attempts if a.get("result") == "failure"]
    
    # 2. Calculate "Noise" (Stealth)
    # Each attempt has a 'stealth_cost'. Failures are 2x louder.
    total_noise = 0.0
    for a in attempts:
        cost = a.get("meta", {}).get("stealth_cost", 0.1)
        if a.get("result") == "failure":
            total_noise += (cost * 2.0) # Failures are noisy!
        else:
            total_noise += cost

    # Normalize Detection Rate (0.0 - 1.0)
    # If noise > threshold, detection is certain (1.0)
    cloudtrail_detection_rate = min(1.0, total_noise / CLOUDTRAIL_SENSITIVITY_THRESHOLD)

    # 3. Determine Exfiltration Success
    # Did we successfully execute a T1530 (S3 Dump) or T1567 (Exfil)?
    exfiltrated_count = 0
    exfil_techniques = ["T1530", "T1567", "T1552"] # S3, Web Exfil, Secrets
    
    for s in successful_steps:
        tech = s.get("meta", {}).get("technique", "")
        # Check if technique ID starts with known exfil codes
        if any(t in tech for t in exfil_techniques):
            exfiltrated_count += 1
            
    # Binary Success Flag (Did we get ANY loot?)
    is_exfiltrated = 1 if exfiltrated_count > 0 else 0

    # 4. Mean Time To Detect (MTTC / MTTD Simulation)
    # If undetected, time is MAX. If detected, time is proportional to when noise spiked.
    if cloudtrail_detection_rate < 0.1:
        mean_time_to_detect = 0.0 # Undetected
    else:
        # Simulate seconds until SOC triage
        # Higher noise = Faster detection
        mean_time_to_detect = round(30.0 * (1.0 - cloudtrail_detection_rate), 2)

    return {
        "cloudtrail_detection_rate": round(cloudtrail_detection_rate, 3),
        "mean_time_to_detect": mean_time_to_detect,
        "exfiltrated": is_exfiltrated,
        "critical_assets_compromised": exfiltrated_count,
        "technique_diversity": len(set(a.get("meta",{}).get("technique") for a in attempts)),
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

def main():
    parser = argparse.ArgumentParser(description="AutoPENT Cloud Harness")
    parser.add_argument("--plan", required=True, help="Path to cloud plan JSON")
    parser.add_argument("--exploit", required=True, help="Path to cloud exploit JSON")
    parser.add_argument("--metrics", required=True, help="Path to output metrics JSON")
    parser.add_argument("--run-info", required=True, help="Path to run info JSON")
    
    args = parser.parse_args()

    # Load Data
    plan = load_json(args.plan)
    exploit = load_json(args.exploit)

    # Calculate "Beast" Metrics
    metrics = calculate_cloud_metrics(plan, exploit)

    # Append run info if available
    run_info = load_json(args.run_info)
    metrics.update(run_info)

    # Save
    with open(args.metrics, "w") as f:
        json.dump(metrics, f, indent=4)

    print(f"[+] Cloud Harness Complete.")
    print(f"    Detection Rate: {metrics['cloudtrail_detection_rate']}")
    print(f"    Exfiltrated:    {'YES' if metrics['exfiltrated'] else 'NO'}")

if __name__ == "__main__":
    main()
