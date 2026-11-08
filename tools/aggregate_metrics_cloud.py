#!/usr/bin/env python3
"""
aggregate_metrics_cloud.py (SAFE VERSION)
-----------------------------------------
✅ Aggregates ONLY the most recent Cloud experiment runs
✅ Prevents old polluted results from corrupting BlackHat metrics
✅ Uses real timestamps from metrics.json
✅ Default window = last 30 runs (configurable)

Outputs:
  - Clean CSV with latest valid data only
  - Console summary of KPIs
"""

import os
import sys
import json
import csv
import glob
import statistics
import argparse
from datetime import datetime

def safe_float(val):
    try:
        return float(val)
    except (ValueError, TypeError):
        return 0.0

def parse_timestamp(ts):
    try:
        return datetime.fromisoformat(ts.replace("Z", ""))
    except Exception:
        return None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--results-dir", required=True, help="Directory containing run_* subfolders")
    parser.add_argument("--out", required=True, help="Output CSV path")
    parser.add_argument("--limit", type=int, default=30, help="How many latest runs to aggregate (default: 30)")
    args = parser.parse_args()

    if not os.path.exists(args.results_dir):
        print(f"[❌] Results directory not found: {args.results_dir}")
        sys.exit(1)

    print(f"[*] Scanning Cloud runs in: {args.results_dir}")

    run_dirs = sorted(glob.glob(os.path.join(args.results_dir, "run_*")))
    valid_runs = []
    
    # 1. Collect Valid Runs
    for run_dir in run_dirs:
        metrics_file = os.path.join(run_dir, "metrics.json")
        if not os.path.exists(metrics_file):
            continue

        try:
            with open(metrics_file, "r") as f:
                metrics = json.load(f)
            
            # Extract Sort Key (Timestamp)
            ts_str = metrics.get("timestamp", "")
            dt = parse_timestamp(ts_str) or datetime.min
            
            # Extract Metrics
            row = {
                "run_id": os.path.basename(run_dir),
                "timestamp_dt": dt, # For sorting
                "exfiltrated": int(metrics.get("exfiltrated", 0)),
                "technique_diversity": int(metrics.get("technique_diversity", 0)),
                "cloudtrail_detection_rate": safe_float(metrics.get("cloudtrail_detection_rate", 0)),
                "mean_time_to_detect": safe_float(metrics.get("mean_time_to_detect", 0))
            }
            valid_runs.append(row)
        except Exception as e:
            continue

    if not valid_runs:
        print("[!] No valid cloud metrics found.")
        sys.exit(0)

    # 2. Sort by Time (Newest First) and Slice
    valid_runs.sort(key=lambda x: x["timestamp_dt"], reverse=True)
    
    # Take only the top N (default 30)
    final_rows = valid_runs[:args.limit]
    
    # Remove helper key before writing
    for r in final_rows:
        del r["timestamp_dt"]

    # 3. Write CSV
    headers = [
        "run_id",
        "exfiltrated",
        "technique_diversity",
        "cloudtrail_detection_rate",
        "mean_time_to_detect"
    ]
    
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(final_rows)

    # 4. Statistical Summary
    print(f"\n[📊] Cloud Experiment Summary (Top {len(final_rows)} Recent Runs)")
    print("-" * 60)
    
    for key in ["cloudtrail_detection_rate", "mean_time_to_detect", "technique_diversity"]:
        vals = [r[key] for r in final_rows]
        mean = statistics.mean(vals)
        stdev = statistics.stdev(vals) if len(vals) > 1 else 0.0
        print(f"{key:<30} : Mean={mean:.4f}  StdDev={stdev:.4f}")

    total_exfil = sum(r["exfiltrated"] for r in final_rows)
    success_rate = (total_exfil / len(final_rows)) * 100
    print(f"{'exfiltration_success_rate':<30} : {success_rate:.1f}% ({total_exfil}/{len(final_rows)})")

    print("-" * 60)
    print(f"[✅] Clean Aggregated CSV saved to: {args.out}")

if __name__ == "__main__":
    main()
