import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

# Load Data
df = pd.read_csv("results/artp/cloud/aggregate_metrics_cloud.csv")

# Create Plot
plt.figure(figsize=(10, 6))
sns.set(style="whitegrid")

# Plot: Detection Rate vs Time to Detect, colored by Success
scatter = sns.scatterplot(
    data=df,
    x="cloudtrail_detection_rate",
    y="mean_time_to_detect",
    hue="exfiltrated",
    palette={0: "red", 1: "green"},
    style="exfiltrated",
    s=100,
    alpha=0.8
)

plt.title("Cloud Kill Chain: Stealth vs. Speed (N=30)", fontsize=14, fontweight='bold')
plt.xlabel("CloudTrail Detection Noise (0.0 - 1.0)", fontsize=12)
plt.ylabel("Time to Compromise (Simulated Secs)", fontsize=12)
plt.axvline(x=0.5, color='grey', linestyle='--', label='Detection Threshold')
plt.legend(title="Exfiltration Success")

# Save
os.makedirs("results/plots", exist_ok=True)
plt.tight_layout()
plt.savefig("results/plots/cloud_success_matrix.png", dpi=300)
print("[+] Plot saved to results/plots/cloud_success_matrix.png")
