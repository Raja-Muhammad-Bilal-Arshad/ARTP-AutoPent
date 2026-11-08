#!/usr/bin/env python3
import os
import argparse
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
from pathlib import Path

def detect_adusers_csv(reports_dir):
    """Find ADUsers.csv automatically inside reports directory"""
    for root, _, files in os.walk(reports_dir):
        for f in files:
            if f.lower() == "adusers.csv":
                return os.path.join(root, f)
    return None

def compute_risk_score(row):
    """Heuristic for risk scoring based on name, description, and status"""
    risk = 0
    name = str(row.get("name", "")).lower()
    desc = str(row.get("description", "")).lower()
    status = str(row.get("enabled", "")).lower() # Changed status to enabled check usually found in AD

    # Heuristics
    if "admin" in name: risk += 4
    if "svc" in name or "service" in name: risk += 3
    if "password" in desc: risk += 5 # High risk finding
    if "krbtgt" in name: risk += 10
    
    # Check if account is enabled (Active AD accounts are riskier than disabled ones)
    if status == "true": 
        risk += 2
        
    return min(risk, 10)

def main():
    parser = argparse.ArgumentParser(description="Research Grade AD Risk Graph")
    parser.add_argument("--reports-dir", required=True, help="Path to reports directory")
    parser.add_argument("--out", required=True, help="Output graph image path")
    parser.add_argument("--summary", required=True, help="Output CSV summary path")
    parser.add_argument("--format", default="png", choices=["png", "pdf", "svg"], help="Output format")
    args = parser.parse_args()

    # --- Load Data ---
    csv_path = detect_adusers_csv(args.reports_dir)
    if not csv_path:
        print(f"[!] ADUsers.csv not found in {args.reports_dir}")
        return

    try:
        df = pd.read_csv(csv_path)
    except Exception as e:
        print(f"[!] Error reading CSV: {e}")
        return
        
    if df.empty:
        print("[!] ADUsers.csv is empty.")
        return

    # Normalize column names
    df.columns = [c.strip().lower() for c in df.columns]
    
    # Calculate Risk
    df["risk"] = df.apply(compute_risk_score, axis=1)

    # --- Build Graph with Topology ---
    G = nx.Graph() # Undirected looks cleaner for clustering

    # Create Structural Hubs (Invisible centers to pull nodes together)
    # This prevents random scattering and groups users by risk visually
    risk_levels = {
        "High Risk": 8,
        "Medium Risk": 5,
        "Low Risk": 2
    }
    
    for label, level in risk_levels.items():
        G.add_node(label, risk=level, type="hub")

    # Add Users and connect to their Risk Hub
    for _, row in df.iterrows():
        user = str(row.get("name", "Unknown"))
        risk = row.get("risk", 0)
        
        G.add_node(user, risk=risk, type="user")
        
        # Connect to the appropriate structural hub
        if risk >= 7:
            G.add_edge(user, "High Risk", weight=2)
        elif risk >= 4:
            G.add_edge(user, "Medium Risk", weight=1)
        else:
            G.add_edge(user, "Low Risk", weight=0.5)

    print(f"[*] Graph built: {len(G.nodes)} nodes, {len(G.edges)} edges.")

    # --- Visualization Setup ---
    plt.figure(figsize=(14, 10), facecolor="white") # Paper standard: White background
    
    # Layout: Spring layout determines position based on edge weights
    # k controls spacing (smaller = tighter), iterations allows physics to settle
    pos = nx.spring_layout(G, k=0.15, iterations=100, seed=42)

    # Separate Hubs from Users for drawing
    user_nodes = [n for n, d in G.nodes(data=True) if d.get("type") == "user"]
    hub_nodes = [n for n, d in G.nodes(data=True) if d.get("type") == "hub"]

    # --- Color Mapping (The Heatmap Aspect) ---
    risks = [G.nodes[n]["risk"] for n in user_nodes]
    
    # Use 'Reds' or 'coolwarm' for a good heatmap effect
    cmap = plt.get_cmap("Reds") 
    norm = mcolors.Normalize(vmin=0, vmax=10)

    # Draw User Nodes
    nx.draw_networkx_nodes(
        G, pos, 
        nodelist=user_nodes,
        node_color=[cmap(norm(r)) for r in risks],
        node_size=[100 + (r * 50) for r in risks], # Higher risk = Bigger node
        alpha=0.85,
        edgecolors="grey", # Thin border makes nodes pop
        linewidths=0.5
    )

    # Draw Hub Nodes (make them invisible or subtle)
    nx.draw_networkx_nodes(G, pos, nodelist=hub_nodes, node_size=0, alpha=0)

    # Draw Edges (Make them very faint, just to show structure)
    nx.draw_networkx_edges(G, pos, alpha=0.1, edge_color="silver")

    # --- Intelligent Labeling ---
    # Only label High Risk nodes to prevent clutter in the paper
    labels = {}
    for n in user_nodes:
        if G.nodes[n]["risk"] >= 6: # Threshold for labeling
            labels[n] = n
            
    # Add Hub Labels
    for n in hub_nodes:
        labels[n] = n.upper()

    nx.draw_networkx_labels(
        G, pos, labels, 
        font_size=8, 
        font_family="sans-serif",
        font_weight="bold",
        verticalalignment="bottom" # Push label slightly above node
    )

    # --- Professional Aesthetics ---
    plt.title("Active Directory Identity Risk Distribution", fontsize=16, fontweight="bold", pad=20)
    
    # Add Colorbar (Legend)
    sm = plt.cm.ScalarMappable(cmap=cmap, norm=norm)
    sm.set_array([])
    cbar = plt.colorbar(sm, ax=plt.gca(), fraction=0.03, pad=0.03)
    cbar.set_label("Risk Severity Score (0-10)", fontsize=10, labelpad=10)
    cbar.outline.set_visible(False) # Clean look

    plt.axis("off") # Remove X/Y axis ticks
    plt.tight_layout()

    # --- Save ---
    Path(os.path.dirname(args.out)).mkdir(parents=True, exist_ok=True)
    plt.savefig(args.out, format=args.format, dpi=300, bbox_inches="tight")
    print(f"[+] Research graph saved to: {args.out}")

    # Save summary
    if "name" in df.columns:
        df[["name", "risk"]].to_csv(args.summary, index=False)
        print(f"[+] Summary saved to: {args.summary}")

if __name__ == "__main__":
    main()
