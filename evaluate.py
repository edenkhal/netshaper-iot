"""
evaluate.py -- Step C: the evaluation. Fully automatic (no manual scoring).

For each shaper:
  privacy  = attack accuracy of a classifier trained on that shaper's output
             (lower = better; chance = 1/#classes = 0.20 here)
  costs    = bandwidth overhead (dummy bytes / original bytes),
             mean latency (ms), dropped bytes (TTL flushes)

Outputs: metrics.csv + three figures, including the project's headline
figure -- attack accuracy vs. bandwidth overhead, one point per shaper.
This mirrors the paper's own evaluation axes: classifier accuracy
(their Fig 5), bandwidth overhead and latency (their Figs 8-9).

Run:  python evaluate.py
"""

import json
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")              # headless backend
import matplotlib.pyplot as plt
from config import SHAPED_PATH, METRICS_PATH, RESULTS_DIR, SHAPER_LEVELS
from attacker import attack_accuracy

# Readable names for tables and figures
LABELS = {
    "shaper0": "S0: No shaping (Base)",
    "shaper1": "S1: Constant-rate (CR)",
    "shaper2": "S2: NetShaper (global \u0394W)",
    "shaper3": "S3: Adaptive per-class \u0394W (ours)",
}


def main():
    # Load everything run_experiment.py produced
    data = json.loads(SHAPED_PATH.read_text(encoding="utf-8"))

    rows = []
    for name in SHAPER_LEVELS:
        shaped_set = data["runs"][name]
        # --- privacy: train+test the adversary on this shaper's output ---
        acc = attack_accuracy(shaped_set)
        # --- costs ---
        total_orig = sum(r["orig_bytes"] for r in shaped_set)
        bw_overhead = sum(r["dummy_bytes"] for r in shaped_set) / total_orig
        mean_delay = float(np.mean([r["delay_ms"] for r in shaped_set]))
        drop_frac = sum(r["dropped_bytes"] for r in shaped_set) / total_orig
        rows.append({"shaper": name, "attack_accuracy": round(acc, 3),
                     "bw_overhead_x": round(bw_overhead, 2),
                     "mean_delay_ms": round(mean_delay, 1),
                     "dropped_frac": round(drop_frac, 4)})

    df = pd.DataFrame(rows)
    print("\n=== Summary (chance accuracy = 0.20) ===")
    print(df.to_string(index=False))
    RESULTS_DIR.mkdir(exist_ok=True)
    df.to_csv(METRICS_PATH, index=False)
    print(f"\n[evaluate] saved {METRICS_PATH}")

    names = [LABELS[n] for n in SHAPER_LEVELS]

    # --- Figure 1: attack accuracy per shaper (privacy) ---
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.bar(names, df["attack_accuracy"], color="#c0392b")
    ax.axhline(0.20, ls="--", c="gray", label="chance (5 classes)")
    ax.set_ylabel("Attack accuracy"); ax.set_ylim(0, 1.05)
    ax.set_title("Privacy: event-classification accuracy on shaped traffic")
    ax.legend(); plt.xticks(rotation=12); plt.tight_layout()
    fig.savefig(RESULTS_DIR / "attack_accuracy.png", dpi=150)

    # --- Figure 2: bandwidth overhead per shaper (log scale: CR dwarfs DP) ---
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.bar(names, df["bw_overhead_x"].clip(lower=0.01), color="#2980b9")
    ax.set_yscale("log")
    ax.set_ylabel("Dummy bytes / original bytes (log)")
    ax.set_title("Cost: bandwidth overhead")
    plt.xticks(rotation=12); plt.tight_layout()
    fig.savefig(RESULTS_DIR / "bandwidth_overhead.png", dpi=150)

    # --- Figure 3 (headline): privacy vs. cost, one point per shaper ---
    fig, ax = plt.subplots(figsize=(6.5, 5))
    xs = df["bw_overhead_x"].clip(lower=0.01)
    ys = df["attack_accuracy"]
    ax.scatter(xs, ys, s=80, color="#2c3e50")
    for name, x, y in zip(SHAPER_LEVELS, xs, ys):
        ax.annotate(name, (x, y), textcoords="offset points", xytext=(8, 4))
    ax.set_xscale("log")
    ax.axhline(0.20, ls="--", c="gray")
    ax.set_xlabel("Bandwidth overhead (x original, log)")
    ax.set_ylabel("Attack accuracy")
    ax.set_title("Privacy vs. cost: the headline figure")
    plt.tight_layout()
    fig.savefig(RESULTS_DIR / "privacy_vs_cost.png", dpi=150)

    print(f"[evaluate] figures saved to {RESULTS_DIR}/")

    # The claim shaper3 must support, printed explicitly:
    s2 = df[df.shaper == "shaper2"].iloc[0]
    s3 = df[df.shaper == "shaper3"].iloc[0]
    if s3.bw_overhead_x < s2.bw_overhead_x:
        print(f"\n[evaluate] EXTENSION RESULT: adaptive shaping cut bandwidth "
              f"overhead {s2.bw_overhead_x:.1f}x -> {s3.bw_overhead_x:.1f}x "
              f"(attack accuracy {s2.attack_accuracy:.2f} -> {s3.attack_accuracy:.2f})")


if __name__ == "__main__":
    main()
