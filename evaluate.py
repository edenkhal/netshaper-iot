###############################################################################
# evaluate.py           //TODO: REMOVE(STEP C)                                #
#                                                                             #
# For each shaper:                                                            #
# device ID = attack accuracy of a classifier predicting WHICH DEVICE a       #
#             trace came from (lower = better; chance = 0.20 here). This is   #
#             NOT NetShaper's own goal -- its threat model assumes the        #
#             device is already identifiable. See evaluate_actions.py for     #
#             the metric it does promise: which ACTION a known device did.    #
# costs    = bandwidth overhead (dummy bytes / original bytes),               #
#            mean latency (ms), dropped bytes (TTL flushes)                   #
#                                                                             #
# Outputs: metrics.csv + three figures, including the project's headline      #
# figure -- attack accuracy vs. bandwidth overhead, one point per shaper.     #
# This mirrors the paper's own evaluation axes: classifier accuracy           #
# (see Fig 5), bandwidth overhead and latency (see Figs 8-9).                 #
#                                                                             #
# cmd:  python evaluate.py                                                    #
###############################################################################

import json
import pandas as pd
import matplotlib
matplotlib.use("Agg")             # prevent plot win from poppin up just saves it
import matplotlib.pyplot as plt
from config import SHAPED_PATH, METRICS_PATH, RESULTS_DIR, SHAPER_LEVELS
from attacker import attack_accuracy

# names for tables and figures
LABELS = {
    "shaper_none": "S0: No shaping (Base)",
    "shaper_const_rate": "S1: Constant-rate (CR)",
    "shaper_dp_global": "S2: NetShaper (global \u0394W)",
    "shaper_dp_per_class": "S3: Adaptive per-class \u0394W (ours)",
    "shaper_dp_tiers": "S4: Tiered \u0394W (ours)",
}

# Helper func
def calculate_costs(shaped_set: list[dict]) -> dict:
    # TODO: write func desc and detail the calcs
    total_orig = 0  # sum of pre shaping bytes 
    total_dummy = 0  # sum of dummy bytes
    total_dropped = 0  # sum ofbytes dropped by the w window TTL
    total_delay = 0.0  # sum of per trace mean delays(for the mean)
    num_traces = 0  # trace count

    for trace in shaped_set:
        total_orig += trace["orig_bytes"]
        total_dummy += trace["dummy_bytes"]
        total_dropped += trace["dropped_bytes"]
        total_delay += trace["delay_ms"]
        num_traces += 1

    # sanity check: avoiding calcs on an empty set
    if total_orig == 0 or num_traces == 0:
        return {"bw_overhead_x": 0.0, "mean_delay_ms": 0.0, "dropped_frac": 0.0}
    # else
    return {"bw_overhead_x": total_dummy / total_orig,
            "mean_delay_ms": total_delay / num_traces,
            "dropped_frac": total_dropped / total_orig}

def main():
    # Load everything run_experiment.py produced
    data = json.loads(SHAPED_PATH.read_text(encoding="utf-8"))

    rows = []
    for type_shaper in SHAPER_LEVELS:
        shaped_set = data["runs"][type_shaper]

        # privacy: train+test the adversary on this shaper's output
        acc = attack_accuracy(shaped_set)

        # costs 
        costs = calculate_costs(shaped_set)

        # add shaper's costs 
        rows.append({"shaper": type_shaper, "attack_accuracy": round(acc, 3),
                     "bw_overhead_x": round(costs["bw_overhead_x"], 2),
                     "mean_delay_ms": round(costs["mean_delay_ms"], 1),
                     "dropped_frac": round(costs["dropped_frac"], 4)})

    df = pd.DataFrame(rows)
    print("\n=== Summary (chance accuracy = 0.20) ===") #TODO what does chance accuracy means
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
    ax.set_title("Device identification on shaped traffic "
                 "(beyond NetShaper's own scope)")
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

    # The claim shaper_dp_global must support, printed explicitly:
    s2 = df[df.shaper == "shaper_const_rate"].iloc[0]
    s3 = df[df.shaper == "shaper_dp_global"].iloc[0]
    if s3.bw_overhead_x < s2.bw_overhead_x:
        print(f"\n[evaluate] EXTENSION RESULT: adaptive shaping cut bandwidth "
              f"overhead {s2.bw_overhead_x:.1f}x -> {s3.bw_overhead_x:.1f}x "
              f"(attack accuracy {s2.attack_accuracy:.2f} -> {s3.attack_accuracy:.2f})")


if __name__ == "__main__":
    main()
