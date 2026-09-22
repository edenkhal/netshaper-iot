###############################################################################
# evaluate_actions.py                                              (STEP D)   #
#                                                                             #
# The SECOND privacy metric: the device is PUBLIC, the secret is WHICH ACTION #
# it performed (camera: photo/recording/watch; plug: on/off; ...).            #
#                                                                             #
# Why this table exists: shaper_dp_per_class and shaper_dp_tiers leak the     #
# device class as a side effect -- their Delta_W is public, so the noise      #
# scale reveals the class (see evaluate.py, and DP_ANALYSIS.md Sec 6.1). That #
# costs nothing NetShaper promised: its threat model treats device identity   #
# as already known to the adversary. What it DOES promise is                  #
# indistinguishability of events WITHIN a device -- hide the application's    #
# secret, not its identity. This script measures that promise, one device at  #
# a time -- and at epsilon_T = 1 every shaper already sits at chance here,    #
# including the cheapest one.                                                 #
#                                                                             #
# Real data only: it needs source_pcap, which pcap_to_traces.py records and   #
# run_experiment.py carries through. On synthetic traces it exits quietly.    #
#                                                                             #
# Outputs: action_metrics.csv + results/action_accuracy.png                   #
#                                                                             #
# cmd:  python evaluate_actions.py     (after run_experiment.py)              #
###############################################################################

import json
import sys
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")             # save figures, never pop a window
import matplotlib.pyplot as plt
from config import (SHAPED_PATH, ACTION_METRICS_PATH, RESULTS_DIR,
                    SHAPER_LEVELS, ACTION_MIN_CAPTURES, N_EVAL_SPLITS)
from attacker import action_attack_accuracy
from evaluate import LABELS         # same short names as the device table


def main():
    # Everything comes from the shaped dataset -- no need to re-run Step B
    data = json.loads(SHAPED_PATH.read_text(encoding="utf-8"))

    # --- synthetic guard: no source_pcap means no action labels ---
    first_run = data["runs"][SHAPER_LEVELS[0]]
    if not all(trace.get("source_pcap") for trace in first_run):
        print("[actions] synthetic traces carry no action labels -- real data only.")
        print("[actions] build traces with pcap_to_traces.py to use this step.")
        sys.exit(0)

    devices = sorted({trace["label"] for trace in first_run})

    rows = []
    for shaper_name in SHAPER_LEVELS:
        shaped_set = data["runs"][shaper_name]
        for device in devices:
            # One classifier per (shaper, device): the device is public here
            result = action_attack_accuracy(shaped_set, device)
            if result is None:
                # Too few actions survive the min-captures filter (the vacuum)
                continue
            result["shaper"] = shaper_name
            rows.append(result)

    if not rows:
        sys.exit(f"ERROR: no device has >= 2 actions with >= {ACTION_MIN_CAPTURES} captures.")

    df = pd.DataFrame(rows)
    usable = sorted(df.device.unique())
    skipped = [d for d in devices if d not in usable]

    # --- print one block per shaper, plus the macro average over devices ---
    print(f"\n=== Action identification within a known device ===")
    print(f"    (mean +- sd over {N_EVAL_SPLITS} capture splits; "
          f"actions with < {ACTION_MIN_CAPTURES} captures dropped)")
    if skipped:
        print(f"    skipped, too few captures per action: {', '.join(skipped)}")
    for shaper_name in SHAPER_LEVELS:
        sub = df[df.shaper == shaper_name]
        print(f"\n{LABELS[shaper_name]}")
        print(f"  {'device':20s} {'acts':>4s} {'chance':>7s} {'balanced acc':>16s} "
              f"{'capture acc':>16s} {'advantage':>10s}")
        for _, r in sub.iterrows():
            print(f"  {r.device:20s} {r.n_actions:4d} {r.chance:7.2f} "
                  f"{r.balanced:10.3f}+-{r.balanced_sd:.3f} "
                  f"{r.capture_acc:10.3f}+-{r.capture_acc_sd:.3f} "
                  f"{r.advantage:10.2f}")
        print(f"  {'MACRO AVERAGE':20s} {'':4s} {'':7s} {sub.balanced.mean():10.3f}"
              f"{'':7s}{sub.capture_acc.mean():10.3f}{'':7s}{sub.advantage.mean():10.2f}")

    # --- save the table ---
    RESULTS_DIR.mkdir(exist_ok=True)
    out = df[["shaper", "device", "n_actions", "n_traces", "n_captures", "chance",
              "acc", "acc_sd", "balanced", "balanced_sd",
              "capture_acc", "capture_acc_sd", "advantage"]].round(4)
    out.to_csv(ACTION_METRICS_PATH, index=False)
    print(f"\n[actions] saved {ACTION_METRICS_PATH}")

    # --- figure: grouped bars, one group per device, one bar per shaper ---
    fig, ax = plt.subplots(figsize=(10, 4.5))
    width = 0.8 / len(SHAPER_LEVELS)
    xs = np.arange(len(usable))
    for i, shaper_name in enumerate(SHAPER_LEVELS):
        sub = df[df.shaper == shaper_name].set_index("device").reindex(usable)
        ax.bar(xs + i * width, sub.balanced.values, width,
               yerr=sub.balanced_sd.values, capsize=2, label=LABELS[shaper_name])
    # Chance differs per device (1/n_actions), so draw one dashed line per group
    for x, device in zip(xs, usable):
        chance = df[df.device == device].chance.iloc[0]
        ax.plot([x - width / 2, x + len(SHAPER_LEVELS) * width - width / 2],
                [chance, chance], ls="--", c="gray", lw=1)
    ax.set_xticks(xs + 0.4 - width / 2)
    ax.set_xticklabels([f"{d}\n({df[df.device == d].n_actions.iloc[0]} actions)"
                        for d in usable])
    ax.set_ylabel("Balanced accuracy (action)")
    ax.set_ylim(0, 1.05)
    ax.set_title("Privacy: action identification within a known device "
                 "(dashed = chance for that device)")
    ax.legend(fontsize=7, ncol=2)
    plt.tight_layout()
    fig.savefig(RESULTS_DIR / "action_accuracy.png", dpi=150)
    print(f"[actions] figure saved to {RESULTS_DIR}/action_accuracy.png")

    # --- the headline this table exists for: does the cheapest DP shaper still
    # deliver the property NetShaper actually promises? ---
    base = df[df.shaper == "shaper_none"]
    cheap = df[df.shaper == "shaper_dp_per_class"]
    if not base.empty and not cheap.empty:
        print(f"\n[actions] HEADLINE (the property NetShaper does promise):")
        print(f"    no shaping     macro balanced acc={base.balanced.mean():.3f}  "
              f"advantage over chance={base.advantage.mean():.2f}")
        print(f"    per-class DP   macro balanced acc={cheap.balanced.mean():.3f}  "
              f"advantage over chance={cheap.advantage.mean():.2f}")
        verdict = ("the cheapest DP shaper hides the action" if cheap.advantage.mean() < 0.05
                   else "the action is STILL visible after shaping -- investigate")
        print(f"    -> {verdict}")


if __name__ == "__main__":
    main()
