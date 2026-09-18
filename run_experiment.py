"""
run_experiment.py: turns raw traces into shaped traces and computes the DP params along way.

Pipeline:
  1. Load the trace dataset.
  2. Compute dataset_stats: the constant rate for CR, and the sensitivities
     Delta_W (global and per-class) for the DP shapers -- estimated as the
     99th percentile of pairwise L1 window distances, the same recipe the
     paper uses ("Delta_T = 2.5MB, which covers 99th %ile of the distances
     in our dataset" -- their Sec 5.1 and Appendix B).
  3. Run each shaper on each trace; save shaped traces + overhead metrics.

Run:  python run_experiment.py
"""

import json                        # reads the traces file and the shaped results. 
import random                      # pair sampling for Delta_W estimation
import numpy as np                 # window-distance computation
from config import (TRACES_PATH, RESULTS_DIR, SHAPED_PATH, SHAPER_LEVELS,
                    T_BINS, W_INTERVALS, SEED)
from shapers import SHAPERS

_rng = random.Random(SEED + 1)     # praivate random generator - independant from the one that made the traces
# TODO if changing into real data so maybe the line above needs to be changed


def window_repr(bins: list[int]) -> np.ndarray:
    """
    reshape a trace into per-interval totals.
    according to the paper's stream representation for the neighboring definition:
    total bytes per interval of length T (their S_{tw,W} at granularity T).
    """
    byte_arr = np.array(bins, dtype=float)
    num_intervals = len(byte_arr) // T_BINS
    # Sum bytes inside each T-interval is the burst-length sequence
    return byte_arr[:num_intervals * T_BINS].reshape(num_intervals, T_BINS).sum(axis=1)


def max_window_distance(a: list[int], b: list[int]) -> float:
    """
    The paper's Definition 1 distance: the max, over all windows of W
    intervals, of the L1 distance between the two burst sequences.
    """
    repr_a, repr_b = window_repr(a), window_repr(b)
    diff = np.abs(repr_a - repr_b)
    k = W_INTERVALS                            # window length in intervals
    # Slide a window of k intervals and take the max L1 sum
    return max(float(diff[i:i + k].sum()) for i in range(len(diff) - k + 1))


def estimate_delta_w(traces: list[dict], num_pairs: int = 1500) -> float:
    """
    Estimate Delta_W as the 99th percentile of pairwise window distances
    over sampled trace pairs -- the paper's own estimation approach.
    """
    dists = []
    for _ in range(num_pairs):
        trace_a, trace_b = _rng.sample(traces, 2)          # random pair from the set
        dists.append(max_window_distance(trace_a["bins"], trace_b["bins"]))
    return float(np.percentile(dists, 99))


def main():
    # Load the dataset produced by make_traces.py
    dataset = json.loads(TRACES_PATH.read_text(encoding="utf-8"))
    labels = sorted({trace["label"] for trace in dataset})

    # dataset_stats: everything the shapers need, computed once 
    peak_bin = max(max(trace["bins"]) for trace in dataset)            # for CR
    delta_w_global = estimate_delta_w(dataset)                 # for shaper2
    # Per-class Delta_W: same recipe restricted to intra-class pairs (shaper3)
    delta_w_per_class = {
        lab: estimate_delta_w([trace for trace in dataset if trace["label"] == lab],
                              num_pairs=400)
        for lab in labels
    }
    stats = {"peak_bin": peak_bin, "delta_w_global": delta_w_global,
             "delta_w_per_class": delta_w_per_class}
    print(f"[run] peak_bin={peak_bin}B  DeltaW_global={delta_w_global:,.0f}B")
    for lab in labels:                        # show the whole point of shaper3:
        print(f"[run]   DeltaW[{lab}] = {delta_w_per_class[lab]:,.0f}B")

    # ---- shape everything ----
    out = {"stats": stats, "runs": {}}
    for shaper_name in SHAPER_LEVELS:
        shaped_set = []
        for trace in dataset:
            shaped = SHAPERS[shaper_name](trace["bins"], trace["label"], stats)
            # Keep the label + everything the evaluation needs
            shaped_set.append({"label": trace["label"],
                               "orig_bytes": sum(trace["bins"]), **shaped})
        out["runs"][shaper_name] = shaped_set
        # Progress line with the headline overheads for a quick sanity read
        total_dummy = sum(r["dummy_bytes"] for r in shaped_set)
        total_orig = sum(r["orig_bytes"] for r in shaped_set)
        mean_delay = np.mean([r["delay_ms"] for r in shaped_set])
        print(f"[run] {shaper_name}: dummy/orig={total_dummy/total_orig:.2f}x  "
              f"mean_delay={mean_delay:.0f}ms")

    # ---- save ----
    RESULTS_DIR.mkdir(exist_ok=True)
    SHAPED_PATH.write_text(json.dumps(out), encoding="utf-8")
    print(f"[run] saved shaped dataset to {SHAPED_PATH}")


if __name__ == "__main__":
    main()
