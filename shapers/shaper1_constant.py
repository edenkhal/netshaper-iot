"""
shaper1_constant.py -- Shaper 1: constant-rate shaping (the paper's CR baseline).

Send a fixed number of bytes every bin, forever, regardless of real traffic.
The paper: "Constant shaping involves sending fixed-sized packets at a
constant rate, which is secure but incurs non-trivial bandwidth and/or
latency overhead" (Sec 1), and their evaluation configured CR "for the
peak load" (Sec 5). We do the same: the constant rate is the dataset's
peak bin size, so no event ever exceeds it (zero latency, huge dummy cost).

Expected result (mirrors their Figure 9): attack accuracy drops to chance,
bandwidth overhead is orders of magnitude above NetShaper's.
"""


def shape(bins: list[int], label: str, dataset_stats: dict) -> dict:
    """Shaper 1: every bin transmits exactly peak_bin bytes."""
    # The constant rate: the dataset-wide peak bin (set in run_experiment)
    rate = dataset_stats["peak_bin"]
    # Every observed bin is identical -- the shape carries zero information
    shaped = [rate] * len(bins)
    # Dummy bytes = whatever the constant rate exceeds the real traffic by
    dummy = sum(max(0, rate - b) for b in bins)
    return {
        "shaped_bins": shaped,
        "dummy_bytes": dummy,
        "delay_ms": 0.0,             # rate >= any real bin, nothing ever queues
        "dropped_bytes": 0,
        "epsilon_note": "perfect indistinguishability within dataset (epsilon ~ 0)",
    }
