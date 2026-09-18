"""
shaper_none.py: no defense (the paper's "Base" setup).

The adversary sees the traffic exactly as generated. This is the reference
point: maximum attack accuracy, zero overhead. The paper's Base results
showed their TCN classifier reaching >0.99 accuracy on unshaped video
traces -- we expect similarly near-perfect accuracy here.
"""


def shape(bins: list[int], label: str, dataset_stats: dict) -> dict:
    """Shaper 0: passthrough the wire shows the true trace."""
    return {
        "shaped_bins": list(bins),   # exactly what the device sent
        "dummy_bytes": 0,            # no padding
        "delay_ms": 0.0,             # no queueing
        "dropped_bytes": 0,          # nothing flushed
        "epsilon_note": "no privacy (epsilon = infinity)",
    }
