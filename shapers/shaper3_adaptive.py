"""
shaper3_adaptive.py -- Shaper 3: OUR EXTENSION -- per-device-class DP shaping.

The gap in the paper: NetShaper picks one (Delta_W, T) per application
domain (W=5s / Delta=2.5MB for video, W=1s / Delta=60KB for web -- their
Sec 5). A smart home is not one domain: a camera moves megabytes while a
smart plug moves hundreds of bytes. A single global Delta_W sized for the
camera forces camera-scale Gaussian noise onto the plug -- pure waste.

Our extension: give each DEVICE CLASS its own Delta_W, computed from that
class's traffic (99th percentile of intra-class pairwise window distances,
the same estimation recipe the paper uses in its Appendix B). Quiet devices
get small sensitivity -> small sigma -> far less dummy traffic.

The honest privacy caveat (stated up front, and in the report):
shaping parameters are public in NetShaper's threat model ("[the adversary]
may also have knowledge about NetShaper, including its shaping strategy and
privacy configurations" -- Sec 2.3). Per-class parameters therefore reveal
the DEVICE CLASS by construction. The DP guarantee protects WHAT the device
does (which event, when) WITHIN its class. This is a deliberate,
quantifiable trade -- the same kind the paper itself makes when it declares
"the number of flows is public" (Sec 5). Our evaluation measures exactly
this: within-class event indistinguishability at a fraction of the cost.
"""

from .shaper2_netshaper import dp_shape_trace   # same core mechanism


def shape(bins: list[int], label: str, dataset_stats: dict) -> dict:
    """Shaper 3: NetShaper mechanism with the CLASS-SPECIFIC Delta_W."""
    # Look up this device class's own sensitivity (computed in run_experiment)
    delta_w = dataset_stats["delta_w_per_class"][label]
    # Identical DP machinery -- only the sensitivity (and thus sigma) changes
    return dp_shape_trace(bins, delta_w=delta_w)
