"""
shaper4_dp_tiers.py: OUR EXTENSION, part 2 - DP shaping with privacy TIERS.
referred also as shaper_dp_tiers

The trade-off it targets:
  - shaper2 (one global Delta_W) gives every device the same noise scale, so
    the scale says nothing about the device, but it pads every device at
    camera scale - a smart plug gets the same noise as the camera.
  - shaper3 (one Delta_W per device) is far cheaper for quiet devices, but the
    noise scale is public and differs per device, so the noise level itself
    identifies the device - a leak beyond anything NetShaper promised to hide,
    since its threat model treats device identity as already known.

Tiers sit in between: devices are grouped into a few tiers, and every device
in a tier shares ONE Delta_W, computed from the pooled traffic of the tier
(99th percentile of intra-tier pairwise window distances - the same recipe as
shaper2/shaper3). Devices in the same tier share a noise scale, so the noise
no longer tells them apart - the adversary learns the tier, not the device -
while quiet tiers still pay far less than the global setting.

Privacy statement: within a tier, the same (epsilon_T, delta_T)-DP per query
as shaper2, with sigma computed from the tier's Delta_W. The tier itself is a
public parameter (as the class is for shaper3), so a tier holding a single
device gives its own noise scale away. That costs nothing NetShaper itself
protects - device identity is public under the paper's threat model either
way - but it defeats the point of grouping, so every tier wants >= 2 members.
"""

from .shaper2_netshaper import dp_shape_trace   # same core mechanism

# Device -> tier map. Edit this to regroup devices; run_experiment.py computes
# one Delta_W for every tier that appears in the dataset.
DEVICE_TIERS = {
    # real data: device names from pcap_to_traces.py
    "amcrest-cam-wired": "heavy",
    "ring-doorbell":     "medium",
    "xiaomi-cleaner":    "medium",
    "echodot":           "medium",
    "tplink-plug":       "light",
    # synthetic data: event names from make_traces.py
    "camera_motion":     "heavy",
    "doorbell_ring":     "medium",
    "vacuum_upload":     "medium",
    "assistant_query":   "medium",
    "plug_toggle":       "light",
}


def tier_of(label: str) -> str:
    """
    The tier of a device label. A label missing from DEVICE_TIERS becomes a
    tier of its own, which falls back to shaper3's per-class behavior.
    """
    return DEVICE_TIERS.get(label, label)


def shape(bins: list[int], label: str, dataset_stats: dict) -> dict:
    """Shaper 4: NetShaper mechanism with the TIER's shared Delta_W."""
    # Look up the sensitivity of this device's tier (computed in run_experiment)
    delta_w = dataset_stats["delta_w_per_tier"][tier_of(label)]
    # Identical DP machinery - only the sensitivity (and thus sigma) changes
    return dp_shape_trace(bins, delta_w=delta_w)
