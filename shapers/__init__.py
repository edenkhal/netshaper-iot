"""
shapers -- the package of four traffic-shaping strategies.

Every shaper is a function with the exact same signature:
    shape(bins: list[int], label: str, dataset_stats: dict) -> dict
It receives one trace (bytes per bin) and returns:
    {
      "shaped_bins":  list[int],  # what the adversary observes on the wire
      "dummy_bytes":  int,        # padding overhead added
      "delay_ms":     float,      # mean queueing delay of payload bytes
      "dropped_bytes": int,       # bytes flushed by the W-window TTL
      "epsilon_note": str,        # the privacy accounting for this shaper
    }

dataset_stats carries pre-computed values that a deployer would set from
domain knowledge. The paper: "one would determine Delta_W based on the
typical difference of traffic between application streams over windows of
length W" (Sec 3.1); computing it as the 99th percentile of pairwise
distances mirrors the paper's own choice (their Appendix B).

Grounding map (Sabzi et al., USENIX Security 2024):
  shaper0 = no defense (their Base)
  shaper1 = constant-rate shaping (their CR baseline, "most secure" but costly)
  shaper2 = NetShaper's DP shaping, faithfully simulated (their Sec 3)
  shaper3 = OUR EXTENSION: per-device-class DP parameters (not in the paper)

Standalone check:  python -m shapers --smoke-test
"""

from .shaper0_none import shape as shaper0        # no shaping (Base)
from .shaper1_constant import shape as shaper1    # constant-rate (CR)
from .shaper2_netshaper import shape as shaper2   # NetShaper DP shaping
from .shaper3_adaptive import shape as shaper3    # our per-class adaptive DP

# Central registry: run_experiment.py iterates over this
SHAPERS = {
    "shaper0": shaper0,
    "shaper1": shaper1,
    "shaper2": shaper2,
    "shaper3": shaper3,
}
