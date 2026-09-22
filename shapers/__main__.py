"""
__main__.py -- entry point of:  python -m shapers --smoke-test

Runs every shaper on one tiny trace and prints the outputs, so you can
verify in seconds that nothing crashes and shaping visibly changes the trace.
"""

import sys
from . import SHAPERS

if "--smoke-test" in sys.argv:
    # A tiny 10-bin trace with one obvious burst in the middle
    demo_bins = [100, 100, 50000, 50000, 50000, 100, 100, 100, 100, 100]
    # Minimal dataset_stats a shaper needs (normally computed by run_experiment)
    stats = {"peak_bin": 60000, "delta_w_global": 200000,
             "delta_w_per_class": {"demo": 150000},
             "delta_w_per_tier": {"demo": 150000}}   # "demo" is unmapped -> its own tier
    for name, fn in SHAPERS.items():
        out = fn(demo_bins, label="demo", dataset_stats=stats)
        print(f"--- {name} ---")
        print(f"  shaped bins: {[int(b) for b in out['shaped_bins']]}")
        print(f"  dummy={out['dummy_bytes']}  delay={out['delay_ms']:.0f}ms  "
              f"dropped={out['dropped_bytes']}  ({out['epsilon_note']})")
    print("[shapers] smoke test passed")
else:
    print("Usage: python -m shapers --smoke-test")
