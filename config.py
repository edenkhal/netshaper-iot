# TODO: Change the desc a bit
"""
config.py:  All project settings in one place.

Time model: traffic is represented as bytes-per-bin over fixed-length bins,
exactly like the NetShaper artifact's simulator, which "transforms an
application's original packet sequence into a sequence of burst sizes
within fixed-length intervals" (Sabzi et al., USENIX Security 2024, Sec 5).
"""

from pathlib import Path     # OS-independent paths

#################################### Paths ####################################
BASE_DIR = Path(__file__).parent
TRACES_PATH = BASE_DIR / "traces.json"          # the synthetic IoT trace dataset
RESULTS_DIR = BASE_DIR / "results"
SHAPED_PATH = RESULTS_DIR / "shaped.json"       # shaped traces + overhead metrics
METRICS_PATH = RESULTS_DIR / "metrics.csv"      # summary table (device identification)
ACTION_METRICS_PATH = RESULTS_DIR / "action_metrics.csv"   # per-device action table

#################################### Time model ####################################
BIN_MS = 100          # one bin = 100 ms of traffic
TRACE_BINS = 60       # each trace covers 60 bins = 6 seconds

#################################### NetShaper parameters (paper Sec 3) ####################################
# T: the DP shaping interval, in bins. The paper shapes at fixed intervals T;
# we use 5 bins = 500 ms (the paper used 10ms-1s depending on the app).
T_BINS = 5
# W: the neighboring window, as a multiple of T (paper: W = kT, W >> T).
# W = 4T = 2 s here; the paper used W=5s for video, W=1s for web.
W_INTERVALS = 4
# Per-query privacy parameters (epsilon_T, delta_T). The paper's headline
# insight: even large epsilons defeat SOTA attacks in practice (their Sec 5.1).
EPSILON_T = 1.0
DELTA_T = 1e-6

#################################### Dataset parameters ####################################
N_TRACES_PER_EVENT = 40   # traces per device-event class (5 classes -> 200 traces)
SEED = 42                 # global seed: the experiment must be reproducible

#################################### Action-identification evaluation (Step D) ####################################
# The second privacy metric: the device is public, the secret is WHICH ACTION it
# performed (see DP_ANALYSIS.md Sec 6). Real data only -- it needs source_pcap.
ACTION_MIN_CAPTURES = 10  # drop actions with fewer captures (many have only 3)
N_EVAL_SPLITS = 10        # capture splits averaged by the action evaluation

#################################### Shaper order in the experiment ####################################
# Must match the keys of the SHAPERS dict (shapers/__init__.py)
# New shapers go at the end: the DP shapers share one noise RNG, so appending
# keeps the earlier shapers' noise draws (and results) unchanged
SHAPER_LEVELS = ["shaper_none", "shaper_const_rate", "shaper_dp_global", "shaper_dp_per_class",
                 "shaper_dp_tiers"]
