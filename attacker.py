"""
attacker.py -- the traffic-analysis adversary.

Role in the experiment: the privacy metric. For each shaper we train a
classifier ON SHAPED TRACES and measure how well it identifies the device
event. Training on shaped data models the paper's adversary, who "may have
access to observations of arbitrary known streams to train its attack [and]
knowledge about NetShaper, including its shaping strategy and privacy
configurations" (their Sec 2.3) -- i.e., the defense is never a secret.

Model choice: a RandomForest over burst features. The paper used a CNN (BB)
and a TCN; for 200 short traces a RandomForest is the right size and is a
standard strong baseline for traffic analysis. This is a declared
simplification (report it in limitations): if the RF already fails, deep
models on this data volume would not do better, but stating the substitution
honestly matters.

# --- Why RandomForest and not a TCN/CNN (as in the paper)? ---
# 1. Data size: we have 200 traces. Deep temporal models (TCN) need
#    thousands+ of samples or they overfit -- on this dataset a TCN would
#    likely score WORSE, not better. The paper trained on far more captured data.
# 2. Logic of the claim: our goal is to show the defense makes the attacker
#    FAIL. If a strong standard baseline (RF) already drops to chance on shaped
#    traffic, that is good evidence the defense works -- a heavier model would
#    not change that conclusion.
# 3. Cost: RF runs in seconds, no GPU/tuning, so we spend our effort on the
#    actual contribution (per-class DP), not on network engineering.
# Limitation (report this): RF does not learn temporal dependencies on its own
# -- it only sees the hand-crafted features we feed it. A TCN attacker might
# catch subtle inter-burst timing patterns our features miss, so our privacy
# numbers are an optimistic upper bound against a more sophisticated adversary.
# Future work: compare against a TCN attacker on a larger captured dataset.


"""

import numpy as np                                  # feature matrices
from sklearn.ensemble import RandomForestClassifier  # the adversary predictor - see above for why we use this instead of a TCN 
from sklearn.model_selection import train_test_split
from config import SEED


def features(shaped_bins: list[int]) -> list[float]:
    """
    Turn one shaped trace into a feature vector.

    We give the attacker both the raw bin sequence AND summary statistics
    (total volume, peak, burst count, active duration) -- the same feature
    families the paper cites for classification: "packet sizes, inter-packet
    timing, total bytes transferred in a burst, the burst duration..." (Sec 2.1).
    """
    arr = np.array(shaped_bins, dtype=float)
    active = arr > 1000                      # bins with meaningful traffic
    stats = [
        arr.sum(),                           # total bytes
        arr.max(),                           # peak bin
        float(active.sum()),                 # active duration (bins)
        float(np.argmax(arr)),               # position of the peak
        float(arr.std()),                    # burstiness
    ]
    # Raw sequence + stats: the attacker gets everything observable
    return list(arr) + stats


def attack_accuracy(shaped_dataset: list[dict]) -> float:
    """
    Train/test the adversary on one shaper's output.

    Args:
        shaped_dataset: list of {"label": event, "shaped_bins": [...]}

    Returns: test-set accuracy (the privacy metric: lower = more private).
    """
    # Build the feature matrix and label vector
    X = np.array([features(d["shaped_bins"]) for d in shaped_dataset])
    y = np.array([d["label"] for d in shaped_dataset])
    # 80/20 split, stratified so every class appears in the test set;
    # fixed seed so the split is identical across shapers (fair comparison)
    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=SEED)
    # A modest forest: enough capacity, no tuning theater
    clf = RandomForestClassifier(n_estimators=200, random_state=SEED)
    clf.fit(X_tr, y_tr)
    return float(clf.score(X_te, y_te))
