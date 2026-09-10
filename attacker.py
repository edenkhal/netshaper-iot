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
"""

import numpy as np                                  # feature matrices
from sklearn.ensemble import RandomForestClassifier
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
