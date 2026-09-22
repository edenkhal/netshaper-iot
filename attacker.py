"""
attacker.py -- the traffic-analysis adversary.

Role in the experiment: the device-identification metric, which is a property
OUTSIDE NetShaper's own threat model -- see action_attack_accuracy below for
the metric the mechanism actually promises. For each shaper we train a
classifier ON SHAPED TRACES and measure how well it identifies the device.
Training on shaped data models the paper's adversary, who "may have
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
from collections import Counter, defaultdict        # action counts + capture-level vote
from sklearn.ensemble import RandomForestClassifier  # the adversary predictor - see above for why we use this instead of a TCN
from sklearn.model_selection import train_test_split
from config import SEED, ACTION_MIN_CAPTURES, N_EVAL_SPLITS


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
        shaped_dataset: list of {"label": event, "shaped_bins": [...],
                        and (for real data) "source_pcap": ...}

    Returns: test-set accuracy (the privacy metric: lower = more private).

    Split logic:
        - REAL DATA (records carry "source_pcap"): split by PCAP, so all windows
        cut from one capture land on the SAME side. Otherwise near-identical
        sibling windows would appear in both train and test and the attacker
        would "cheat", inflating accuracy. This is the honest evaluation.
        - SYNTHETIC DATA (no "source_pcap"): each trace is independent, so a
        plain stratified 80/20 split is correct.
    """
    # Build the feature matrix and label vector (same for both paths)
    X = np.array([features(d["shaped_bins"]) for d in shaped_dataset])
    y = np.array([d["label"] for d in shaped_dataset])

    # --- decide which split to use ---
    # Real data carries a non-empty source_pcap on every record; synthetic data
    # either lacks the key or has it set to None.
    has_pcap = all(d.get("source_pcap") for d in shaped_dataset)
    if has_pcap:
        # Group-aware split: whole PCAPs go to train or test, never both.
        # GroupShuffleSplit keeps groups (source_pcap) intact across the split.
        from sklearn.model_selection import GroupShuffleSplit
        groups = np.array([d["source_pcap"] for d in shaped_dataset])
        splitter = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=SEED)
        train_idx, test_idx = next(splitter.split(X, y, groups))
        X_tr, X_te = X[train_idx], X[test_idx]
        y_tr, y_te = y[train_idx], y[test_idx]
    else:
        # 80/20 split, stratified so every class appears in the test set;
        # fixed seed so the split is identical across shapers (fair comparison)
        X_tr, X_te, y_tr, y_te = train_test_split(
            X, y, test_size=0.2, stratify=y, random_state=SEED)

    # A modest forest: enough capacity, no tuning theater
    clf = RandomForestClassifier(n_estimators=200, random_state=SEED)
    clf.fit(X_tr, y_tr)
    return float(clf.score(X_te, y_te))


# ---------------------------------------------------------------------------
# The SECOND privacy metric: which ACTION did a KNOWN device perform?
#
# Device identification (above) measures what the per-class/per-tier shapers
# reveal as a side effect, beyond anything NetShaper's mechanism protects:
# their parameters are public, so they reveal the class.
# The property they actually promise is event privacy WITHIN a device, which is
# also the paper's own goal (hide the application's secret, not its identity).
# These functions measure exactly that, one device at a time.
#
# The Mon(IoT)r layout gives us the labels for free: source_pcap is
# "<device>/<action>/<capture>.pcap", so the action is already in the data
# produced by run_experiment.py -- no re-conversion of PCAPs needed.
# ---------------------------------------------------------------------------


def action_of(source_pcap: str) -> str:
    """
    The action (Mon(IoT)r activity folder) a trace came from.

    "amcrest-cam-wired\\android_lan_photo\\2019-03-29_21_22_44.45s.pcap"
        -> "android_lan_photo"
    Returns "" when the path carries no action folder (synthetic data).
    """
    if not source_pcap:
        return ""
    parts = source_pcap.replace("\\", "/").split("/")   # accept both separators
    return parts[1] if len(parts) > 2 else ""


def action_attack_accuracy(shaped_dataset: list[dict], device: str,
                           min_captures: int = ACTION_MIN_CAPTURES,
                           n_splits: int = N_EVAL_SPLITS) -> dict | None:
    """
    Train/test the adversary on ONE device's traces, predicting the action.

    Args:
        shaped_dataset: one shaper's output (needs "source_pcap" on every record)
        device:         the device label to restrict to (its identity is public here)
        min_captures:   actions with fewer captures are dropped -- the dataset has
                        many actions with only 3 captures, too few to split
        n_splits:       how many capture splits to average over (small per-device
                        data makes a single split unreliable)

    Returns a dict of metrics, or None when fewer than 2 actions survive the
    min_captures filter (the vacuum: every one of its actions has 3 captures).

    Metrics (mean and sd over the splits):
        acc / acc_sd                  per-window accuracy
        balanced / balanced_sd        per-window balanced accuracy (mean recall)
        capture_acc / capture_acc_sd  per-capture accuracy, by majority vote over
                                      the windows of each test capture -- an
                                      adversary who watches one whole interaction
        chance = 1/n_actions          no-information level for this device
        advantage                     (balanced - chance) / (1 - chance), so that
                                      devices with different action counts (and
                                      so different chance levels) are comparable
    """
    # --- restrict to this device, and to actions with enough captures ---
    traces = [d for d in shaped_dataset if d["label"] == device]
    captures_per_action = defaultdict(set)
    for d in traces:
        captures_per_action[action_of(d["source_pcap"])].add(d["source_pcap"])
    keep = {a for a, caps in captures_per_action.items()
            if a and len(caps) >= min_captures}
    if len(keep) < 2:                      # nothing to tell apart -> no task
        return None
    traces = [d for d in traces if action_of(d["source_pcap"]) in keep]

    # Same feature extractor as the device attacker: the adversary sees the
    # shaped bins and nothing else
    X = np.array([features(d["shaped_bins"]) for d in traces])
    y = np.array([action_of(d["source_pcap"]) for d in traces])
    groups = np.array([d["source_pcap"] for d in traces])
    actions = sorted(keep)

    # Split by CAPTURE, exactly as in attack_accuracy: windows cut from one
    # capture are near-copies, so they must not straddle train and test
    from sklearn.model_selection import GroupShuffleSplit
    splitter = GroupShuffleSplit(n_splits=n_splits, test_size=0.2, random_state=SEED)

    accs, balanced, capture_accs = [], [], []
    for train_idx, test_idx in splitter.split(X, y, groups):
        # A split that lost an action from training cannot predict it -- skip it
        if len(set(y[train_idx])) < len(actions):
            continue
        clf = RandomForestClassifier(n_estimators=200, random_state=SEED)
        clf.fit(X[train_idx], y[train_idx])
        pred = clf.predict(X[test_idx])
        y_te = y[test_idx]

        accs.append(float(np.mean(pred == y_te)))
        # Balanced accuracy = mean per-action recall, so a big action cannot
        # carry the score (the same reason we report it for devices)
        recalls = [float(np.mean(pred[y_te == a] == a))
                   for a in actions if np.any(y_te == a)]
        balanced.append(float(np.mean(recalls)))

        # Capture level: majority vote over the windows of each test capture
        votes = defaultdict(list)                      # capture -> predictions
        truth = {}                                     # capture -> its action
        for cap, p, t in zip(groups[test_idx], pred, y_te):
            votes[cap].append(p)
            truth[cap] = t
        hits = [Counter(v).most_common(1)[0][0] == truth[cap]
                for cap, v in votes.items()]
        capture_accs.append(float(np.mean(hits)))

    if not accs:                           # every split was unusable
        return None

    chance = 1.0 / len(actions)
    balanced_mean = float(np.mean(balanced))
    return {
        "device": device,
        "n_actions": len(actions),
        "actions": actions,
        "n_traces": len(traces),
        "n_captures": len({g for g in groups}),
        "n_splits_used": len(accs),
        "chance": chance,
        "acc": float(np.mean(accs)), "acc_sd": float(np.std(accs)),
        "balanced": balanced_mean, "balanced_sd": float(np.std(balanced)),
        "capture_acc": float(np.mean(capture_accs)),
        "capture_acc_sd": float(np.std(capture_accs)),
        # How much of the gap between guessing and perfect the attacker closed
        "advantage": (balanced_mean - chance) / (1.0 - chance),
    }