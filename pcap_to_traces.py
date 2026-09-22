"""
pcap_to_traces.py -- Step A (REAL DATA): convert Mon(IoT)r IMC'19 PCAPs into
the trace format the rest of the pipeline expects.

This REPLACES make_traces.py when using real data. It reads the captured
PCAP files for a chosen set of devices, slices each capture into fixed
6-second windows of bytes-per-100ms, labels each window by DEVICE, and writes
traces.json in the exact same shape make_traces.py produced -- plus one extra
field, "source_pcap", so the attacker can split train/test by capture.

Dataset layout (Mon(IoT)r IMC'19), one PCAP per event instance:
    <ROOT>/us/<device>/<activity>/<datetime>.<length>.pcap
We pool all activities of a device into one class (label = device), because
per-activity folders are often too small on their own, and device
identification is the task that matches our per-class shaping.

Why slice into windows: a single 250-second camera capture becomes ~40
6-second traces, turning a few PCAPs into many samples. Windows from the SAME
pcap are correlated, so we record source_pcap and split by it later.

Usage:
    pip install scapy
    python pcap_to_traces.py --root /path/to/IMC19    # folder that contains "us"
Options:
    --root PATH     dataset root (the directory containing the us/ folder) [required]
    --country us    which country subfolder to use (us or uk) [default: us]
    --min-bins N    drop windows with fewer than N non-empty bins (skips near-empty
                    tail slices) [default: 1, i.e. keep everything, pad short ones]
"""

import sys                              # command-line args, clean exit
import json                             # writing traces.json
import argparse                         # parse --root / --country / --min-bins
from pathlib import Path                # filesystem walking
from collections import defaultdict     # per-class counters for the summary
from config import TRACES_PATH, BIN_MS, TRACE_BINS, SEED   # match the pipeline's constants

# The 5 device classes we selected from the dataset (see project notes).
# Edit this list to change which devices become classes.
DEVICES = [
    "amcrest-cam-wired",   # camera  -> heavy, sustained traffic
    "ring-doorbell",       # doorbell -> medium event bursts
    "tplink-plug",         # plug    -> tiny command traffic (quiet device)
    "echodot",             # echo    -> short voice/audio bursts
    "xiaomi-cleaner",      # vacuum  -> medium-long map/status uploads
]

# Trace geometry, taken straight from config so real traces match synthetic ones
BIN_SECONDS = BIN_MS / 1000.0          # 0.1 s per bin
WINDOW_SECONDS = TRACE_BINS * BIN_SECONDS   # 60 * 0.1 = 6.0 s per trace


def pcap_to_bins(pcap_path: Path) -> list[list[int]]:
    """
    Read one PCAP and return a list of fixed-length traces (6s windows).

    Each trace is a list of TRACE_BINS integers: bytes observed in each
    100ms bin. A capture longer than 6s yields multiple consecutive windows;
    a capture shorter than 6s yields one zero-padded window.

    Returns [] if the capture has no packets (or can't be read).
    """
    # Import scapy lazily so --help works even without it installed
    from scapy.utils import RawPcapReader   # fast, header-only packet reader
    from scapy.layers.l2 import Ether       # to parse the link-layer length

    # First pass: collect (relative_time_seconds, packet_num_bytes) for all packets
    packets = []                            # list of (t_rel, nbytes)
    start_time = None                       # timestamp of the first packet
    try:
        for pkt_data, pkt_meta in RawPcapReader(str(pcap_path)):
            # pkt_meta.sec/.usec = capture timestamp; wirelen = bytes on the wire
            ts = pkt_meta.sec + pkt_meta.usec / 1_000_000.0
            nbytes = pkt_meta.wirelen        # true on-wire size (not truncated)
            if start_time is None:           # anchor time at the first packet
                start_time = ts
            packets.append((ts - start_time, nbytes))   # store time RELATIVE to start
    except Exception as e:
        # A corrupt/empty pcap shouldn't kill the whole run -- warn and skip
        print(f"    [warn] could not read {pcap_path.name}: {e}")
        return []

    # No packets -> nothing to emit
    if not packets:
        return []

    # How long is the capture, and how many 6s windows does it span?
    duration = packets[-1][0]                              # last packet's rel time
    n_windows = max(1, int(duration // WINDOW_SECONDS) + 1)  # at least one window

    # Prepare empty traces: n_windows rows, each TRACE_BINS bins of zero bytes
    traces = [[0] * TRACE_BINS for _ in range(n_windows)]

    # Second pass: drop each packet's bytes into its (window, bin) slot
    for t_rel, nbytes in packets:
        win = int(t_rel // WINDOW_SECONDS)                # which 6s window
        # position inside that window, in bins (0..TRACE_BINS-1)
        bin_in_win = int((t_rel - win * WINDOW_SECONDS) // BIN_SECONDS)
        # clamp for the rare float-rounding edge at a window boundary
        if bin_in_win >= TRACE_BINS:
            bin_in_win = TRACE_BINS - 1
        traces[win][bin_in_win] += nbytes                 # accumulate bytes

    return traces


def main():
    # --- parse arguments ---
    parser = argparse.ArgumentParser(description="Convert Mon(IoT)r PCAPs to traces.json")
    parser.add_argument("--root", required=True,
                        help="dataset root (the directory that contains the us/ folder)")
    parser.add_argument("--country", default="samples",
                        help="the subfolder under --root that holds the device folders "
                             "(e.g. 'us', 'uk', or 'samples') [default: us]")
    parser.add_argument("--min-bins", type=int, default=1,
                        help="drop windows with fewer than N non-empty bins (default: 1)")
    parser.add_argument("--cap", type=int, default=0,
                        help="max traces per device class; randomly subsamples classes "
                             "larger than this to balance the dataset (0 = no cap)")
    args = parser.parse_args()

    country_dir = Path(args.root) / args.country   # e.g. /data/IMC19/us
    # Fail early with a clear message if the path is wrong
    if not country_dir.is_dir():
        sys.exit(f"ERROR: {country_dir} not found. Point --root at the folder containing '{args.country}'.")

    dataset = []                                   # the traces we will write
    per_class = defaultdict(int)                   # count traces per device (summary)
    per_class_pcaps = defaultdict(int)             # count pcaps per device (summary)

    # --- walk each chosen device ---
    for device in DEVICES:
        device_dir = country_dir / device
        if not device_dir.is_dir():
            # A missing device is a real problem for the class balance -- warn loudly
            print(f"[convert] WARNING: device folder missing, skipping: {device_dir}")
            continue

        # Find every pcap under this device (across ALL its activity folders)
        pcaps = sorted(device_dir.rglob("*.pcap"))
        print(f"[convert] {device}: {len(pcaps)} pcap files")

        for pcap in pcaps:
            # Slice this capture into 6s windows
            windows = pcap_to_bins(pcap)
            per_class_pcaps[device] += 1
            for w in windows:
                # Optionally skip near-empty tail windows (few non-empty bins)
                non_empty = sum(1 for b in w if b > 0)
                if non_empty < args.min_bins:
                    continue
                # One trace record -- SAME shape as make_traces.py, plus source_pcap
                dataset.append({
                    "label": device,               # class = device name
                    "bins": w,                     # bytes per 100ms bin
                    "source_pcap": str(pcap.relative_to(country_dir)),  # for split-by-pcap
                })
                per_class[device] += 1

    # --- guard: did we actually get data? ---
    if not dataset:
        sys.exit("ERROR: no traces produced. Check --root path and that pcaps are downloaded (not cloud-only).")

    # --- optional balancing: cap each class to --cap traces ---
    # Imbalanced classes let the attacker score high by favoring the big class,
    # which would distort the privacy metric. Capping every class to the same
    # size makes accuracy reflect genuine distinguishability. We subsample whole
    # traces (with the fixed SEED) so a re-run is reproducible; the PCAP-aware
    # split in attacker.py still holds because source_pcap travels with each trace.
    if args.cap > 0:
        import random
        rng = random.Random(SEED)                  # reproducible subsampling
        capped = []
        # Group traces by class, then take up to --cap of each
        for device in DEVICES:
            class_traces = [t for t in dataset if t["label"] == device]
            if len(class_traces) > args.cap:
                class_traces = rng.sample(class_traces, args.cap)   # random subset
            capped.extend(class_traces)
            per_class[device] = len(class_traces)  # update the summary count
        dataset = capped
        print(f"[convert] capped each class to <= {args.cap} traces")

    # --- write traces.json (same location make_traces.py uses) ---
    TRACES_PATH.write_text(json.dumps(dataset), encoding="utf-8")
    print(f"\n[convert] wrote {TRACES_PATH}: {len(dataset)} traces from {len(per_class)} devices")
    # Per-class summary -- watch for imbalance (one device dwarfing others)
    print("[convert] traces per class (pcaps):")
    for device in DEVICES:
        if per_class[device]:
            print(f"    {device:22s} {per_class[device]:5d} traces  ({per_class_pcaps[device]} pcaps)")

    # --- balance warning ---
    counts = [per_class[d] for d in DEVICES if per_class[d]]
    if counts and max(counts) > 5 * min(counts):
        print("\n[convert] NOTE: classes are imbalanced (largest > 5x smallest).")
        print("          Consider capping traces per class, or note it in the report.")


if __name__ == "__main__":
    main()
