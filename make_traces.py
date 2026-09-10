"""
make_traces.py -- Step A: build the synthetic Smart Home traffic dataset.

Produces traces.json: 200 traces (5 device-event classes x 40 traces),
each a vector of bytes-per-100ms-bin, with a ground-truth event label.

Why synthetic? Same reason as planting PII in MinCtx: full ground truth.
We know exactly which event generated each trace, so attack accuracy is
exactly measurable. The loader interface (one vector + one label) is
identical to what you would extract from a real dataset (e.g., Mon(IoT)r
or UNSW IoT traces) -- swapping in real data later only replaces this file.

Grounding: NetShaper's own evaluation represents traffic exactly this way --
burst sizes within fixed-length intervals (their simulator, Sec 5) -- and
its threat model adversary "can precisely record the traffic shape: the
sizes, timing, and direction of packets" (Sec 2.3). Our event classes give
that adversary exactly such shapes to classify.

Run:  python make_traces.py
"""

import json                    # to save the dataset
import random                  # noise in the synthetic patterns
from config import TRACES_PATH, TRACE_BINS, N_TRACES_PER_EVENT, SEED

# Fixed RNG: the dataset must be identical on every run
_rng = random.Random(SEED)

# ---------------------------------------------------------------
# Device-event classes. Each entry defines the traffic "shape" of one
# smart-home event: which bins carry traffic and roughly how many bytes.
# The shapes are stylized versions of well-documented IoT patterns
# (camera clip upload = long heavy burst; plug toggle = one tiny burst...).
# ---------------------------------------------------------------
EVENT_PROFILES = {
    # camera motion clip upload: heavy sustained upstream burst
    "camera_motion":  {"start": (4, 8),  "length": (25, 32), "bytes_per_bin": (45000, 60000)},
    # video doorbell ring: medium burst (snapshot + short clip)
    "doorbell_ring":  {"start": (8, 12), "length": (8, 12),  "bytes_per_bin": (15000, 25000)},
    # smart plug toggle: a single tiny command/ack exchange
    "plug_toggle":    {"start": (10, 14),"length": (1, 2),   "bytes_per_bin": (300, 800)},
    # voice assistant query: short up burst then response
    "assistant_query":{"start": (6, 10), "length": (5, 8),   "bytes_per_bin": (6000, 10000)},
    # robot vacuum map upload: long medium burst
    "vacuum_upload":  {"start": (15, 25),"length": (15, 22), "bytes_per_bin": (25000, 35000)},
}

# Background keepalive traffic present in every trace (all devices chat a
# little all the time) -- makes the classification non-trivial
KEEPALIVE_RANGE = (0, 400)   # bytes per bin


def make_trace(event: str) -> list[int]:
    """
    Generate one trace (bytes-per-bin vector) for a given event class.

    The start bin and burst length are jittered per trace, so the attacker
    cannot classify by position alone -- it must use the shape.
    """
    profile = EVENT_PROFILES[event]
    # Start with background keepalive noise in every bin
    trace = [_rng.randint(*KEEPALIVE_RANGE) for _ in range(TRACE_BINS)]
    # Draw the burst position and length for this specific trace
    start = _rng.randint(*profile["start"])
    length = _rng.randint(*profile["length"])
    # Add the event burst on top of the keepalive
    for b in range(start, min(start + length, TRACE_BINS)):
        trace[b] += _rng.randint(*profile["bytes_per_bin"])
    return trace


def main():
    """Build the full dataset and save it. Safe to re-run (overwrites)."""
    dataset = []                                       # list of {label, bins}
    for event in EVENT_PROFILES:
        for i in range(N_TRACES_PER_EVENT):
            dataset.append({"label": event, "bins": make_trace(event)})
    # Save as JSON -- simple, inspectable by eye
    TRACES_PATH.write_text(json.dumps(dataset), encoding="utf-8")
    print(f"[make_traces] wrote {TRACES_PATH}: {len(dataset)} traces, "
          f"{len(EVENT_PROFILES)} classes, {TRACE_BINS} bins each")

    # Sanity check: every class has the right count and non-trivial traffic
    for event in EVENT_PROFILES:
        subset = [d for d in dataset if d["label"] == event]
        assert len(subset) == N_TRACES_PER_EVENT
        assert all(sum(d["bins"]) > 0 for d in subset)
    print("[make_traces] sanity check passed: all classes populated")


if __name__ == "__main__":
    main()
