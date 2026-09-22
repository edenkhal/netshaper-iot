# NetShaper-IoT -- DP traffic shaping for Smart Home privacy

Final project: extending NetShaper (Sabzi et al., USENIX Security 2024) to
smart-home IoT traffic, with a per-device-class adaptive shaping strategy.

## The problem in one line
Even when IoT traffic is encrypted, the *shape* of the traffic (bytes and
timing) leaks what a device is doing -- when the camera uploaded a clip, when
someone rang the doorbell, when the vacuum started. The device itself is not
the secret: an attacker can usually spot it from IP addresses and protocols
alone, and NetShaper's threat model does not try to hide it. The secret is
the ACTION. We shape the traffic so an attacker can't tell which action is
underway, and measure what that costs in bandwidth and latency.

## Grounding in the paper (verified facts from the full text)
- NetShaper mitigates network side-channel leaks via **traffic shaping with
  (epsilon, delta)-DP guarantees**, using the **Gaussian mechanism** on the
  buffering-queue length at fixed intervals T (their Sec 3).
- Neighboring streams differ by at most **Delta_W in L1 over any window W**;
  a TTL that flushes bytes older than W enforces the assumption that bounds
  sensitivity to **Delta_T <= Delta_W** (their Prop. 1).
- It was evaluated on **video streaming and a medical web service -- NOT IoT**
  -- with per-domain parameters (video: W=5s, Delta=2.5MB, T=1s). This is the
  gap we fill.
- Headline insight we rely on: **there is a large gap between theoretical DP
  and the epsilon needed to defeat real attacks** -- their SOTA classifier is
  beaten at epsilon up to ~1000. So we report *empirical* attack accuracy.
- The artifact ships a **simulator** that turns a packet trace into a
  burst-size sequence per interval -- exactly the representation we use.

## The gap we fill (our contribution)
A smart home is many domains at once: a camera moves megabytes, a smart plug
moves hundreds of bytes. One global Delta_W sized for the camera forces
camera-scale noise onto the plug. **Our extension gives each device class its
own Delta_W**, cutting dummy traffic for quiet devices while keeping the
DP guarantee on *which event* happened within a class. We quantify the
privacy/cost trade against the paper's own baselines (Base, CR, NetShaper).

## Project structure
```
netshaper-iot/
|- README.md            <- you are here
|- DP_ANALYSIS.md       <- formal privacy analysis (the DP shapers 2-4)
|- REPORT_DRAFT.md      <- methodology / results / discussion, with the real-data numbers
|- requirements.txt
|- config.py            <- all settings (bins, T, W, epsilon, delta, seed, shaper list)
|- make_traces.py       <- Step A (synthetic): dataset + ground-truth labels
|- pcap_to_traces.py    <- Step A (real data): convert Mon(IoT)r IMC'19 PCAPs -> traces.json
|- shapers/             <- the five shaping strategies
|  |- __init__.py       <- SHAPERS registry
|  |- __main__.py       <- the --smoke-test entry point
|  |- shaper0_none.py        <- no shaping (paper's Base)
|  |- shaper1_const_rate.py  <- constant-rate (paper's CR)
|  |- shaper2_netshaper.py   <- NetShaper DP shaping, faithfully simulated
|  |- shaper3_adaptive.py    <- OUR per-class adaptive DP shaping
|  |- shaper4_dp_tiers.py    <- OUR per-tier DP shaping (device -> tier map at the top)
|- attacker.py          <- the traffic-analysis adversary: device ID (Step C) and
|                          action ID within a known device (Step D)
|- run_experiment.py    <- Step B: compute Delta_W, shape every trace with every shaper
|- evaluate.py          <- Step C: device identification + overheads + figures
|- evaluate_actions.py  <- Step D (real data): which ACTION did a known device do?
|- traces.json          <- made by pcap_to_traces.py (or make_traces.py)
|- results/             <- made by run_experiment.py / evaluate.py / evaluate_actions.py
```

## Install (once)
```bash
cd netshaper-iot
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

## Run order
```bash
python make_traces.py            # Step A: build the dataset (must end "passed")
python -m shapers --smoke-test   # sanity: all five shapers run
python run_experiment.py         # Step B: shape everything, compute Delta_W
python evaluate.py               # Step C: attack accuracy, overheads, figures
```
### Using real data (Mon(IoT)r IMC'19) instead of synthetic
The pipeline can run on real IoT captures with no changes to the shapers,
DP math, attacker, or evaluate. Only the data source changes:

1. Request + download the IMC'19 **Interaction Dataset** (`iot-data.tar`, ~9.3GB)
   from the Mon(IoT)r group and extract it (you get `us/`, `uk/`, ... folders).
2. Make sure the device folders you want are fully downloaded to disk
   (not cloud-only placeholders).
3. Convert PCAPs to traces.json (replaces make_traces.py):
   ```
   pip install scapy
   python pcap_to_traces.py --root /path/to/IMC19   # folder containing us/
   ```
   This walks the 5 chosen devices (edit DEVICES in the script to change them),
   labels each trace by DEVICE, slices every capture into fixed 6s/60-bin
   windows, and records source_pcap.
4. Run the pipeline exactly as usual:
   ```
   python run_experiment.py
   python evaluate.py
   python evaluate_actions.py   # Step D: real data only
   ```

The task becomes device identification (which device is active) instead of
synthetic event identification. The attacker automatically splits train/test
BY PCAP when source_pcap is present, so correlated windows from one capture
never leak across the split (an honest evaluation). On synthetic data (no
source_pcap) it uses the original stratified split.

No manual scoring anywhere -- the whole pipeline is automatic (unlike MinCtx,
because here the "answer quality" is a classifier accuracy, not a text answer).

## How to debug
- Every script runs standalone and prints verbose intermediate values.
- `shapers --smoke-test` prints the shaped bins so you can see, by eye, that
  S0 passes traffic through, S1 flattens it, S2/S3 add noise + dummy.
- In run_experiment, watch the per-class Delta_W line: the camera's Delta_W
  should be ~100x the plug's. That gap is the whole reason shaper3 helps.
- If shaper3 does NOT beat shaper2 on bandwidth, that is a real result to
  discuss, not a bug -- report it.

## What the first run shows (and the tension to discuss)
NOTE: the table below is the old SYNTHETIC run. The real-data results (and the
action-identification table that matters more) are in REPORT_DRAFT.md and
results/*.csv. The reading underneath it has been corrected -- see below.

Our test run gave:

| shaper | attack acc | bandwidth | mean delay |
|--------|-----------|-----------|------------|
| S0 none | 1.00 | 0x | 0 ms |
| S1 constant-rate | 0.20 (chance) | 6.8x | 0 ms |
| S2 NetShaper global | 0.25 | 60.7x | 559 ms |
| S3 adaptive (ours) | 0.68 | 13.8x | 536 ms |

Read this honestly: adaptive shaping cut bandwidth **4.4x** (60.7x -> 13.8x),
but attack accuracy **rose** (0.25 -> 0.68). That is the real privacy/cost
tension of per-class parameters, and it is the heart of the project's
discussion -- not something to hide:
- Per-class Delta_W is public (threat model), so the attacker wins by reading
  the *class* off the parameters. But device/class identity is a NON-GOAL for
  NetShaper: its adversary is assumed to know already which device is talking.
  So this number is a leak beyond the paper's scope, not a broken guarantee.
- On the property NetShaper does promise -- which ACTION a known device
  performed -- the real-data run (Step D, evaluate_actions.py) found every
  shaper at chance, S3 included. The cheap shaper delivers the actual
  guarantee; what it gives up is protection the paper never offered.
- So the honest framing is: S3 buys a large bandwidth saving and still keeps
  NetShaper's own guarantee. The interesting question your report can explore
  is what it costs to ALSO hide the class -- e.g., grouping devices into a few
  privacy *tiers* (quiet / medium / heavy) instead of one global value or
  one-per-class.

This is exactly the kind of tunable trade the paper frames as the whole point
of DP shaping ("configuring a tradeoff between privacy guarantees, bandwidth
and latency overheads"). Making the trade *visible and measurable* for IoT is
the contribution.

## Design decisions (why it's built this way)
- **Simulator, not a live tunnel**: the paper itself reports privacy/bandwidth
  from its simulator (Sec 5). A live QUIC middlebox is pure engineering with
  no extra research value at this scope. Future work: the real testbed.
- **Synthetic traces with known labels**: gives exact attack-accuracy ground
  truth. The loader takes one vector + one label per trace, so swapping in a
  real IoT dataset (Mon(IoT)r, UNSW) only replaces make_traces.py.
- **RandomForest attacker, not CNN/TCN**: right-sized for 200 short traces and
  a strong standard baseline. Declared in limitations.
- **Basic composition, not Renyi**: a conservative (over-)estimate of epsilon;
  never understates privacy loss. See DP_ANALYSIS.md Sec 5.
