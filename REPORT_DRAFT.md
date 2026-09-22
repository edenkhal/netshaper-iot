# NetShaper-IoT: Methodology, Results and Discussion

Units: 1 KB = 1,000 bytes; 1 Mbit/s = 10⁶ bit/s. "Main split" values are the ones in
`results/metrics.csv` and the figures; "10 splits" values are mean ± standard deviation
over ten different train/test splits (Section 1.3).

---

## 1. Methodology

### 1.1 Data

We use real smart-home traffic from the Mon(IoT)r interaction dataset (Ren et al.,
IMC 2019), which contains one packet capture per controlled interaction with a device,
for example switching a plug on from the Android app or starting a camera recording.
We selected five devices that span the traffic-volume range of a smart home.

**Table 1. Dataset.**

| Device | Role | Captures | Interaction types | 6-s traces | Mean traffic |
|---|---|---:|---:|---:|---:|
| amcrest-cam-wired | camera | 212 | 8 | 1,642 | 240 kbit/s |
| ring-doorbell | video doorbell | 167 | 7 | 878 | 502 kbit/s |
| tplink-plug | smart plug | 242 | 9 | 692 | 7.4 kbit/s |
| echodot | voice assistant | 95 | 7 | 257 | 26 kbit/s |
| xiaomi-cleaner | robot vacuum | 27 | 9 | 88 | 1.1 kbit/s |
| **Total** | | **743** | | **3,557** | |

**Task.** Device identification: a trace is labeled with the device that produced it, and
all of a device's interaction types are pooled into one class. Many individual
interaction types have only three captures, too few to train on.

**From captures to traces.** For every packet we keep its timestamp and on-wire length.
Bytes are summed into 100 ms bins, and each capture is cut into consecutive,
non-overlapping 6-second windows of 60 bins. The last partial window is zero-padded, and
windows without traffic are dropped. Each trace records the capture it came from. This
is the bytes-per-interval representation that NetShaper's own simulator uses.

**Class balance.** The classes were not capped: the camera contributes 46% of the traces
and the vacuum 2.5%. Uniform chance over five classes is 0.20, but an attacker that
always answers "camera" already scores about 0.45. We therefore report **balanced
accuracy** (the mean of per-device recall, where 0.20 means no information) next to
plain accuracy, and include the always-"camera" score as a reference.

### 1.2 Shaping strategies

- **S0 None (Base).** Traffic passes unchanged.
- **S1 Constant rate (CR).** Every bin carries the dataset's largest bin, 199,038 B
  (15.9 Mbit/s), so the shape carries no information and nothing ever queues. Like the
  paper, we configure CR for peak load.
- **S2 NetShaper, global ΔW.** The paper's mechanism. Bytes enter a queue. Every
  T = 500 ms the queue length L is released with Gaussian noise, L̃ = L + N(0, σ²), with
  σ = ΔW·√(2 ln(1.25/δ_T))/ε_T ≈ 5.30·ΔW. The shaper sends min(max(0, L̃), L) real bytes
  and pads the rest of max(0, L̃) with dummy bytes. A TTL drops bytes older than
  W = 2 s (4T), which bounds the query's sensitivity by ΔW (the paper's Prop. 1). One ΔW
  applies to every device.
- **S3 Per-device ΔW (ours).** The same mechanism with a separate ΔW for each device.
- **S4 Tiered ΔW (ours).** The same mechanism. Devices are grouped into tiers that share
  one ΔW. Main configuration: heavy = {camera}, medium = {doorbell, Echo Dot, vacuum},
  light = {plug}. Section 3.5 also evaluates an alternative grouping, S4′.

**Estimating ΔW.** Following the paper (Sec. 5.1, App. B), ΔW is the 99th percentile of
the distance between two traces. The distance is the largest L1 difference between their
per-interval byte counts over any window of length W (the paper's Definition 1). We
sample 1,500 random pairs for the global value and 400 pairs within each device (S3) or
tier (S4). This gives:

- global: 335 KB
- per device: 339 KB (camera), 308 KB (doorbell), 58 KB (Echo Dot), 23 KB (plug),
  4.0 KB (vacuum)
- per tier: 354 KB (heavy), 325 KB (medium), 15 KB (light)

**Privacy parameters.** ε_T = 1 and δ_T = 10⁻⁶ per release. A 6-s trace has 12 releases,
so by basic sequential composition each trace is (12, 1.2·10⁻⁵)-DP with respect to the
neighbor relation its ΔW defines. Basic composition overstates the loss compared with
the paper's Rényi-DP accounting. S2, S3 and S4 share these parameters. They differ only
in which ΔW, and so which neighbor relation, applies to each device.

### 1.3 Adversary and evaluation protocol

**Adversary.** A random forest with 200 trees, trained on shaped traffic. It sees the 60
observed bin sizes plus five summaries: total bytes, peak bin, number of active bins,
position of the peak, and standard deviation. As in the paper's threat model, the
adversary knows the shaping strategy and its parameters and trains on the defense's
output.

**Split by capture.** Windows cut from the same capture are strongly correlated, so a
random split over windows would put near-copies of test traces into training. We split
whole captures 80/20 (scikit-learn `GroupShuffleSplit`, seed 42): 594 training captures
(2,792 traces) and 149 test captures (765 traces). The split depends only on the
captures, so every strategy is trained and tested on the same traces. To measure how
much the results depend on the split, we repeat the evaluation over ten capture splits
(seeds 42–51).

**Cost metrics.**

- **Bandwidth overhead:** total padding bytes divided by total original bytes.
- **Mean delay:** the byte-weighted mean queueing delay of delivered payload, averaged
  over traces.
- **Dropped:** payload bytes discarded by the TTL, divided by original bytes.

### 1.4 The second task: which action did a known device perform?

Device identification is a non-goal under NetShaper's threat model. The paper does not
set out to hide that a device is active, because an adversary can usually identify it
from its IP address, its protocol, or the mere presence of traffic. What the mechanism
promises is that a known device's *actions* are indistinguishable: not hiding that the
camera is transmitting, but hiding whether it is streaming video after detecting motion
or sitting in standby. We therefore run a second evaluation in which the device is public
and the secret is the action, which is the property the shaping is built to protect.

The dataset labels this for free, because each capture sits in a folder named after the
controlled interaction that produced it. We train one classifier per device, using the
same features and the same split by capture, and drop actions with fewer than 10 captures
(many have only three). What remains:

| Device | Actions kept | Traces | Captures | Chance |
|---|---|---:|---:|---:|
| amcrest-cam-wired | 6 (photo, recording, watch; LAN and WAN) | 1,556 | 206 | 0.17 |
| ring-doorbell | 4 (watch LAN/WAN, Alexa watch, Alexa stop) | 845 | 158 | 0.25 |
| tplink-plug | 6 (on and off; LAN, WAN, Alexa) | 672 | 233 | 0.17 |
| echodot | 2 (voice, volume) | 164 | 80 | 0.50 |
| xiaomi-cleaner | excluded: every action has only 3 captures | — | — | — |

Chance differs per device, so alongside balanced accuracy we report the **advantage over
chance**, (balanced − chance) / (1 − chance), which is 0 for a useless attacker and 1 for
a perfect one. We also report a **capture-level** score, taking the majority vote over the
windows of one capture, which models an adversary who watches a whole interaction rather
than a single 6-second window. Results are averaged over ten capture splits.

---

## 2. Results

**Table 2. Privacy (lower is better).**

| Strategy | Accuracy (main) | Balanced acc. (main) | Accuracy (10 splits) | Balanced acc. (10 splits) |
|---|---:|---:|---:|---:|
| S0 None | 0.901 | 0.724 | 0.893 ± 0.019 | 0.737 ± 0.031 |
| S1 Constant rate | 0.473 | 0.200 | 0.451 ± 0.028 | 0.200 ± 0.000 |
| S2 NetShaper, global ΔW | 0.442 | 0.192 | 0.427 ± 0.023 | 0.196 ± 0.005 |
| S3 Per-device ΔW (ours) | 0.678 | 0.780 | 0.720 ± 0.028 | 0.746 ± 0.016 |
| S4 Tiered ΔW (ours) | 0.607 | 0.398 | 0.633 ± 0.025 | 0.398 ± 0.005 |
| *Reference: always "camera"* | *0.473* | *0.200* | *0.451 ± 0.028* | *0.200* |

**Table 3. Cost, over all 3,557 traces (5.9 hours of device traffic).**

| Strategy | Bandwidth overhead | Total padding | Mean delay | Payload dropped |
|---|---:|---:|---:|---:|
| S0 None | 0× | 0 | 0 ms | 0% |
| S1 Constant rate | 65.85× | 41.8 GB | 0 ms | 0% |
| S2 NetShaper, global ΔW | 47.88× | 30.4 GB | 541.5 ms | 3.38% |
| S3 Per-device ΔW (ours) | 34.44× | 21.9 GB | 530.7 ms | 3.51% |
| S4 Tiered ΔW (ours) | 39.34× | 25.0 GB | 549.3 ms | 4.39% |

**Table 4. Per device: padding rate (Mbit/s) and attacker recall** (the fraction of the
device's test traces labeled correctly; mean over ten splits). Under S1, recall is 1.00
for the camera and 0 for every other device.

| Device | Own traffic | Pad S2 | Pad S3 | Pad S4 | Recall S0 | Recall S2 | Recall S3 | Recall S4 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Camera | 0.240 | 11.5 | 11.6 | 12.0 | 0.95 | 0.91 | 0.93 | 0.93 |
| Doorbell | 0.502 | 11.1 | 10.3 | 10.9 | 0.94 | 0.05 | 0.10 | 0.06 |
| Echo Dot | 0.026 | 11.3 | 2.06 | 10.8 | 0.48 | 0.00 | 0.80 | 0.00 |
| Plug | 0.0074 | 11.5 | 0.78 | 0.51 | 0.93 | 0.01 | 0.96 | 1.00 |
| Vacuum | 0.0011 | 11.3 | 0.14 | 11.1 | 0.39 | 0.00 | 0.94 | 0.00 |

![Attack accuracy per strategy](results/attack_accuracy.png)

**Figure 1.** Attack accuracy per strategy on the main split. The dashed line is uniform
chance for five classes (0.20). Because the classes are imbalanced, the no-information
score on this split is 0.47 (always answering "camera"). Bars near 0.45 therefore mean
the attacker learned nothing; Table 2 gives balanced accuracy.

![Bandwidth overhead per strategy](results/bandwidth_overhead.png)

**Figure 2.** Bandwidth overhead (padding divided by original bytes, log scale). S0 has
no overhead; its bar is drawn at the axis floor of 0.01.

![Privacy against cost](results/privacy_vs_cost.png)

**Figure 3.** Privacy against cost, one point per strategy (lower left is better). S0 is
drawn at the axis floor (its true overhead is 0). S1 and S2 are at the no-information
level. S3 and S4 give up some privacy for less padding. Plain accuracy understates how
differently those two leak: their balanced accuracies are 0.75 and 0.40 (Table 2).

**Main observations.**

1. Without shaping, the attacker identifies the device in 90% of test windows (balanced
   accuracy 0.72–0.74).
2. S1 and S2 both bring the attacker to the no-information level: balanced accuracy 0.20.
   S2 needs 27% less padding than S1. The 0.03 accuracy gap between them is within
   split-to-split variation.
3. S3 uses 28% less padding than S2, but its balanced accuracy (0.75) equals that of no
   shaping.
4. S4 falls between S2 and S3 on both axes: balanced accuracy 0.40 with 25.0 GB of
   padding.
5. Every DP strategy adds 0.53–0.55 s of mean delay and drops 3.4–4.4% of payload.

### 2.1 The second task: action identification

**Table 5. Action identification within a known device.** Balanced accuracy and, in
brackets, the advantage over chance. Mean over ten capture splits; chance is 0.17 for the
camera and plug, 0.25 for the doorbell, 0.50 for the Echo Dot.

| Strategy | Camera | Doorbell | Plug | Echo Dot | Macro balanced | Macro advantage | Capture-level |
|---|---:|---:|---:|---:|---:|---:|---:|
| S0 None | 0.479 (0.38) | 0.779 (0.71) | 0.524 (0.43) | 0.651 (0.30) | 0.609 | 0.45 | 0.708 |
| S1 Constant rate | 0.167 (0.00) | 0.250 (0.00) | 0.167 (0.00) | 0.500 (0.00) | 0.271 | 0.00 | 0.222 |
| S2 Global ΔW | 0.157 (−0.01) | 0.240 (−0.01) | 0.151 (−0.02) | 0.474 (−0.05) | 0.256 | −0.02 | 0.240 |
| S3 Per-device ΔW | 0.173 (0.01) | 0.240 (−0.01) | 0.190 (0.03) | 0.445 (−0.11) | 0.262 | −0.02 | 0.250 |
| S4 Tiered ΔW | 0.161 (−0.01) | 0.258 (0.01) | 0.156 (−0.01) | 0.523 (0.05) | 0.275 | 0.01 | 0.264 |

![Action identification per device](results/action_accuracy.png)

**Figure 4.** Action identification within a known device, one group per device and one
bar per strategy, with error bars over ten capture splits. The dashed line in each group
is that device's chance level, which differs because the devices have different numbers
of actions.

Two observations:

1. **The action is visible when traffic is unshaped.** The doorbell's action is identified
   78% of the time against a chance level of 25%, rising to 91% when the attacker votes
   over a whole capture. Across the four usable devices the attacker closes 45% of the gap
   between guessing and perfect.
2. **Every shaper removes it.** S1 through S4 all sit at their device's chance level, with
   advantages between −0.02 and 0.01, which is within the spread across splits. The
   cheapest DP configuration does this as completely as the most expensive one.

---

## 3. Discussion

### 3.1 The threat is real

With no shaping, the attacker names the device behind 90% of unseen 6-second windows
from unseen captures, using nothing but bytes per 100 ms. The camera, doorbell and plug
are each recognized at least 93% of the time. The Echo Dot (0.48) and the vacuum (0.39)
are harder: they have the fewest training captures and send little traffic in most
windows. A balanced accuracy of 0.74, against a no-information level of 0.20, confirms
that the shape of encrypted traffic alone identifies smart-home devices.

### 3.2 DP shaping works, and costs less than constant rate

S1 and S2 both reduce the attacker to the no-information level. Their accuracy of about
0.45 is simply the camera's share of the test set, because the attacker answers "camera"
for almost every trace, and their balanced accuracy is 0.20. S2 gets there with 27% less
padding than constant rate. In exchange it adds about half a second of mean delay and
drops about 3% of payload at the TTL. This reproduces the paper's finding on real IoT
traffic: DP shaping defeats a practical classifier with less bandwidth than
constant-rate shaping. As in the paper, the claim rests on the measured attack, not on
the formal bound. ε_T = 1 corresponds to ε ≤ 12 per 6-second trace.

### 3.3 Why one global ΔW is expensive

Under S2 every device is padded at about 11.3 Mbit/s, whatever its own traffic
(Table 4). When the queue is nearly empty, which is most of the time for quiet devices,
each 500 ms release sends max(0, noise), whose mean is σ/√(2π) ≈ 0.4σ. With σ = 1.78 MB
this predicts 11.3 Mbit/s, matching the measurement. The smart plug averages 7.4 kbit/s
and is padded at 11.5 Mbit/s, about 1,550 times its own traffic. For the vacuum the ratio
exceeds 10,000. This is the waste the extension targets, now measured on real traffic.

### 3.4 Per-device ΔW: cheap for quiet devices, but the noise identifies the device

Per-device ΔW cuts padding for the Echo Dot, plug and vacuum by 82%, 93% and 99%
(Table 4). The aggregate overhead improves by only 28% (47.9× to 34.4×) because it is
weighted by bytes. The camera and doorbell carry 98.6% of the original traffic, and the
camera's own ΔW (339 KB) is no smaller than the global one (335 KB).

The leak beyond NetShaper's own scope is large. Balanced accuracy rises to 0.75, the
same as with no shaping (0.74) within split-to-split variation. For the quiet devices S3 is more identifying than
no defense at all: vacuum recall goes from 0.39 to 0.94, and Echo Dot recall from 0.48
to 0.80. The reason is that σ is public under the threat model, and the spread of the
shaped burst sizes reveals it. The quiet devices have σ of 21 KB, 121 KB and 308 KB, far
from each other and from the heavy devices (1.6–1.8 MB). The noise level is therefore a
cleaner fingerprint than the devices' own traffic.

This does not contradict S3's formal guarantee. S3 protects which interaction a device
performed, and device identity is public under NetShaper's threat model to begin with,
not something S3 chose to give away (DP_ANALYSIS.md, Section 6.1). Device
identification measures what lies beyond that guarantee rather than what it fails to
deliver, and the result shows that this extra leak is large for quiet devices.

The camera and doorbell point to a way out. Their ΔW differ by only 10% (339 KB and
308 KB), and under S3 the attacker cannot separate them. Doorbell recall is 0.10, almost
as low as under global S2 (0.05). Devices that share a noise scale hide each other.

### 3.5 Tiers: the attacker learns the tier, and nothing more

S4 turns that observation into a design: devices in a tier share σ, so the noise no
longer separates them. The measured balanced accuracy is 0.40. That is exactly what an
attacker gets by identifying the tier and then guessing the most common device in it:
two devices recognized, three never (2/5). Plain accuracy hides this. S4's 0.63 looks
close to S3's 0.72, but S4 completely hides three of the five devices, while S3 hides
only the doorbell.

The configured three tiers act as two. The heavy tier (camera, 354 KB) and the medium
tier (doorbell, Echo Dot, vacuum; 325 KB) differ by only 9% in ΔW, so the attacker
cannot tell them apart. In effect the grouping is {camera, doorbell, Echo Dot, vacuum}
and {plug}. Two consequences:

- The plug is alone in its tier and is always identified (recall 1.00). A one-device
  tier hides nothing about which device it is.
- The Echo Dot and the vacuum are padded at the doorbell's scale (10.8 and 11.1 Mbit/s),
  so they save nothing compared with S2.

Overall, S4 recovers 64% of the padding S3 saves over S2 (30.4 GB to 25.0 GB, against
30.4 GB to 21.9 GB).

Grouping devices by their ΔW works better. We ran an alternative, **S4′**, through the
same pipeline, with heavy = {camera, doorbell} (ΔW 339 KB) and light = {Echo Dot, plug,
vacuum} (ΔW 55 KB):

| Strategy | Balanced acc. (10 splits) | Accuracy (10 splits) | Overhead | Total padding | Share of S3's saving |
|---|---:|---:|---:|---:|---:|
| S2 global | 0.196 ± 0.005 | 0.427 ± 0.023 | 47.88× | 30.4 GB | 0% |
| S4 heavy / medium / light | 0.398 ± 0.005 | 0.633 ± 0.025 | 39.34× | 25.0 GB | 64% |
| S4′ heavy / light, by ΔW | 0.395 ± 0.006 | 0.633 ± 0.022 | 36.30× | 23.1 GB | 86% |
| S3 per device | 0.746 ± 0.016 | 0.720 ± 0.028 | 34.44× | 21.9 GB | 100% |

S4′ leaks the same amount as S4, since the attacker learns only heavy or light, but it
pads less: each of the three quiet devices is padded at about 1.9 Mbit/s instead of
about 11 Mbit/s. Under S4′ the plug is still labeled correctly 98% of the time, but only
because it is the most common device in the light tier, so "plug" is the attacker's
default answer for any light-tier trace. The Echo Dot and vacuum are labeled correctly
0–1% of the time.

Two design rules follow:

1. **Privacy can be read off the tier map.** When the padding dominates the devices' own
   traffic, as it does here, the attacker learns the tier and can only guess within it.
   Balanced accuracy is then about the number of distinguishable tiers divided by the
   number of devices.
2. **Cost follows the largest ΔW in each tier.** Devices with similar ΔW should share a
   tier, and each tier needs more than one device to hide anything.

Where to draw the tier boundaries is then an explicit, measurable choice between
bandwidth and how many devices each device hides among. This is the kind of tunable
trade-off NetShaper exposes, applied to a domain the paper did not study.

### 3.6 What the shapers actually protect: the action

Section 3.4 shows that per-device ΔW gives away the device. Table 5 shows what it keeps.
Unshaped, a device's action is clearly visible: the attacker closes 45% of the gap between
guessing and perfect, and 71% for the doorbell. Under every shaper, including the cheapest
DP configuration, that advantage falls to zero.

This reframes the comparison. On the secret NetShaper is built to hide — what the
application did, not which application it is — S3 at 34.4× overhead does as well as
constant-rate at 65.9× and as well as global ΔW at 47.9×. The strategies differ on one axis
only: whether they also hide *which device* is speaking, which NetShaper's mechanism was
never built to do. Under the paper's threat model device identity is public by design,
not a question a deployment settles for itself. Everything that follows is therefore
about a property beyond NetShaper's own promise, and about what a deployer who wants it
anyway would have to pay:

- **Against a local Wi-Fi observer**, device identity leaks through MAC addresses and
  vendor prefixes regardless, which is the situation NetShaper already assumes. Per-device
  ΔW delivers the paper's actual guarantee and is the cheapest configuration we measured.
- **Against an observer past the home gateway**, such as an ISP, device identity may not
  otherwise be visible. A deployer who wants to hide it is asking for more than the
  mechanism promises, and would need tiers (Section 3.5) or one global ΔW, at 5% to 39%
  more padding than per-device ΔW.

One consequence is worth stating, because it rules out the obvious first instinct. Raising
the noise does not address the device leak: that leak comes from the *relative* sizes of
the per-device σ, and spending a smaller ε multiplies every σ by the same factor, leaving
the ratios — and so the fingerprint — intact, while multiplying the padding. Nor is there
anything left to buy on the action side, where ε_T = 1 already reaches chance. More noise
is not a substitute for shared noise, which is what tiers provide.

### 3.7 Latency and loss

Every DP strategy adds 0.53–0.55 s of mean delay, mostly from the 500 ms release
interval: bytes wait for the next release, and wait longer when the noise is negative.
That is acceptable for camera uploads and telemetry but noticeable for interactive
actions such as a voice response or switching a plug. Between 3.4% and 4.4% of payload
waits longer than W = 2 s and is dropped by the TTL. A real tunnel would retransmit
those bytes, adding delay that the simulator does not model. S4 and S4′ drop exactly the
same fraction (4.39%) despite different ΔW, which suggests that the differences in
dropped payload between strategies come from the noise draws rather than from the
strategy. Constant rate avoids both costs only because its rate is set to the dataset's
peak.

---

## 4. Limitations

- **The action evaluation reaches a floor, and covers four devices.** Every shaper sits at
  chance, so Table 5 cannot rank one strategy above another. It establishes only that each
  is sufficient at ε_T = 1 against this attacker; a stronger attacker, finer-grained
  actions, or a longer observation window could separate them. The vacuum is excluded
  because each of its actions has only three captures, and the Echo Dot contributes a
  two-way choice (chance 0.50). Action labels are the dataset's controlled interactions,
  taken from folder names, not verified from traffic content.
- **Class imbalance.** The classes were not capped (18.7 : 1 between camera and vacuum).
  Balanced accuracy compensates. Capping would make 0.20 the no-information level but
  would leave the vacuum with only 88 traces.
- **A single attacker.** A random forest on 65 features. The paper's CNN and TCN
  attackers may extract more, so our accuracies are lower bounds on what a stronger
  adversary achieves.
- **ΔW estimates are noisy and in-sample.** For devices and tiers, ΔW is the 99th
  percentile of only 400 sampled pairs. The plug's value came out at 22.8 KB as a device
  (S3) and 15.0 KB as a one-device tier (S4), from the same traces. ΔW and the CR rate
  are also computed on the data being evaluated, which assumes the deployer knows the
  traffic distribution. By construction, 1% of pairs fall outside the neighbor relation.
- **Loose accounting.** Basic composition (ε ≤ 12 per 6-second trace) overstates the
  loss compared with Rényi-DP, and the loss grows across consecutive windows of a longer
  observation.
- **Simulation.** Shaping runs on 100 ms bins, not in a live tunnel, so there is no
  per-packet overhead and no retransmission of dropped bytes. Each result is a single
  draw of the shaping noise: the ten splits vary the train and test captures, not the
  noise.
