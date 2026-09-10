# Formal privacy analysis -- DP traffic shaping (shapers 2 & 3)

This follows NetShaper (Sabzi et al., USENIX Security 2024, Sec 3 and
Appendix C). We restate the parts our simulator implements and note exactly
where we simplify.

## 1. What is protected

The adversary observes the *shape* of tunnel traffic -- bytes per bin over
time -- and tries to infer the device event. DP makes two neighboring
streams (two events whose traffic differs by at most Delta_W over any window
W) indistinguishable from the observed shape.

## 2. Neighboring definition (paper Def. 1)

Represent a stream over a window [t, t+W) at granularity T as the sequence
of per-interval burst lengths. Two streams S, S' are neighbors if, over
*every* window of length W, the L1 distance between their burst sequences
is at most Delta_W:

    max_{windows}  || S_{tw,W} - S'_{tw,W} ||_1  <=  Delta_W

We estimate Delta_W as the 99th percentile of pairwise window distances in
the dataset -- the paper's own recipe (their Sec 5.1 used Delta_T = 2.5MB
"which covers 99th %ile of the distances").

## 3. The DP query and its sensitivity (paper Prop. 1)

Every interval T, the mechanism measures the buffering-queue length L. A TTL
drops any bytes older than W (Assumption 1: "all bytes enqueued prior to or
at time t are transmitted by time t+W"). Under that assumption the paper
proves the query sensitivity is bounded by the neighboring distance:

    Delta_T  <=  Delta_W        (Proposition 1)

Our simulator enforces Assumption 1 literally: the queue flush in
shaper2_netshaper.py drops chunks once (current_bin - arrival_bin) >= W.

## 4. The mechanism: Gaussian (paper Step 3)

We release L with additive Gaussian noise:

    L_tilde = L + N(0, sigma^2),
    sigma^2 = 2 * Delta_W^2 * ln(1.25 / delta_T) / epsilon_T^2

This is the standard (epsilon_T, delta_T)-DP Gaussian mechanism, giving a
per-interval guarantee on the released queue length -- and, by
post-processing, on the bytes observable on the wire (the packetization is
secret-independent, so it preserves DP -- paper Sec 3.2).

## 5. Composition over a stream

A trace spans N = ceil(tau / T) intervals, so N DP queries are released.
The paper composes these with Renyi-DP for a tight bound (order sqrt(N)
growth). **Our simplification (declared):** we report the per-query
(epsilon_T, delta_T) and N, and use basic sequential composition
(epsilon_total <= N * epsilon_T) as a conservative upper bound. This
overstates the loss relative to the paper but never understates it, which is
the safe direction for a privacy claim.

## 6. Our extension's privacy statement (shaper 3)

shaper3 uses a per-device-class Delta_W instead of one global value. Two
consequences, both quantifiable:

- **Within a class**, the guarantee is identical in form to shaper2:
  (epsilon_T, delta_T)-DP per query with sigma computed from that class's
  (smaller) Delta_W. Quiet devices get less noise for the *same* epsilon.
- **Across classes**, the choice of Delta_W is a public parameter (the paper's
  threat model grants the adversary "knowledge about NetShaper, including its
  shaping strategy and privacy configurations", Sec 2.3). So per-class
  parameters reveal the *class*, not the *event*. This is the same category
  of public leakage the paper already accepts when it states "the number of
  flows is public" (Sec 5). We protect the event within the class and measure
  the cost saving that buys.

## 7. The headline caveat the paper itself raises

There is a large gap between theoretical DP and the parameters needed to
defeat real attacks: the paper defeats SOTA classifiers at epsilon up to
~1000, "too large to offer meaningful theoretical privacy guarantees" but
"sufficient to defeat SOTA attacks" (Sec 5.1). Our evaluation reports the
*empirical* attack accuracy for this reason -- the theoretical epsilon alone
does not tell the practical privacy story.
