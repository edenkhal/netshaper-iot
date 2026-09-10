"""
shaper2_netshaper.py -- Shaper 2: NetShaper's DP shaping, faithfully simulated.

This reproduces the mechanism of Sec 3 of the paper (Sabzi et al., USENIX
Security 2024), at the granularity their own simulator uses:

  1. Application bytes accumulate in a buffering queue Q.        (their step 1)
  2. Every DP shaping interval T, a DP QUERY measures the queue
     length L with the GAUSSIAN MECHANISM:
         L_tilde = L + N(0, sigma^2),
         sigma^2 = 2 * DeltaW^2 * ln(1.25/delta_T) / epsilon_T^2  (their step 2-3)
  3. Transmit R = min(max(0, L_tilde), L) real bytes; pad with
     D = max(0, L_tilde) - R dummy bytes.                        (their Sec 4.1:
     "R is the minimum of L_tilde and the application bytes available...
      and D = L_tilde - R")
  4. TTL: bytes older than W are dropped from Q -- this enforces
     Assumption 1 ("all bytes enqueued prior to or at time t are
     transmitted by time t + W"), which is what bounds the
     sensitivity: Delta_T <= Delta_W (their Proposition 1).

Overhead semantics straight from the paper: "when the noise is positive,
dummy bytes need to be sent, incurring higher bandwidth overhead; when the
noise is negative, fewer bytes are sent and the unsent bytes accumulated in
the buffering queue incur a latency overhead" (Sec 3.2).

Simplification vs. the paper (declared in DP_ANALYSIS.md): the paper
composes per-query losses with Renyi-DP; we report per-query (eps_T,
delta_T) and the number of queries N, and use basic sequential composition
(N * eps_T) as a conservative upper bound.
"""

import math                                   # for the Gaussian sigma formula
import random                                 # noise draws
from config import (BIN_MS, T_BINS, W_INTERVALS, EPSILON_T, DELTA_T, SEED)

# Module-level RNG with fixed seed: reproducible experiment
_rng = random.Random(SEED + 2)                # +2 so shapers don't share draws


def gaussian_sigma(delta_w: float, epsilon_t: float = EPSILON_T,
                   delta_t: float = DELTA_T) -> float:
    """
    The Gaussian-mechanism noise scale, exactly the paper's formula:
        sigma^2 = 2 * DeltaW^2 * ln(1.25/delta_T) / epsilon_T^2
    """
    return math.sqrt(2 * (delta_w ** 2) * math.log(1.25 / delta_t)) / epsilon_t


def dp_shape_trace(bins: list[int], delta_w: float) -> dict:
    """
    Core NetShaper simulation over one trace. Shared by shaper2 (global
    Delta_W) and shaper3 (per-class Delta_W) -- only the sensitivity differs.

    Returns the same dict contract as every shaper.
    """
    sigma = gaussian_sigma(delta_w)           # noise scale for this Delta_W
    w_bins = W_INTERVALS * T_BINS             # the TTL window W, in bins

    queue = []                                # FIFO of (arrival_bin, nbytes)
    shaped = []                               # observed bytes per bin (output)
    dummy_total = 0                           # bandwidth overhead accumulator
    dropped_total = 0                         # bytes flushed by the W TTL
    delays = []                               # per-byte-chunk delays for latency

    n_queries = 0                             # DP query counter (for accounting)
    for b, incoming in enumerate(bins):
        # -- enqueue this bin's application bytes --
        if incoming > 0:
            queue.append([b, incoming])       # list (mutable) for partial dequeue

        # -- TTL flush: enforce Assumption 1 (bytes older than W are dropped) --
        while queue and (b - queue[0][0]) >= w_bins:
            dropped_total += queue[0][1]      # count what the TTL discards
            queue.pop(0)

        # Shaping happens only at interval boundaries (every T bins);
        # between queries nothing is transmitted (the tunnel sends shaped
        # bursts once per interval -- their Figure 1)
        if (b + 1) % T_BINS != 0:
            shaped.append(0)                  # no transmission this bin
            continue

        # -- the DP query on the queue length (their step 2+3) --
        L = sum(chunk[1] for chunk in queue)              # true queue length
        L_tilde = L + _rng.gauss(0, sigma)                # Gaussian mechanism
        n_queries += 1
        to_send = max(0.0, L_tilde)                       # can't send negative

        # -- split into real payload R and dummy padding D (their Sec 4.1) --
        R = min(to_send, L)                               # real bytes sent now
        D = to_send - R                                   # padding
        dummy_total += D

        # -- dequeue R bytes FIFO, recording each chunk's queueing delay --
        remaining = R
        while remaining > 0 and queue:
            arrival, nbytes = queue[0]
            take = min(nbytes, remaining)
            delays.append((b - arrival, take))            # (delay_bins, weight)
            remaining -= take
            if take == nbytes:
                queue.pop(0)                              # chunk fully sent
            else:
                queue[0][1] -= take                       # partial send

        # The wire shows one burst of size R + D at this interval boundary
        shaped.append(R + D)

    # Weighted mean delay of transmitted payload bytes, converted to ms
    total_w = sum(w for _, w in delays)
    mean_delay_bins = (sum(d * w for d, w in delays) / total_w) if total_w else 0.0

    return {
        "shaped_bins": shaped,
        "dummy_bytes": int(dummy_total),
        "delay_ms": mean_delay_bins * BIN_MS,
        "dropped_bytes": int(dropped_total),
        "epsilon_note": (f"({EPSILON_T},{DELTA_T})-DP per query, N={n_queries} "
                         f"queries, sigma={sigma:.0f}B, DeltaW={delta_w:.0f}B"),
    }


def shape(bins: list[int], label: str, dataset_stats: dict) -> dict:
    """Shaper 2: NetShaper with ONE GLOBAL Delta_W for all devices."""
    # The paper sets one Delta_W per application domain; a uniform smart-home
    # deployment must cover the noisiest device (the camera), so the global
    # Delta_W is large -- and so is the noise added to every quiet device.
    # That mismatch is exactly what shaper3 attacks.
    return dp_shape_trace(bins, delta_w=dataset_stats["delta_w_global"])
