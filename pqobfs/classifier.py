"""GFW-style byte-distribution classifier (the Surface 1 detector).

The detectable artifact in a raw ML-KEM public key is the *12-bit coefficient
bias*: each coefficient lives in Z_q with q = 3329 < 4096 = 2^12, so the most
significant bit of every 12-bit coefficient group is 0 unless the coefficient is
>= 2048, which happens with probability (q-2048)/q ~= 0.385. A uniform random
byte string has that bit set with probability 0.5. A censor can therefore:

  * measure the average popcount per byte (a coarse, byte-level signal), and
  * test the distribution of the per-coefficient most-significant bits against
    the uniform Binomial(0.5) expectation (the sharp, structure-aware signal).

``gfw_classify`` combines both and returns ``'biased'`` when the key carries
detectable lattice structure, ``'random'`` otherwise.
"""

from __future__ import annotations

import numpy as np
from scipy.stats import chisquare

# popcount window that a censor treats as "plausibly uniform".
UNIFORM_POPCOUNT_LO = 3.4
UNIFORM_POPCOUNT_HI = 4.6

# p-value below which the coefficient-MSB test rejects the uniform hypothesis.
MSB_P_THRESHOLD = 1e-3

_POPCOUNT_TABLE = np.array([bin(i).count("1") for i in range(256)], dtype=np.float64)


def popcount_per_byte(data: bytes) -> float:
    """Average number of set bits per byte. Uniform random ~= 4.0."""
    if not data:
        return 0.0
    arr = np.frombuffer(data, dtype=np.uint8)
    return float(_POPCOUNT_TABLE[arr].mean())


def chi2_uniformity(data: bytes) -> tuple[float, float]:
    """Chi-squared test for byte-value uniformity. Returns (statistic, p_value)."""
    if not data:
        return 0.0, 1.0
    arr = np.frombuffer(data, dtype=np.uint8)
    counts = np.bincount(arr, minlength=256).astype(np.float64)
    stat, p = chisquare(counts)
    return float(stat), float(p)


def coefficient_msb_bias(data: bytes, ncoeffs: int) -> tuple[float, float]:
    """Fraction of set 12th-bits across packed 12-bit coefficients, and its p-value.

    Tests the observed count of set MSBs against Binomial(ncoeffs, 0.5) via a
    chi-squared goodness-of-fit on {set, unset}. A low p-value means the data
    deviates from uniform 12-bit groups -- the ML-KEM lattice signature.
    """
    bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8), bitorder="little")
    needed = ncoeffs * 12
    if bits.size < needed:
        return 0.5, 1.0
    msb = bits[11:needed:12][:ncoeffs]
    set_count = int(msb.sum())
    frac = set_count / ncoeffs
    expected = ncoeffs / 2.0
    observed = np.array([set_count, ncoeffs - set_count], dtype=np.float64)
    exp = np.array([expected, expected], dtype=np.float64)
    _, p = chisquare(observed, exp)
    return float(frac), float(p)


def gfw_classify(data: bytes, ncoeffs: int | None = None) -> dict:
    """Classify ``data`` as 'random' or 'biased' (detectable lattice structure).

    ``ncoeffs`` is the number of 12-bit coefficients packed at the start of the
    buffer (the coefficient block of an ML-KEM public key). If omitted it is
    inferred as ``len(data)*8//12`` (treat the whole buffer as coefficients).
    """
    if ncoeffs is None:
        ncoeffs = (len(data) * 8) // 12

    popcount = popcount_per_byte(data)
    chi2_stat, chi2_p = chi2_uniformity(data)
    msb_frac, msb_p = coefficient_msb_bias(data, ncoeffs)

    in_uniform_range = UNIFORM_POPCOUNT_LO < popcount < UNIFORM_POPCOUNT_HI
    msb_biased = msb_p < MSB_P_THRESHOLD

    verdict = "biased" if (msb_biased or not in_uniform_range) else "random"

    return {
        "popcount": popcount,
        "in_uniform_range": in_uniform_range,
        "chi2_stat": chi2_stat,
        "chi2_p": chi2_p,
        "msb_set_fraction": msb_frac,
        "msb_p": msb_p,
        "verdict": verdict,
    }
