"""Statistical detection methods for covert channel analysis.

Implements:
    - Chi-squared test for field value distributions
    - Kolmogorov-Smirnov test for inter-packet delay (IPD)
    - Shannon entropy calculation
    - Inter-packet delay analysis
"""

import math
from dataclasses import dataclass

import numpy as np
from scipy import stats as sp_stats


@dataclass
class StatResult:
    """Result of a statistical test."""

    method: str
    metric: str
    score: float
    p_value: float | None
    threshold: float
    is_anomaly: bool
    details: str = ""


def chi_squared_uniformity(values: list[int], alpha: float = 0.05) -> StatResult:
    """Chi-squared test for uniformity of field values.

    Tests whether the distribution of values deviates significantly
    from a uniform distribution, which may indicate steganographic encoding.

    Args:
        values: List of integer field values (e.g., IP IDs).
        alpha: Significance level.

    Returns:
        StatResult with test outcome.
    """
    if len(values) < 10:
        return StatResult(
            method="chi_squared",
            metric="uniformity",
            score=0.0,
            p_value=1.0,
            threshold=alpha,
            is_anomaly=False,
            details="Insufficient data (< 10 samples)",
        )

    arr = np.array(values)
    # Bin values into 256 buckets
    n_bins = min(256, len(set(values)))
    observed, bin_edges = np.histogram(arr, bins=n_bins)
    expected = np.full_like(observed, fill_value=len(values) / n_bins, dtype=float)

    chi2, p_value = sp_stats.chisquare(observed, f_exp=expected)

    return StatResult(
        method="chi_squared",
        metric="uniformity",
        score=float(chi2),
        p_value=float(p_value),
        threshold=alpha,
        is_anomaly=p_value < alpha,
        details=f"chi2={chi2:.4f}, p={p_value:.6f}, bins={n_bins}",
    )


def ks_test_ipd(delays: list[float], alpha: float = 0.05) -> StatResult:
    """Kolmogorov-Smirnov test for inter-packet delay distribution.

    Tests whether IPD follows an exponential distribution (typical for
    normal traffic). Steganographic traffic often has more regular timing.

    Args:
        delays: List of inter-packet delays in seconds.
        alpha: Significance level.

    Returns:
        StatResult with test outcome.
    """
    if len(delays) < 10:
        return StatResult(
            method="ks_test",
            metric="ipd_distribution",
            score=0.0,
            p_value=1.0,
            threshold=alpha,
            is_anomaly=False,
            details="Insufficient data (< 10 samples)",
        )

    arr = np.array(delays)
    arr = arr[arr > 0]  # filter zero delays
    if len(arr) < 5:
        return StatResult(
            method="ks_test",
            metric="ipd_distribution",
            score=0.0,
            p_value=1.0,
            threshold=alpha,
            is_anomaly=False,
            details="Insufficient positive delays",
        )

    mean_delay = float(np.mean(arr))
    stat, p_value = sp_stats.kstest(arr, "expon", args=(0, mean_delay))

    return StatResult(
        method="ks_test",
        metric="ipd_distribution",
        score=float(stat),
        p_value=float(p_value),
        threshold=alpha,
        is_anomaly=p_value < alpha,
        details=f"D={stat:.4f}, p={p_value:.6f}, mean_ipd={mean_delay:.4f}s",
    )


def shannon_entropy(values: list[int]) -> StatResult:
    """Calculate Shannon entropy of field values.

    High entropy close to theoretical maximum may indicate
    steganographic encoding (random-looking data).

    Args:
        values: List of integer field values.

    Returns:
        StatResult with entropy score.
    """
    if not values:
        return StatResult(
            method="entropy",
            metric="shannon",
            score=0.0,
            p_value=None,
            threshold=0.0,
            is_anomaly=False,
            details="No data",
        )

    n = len(values)
    freq: dict[int, int] = {}
    for v in values:
        freq[v] = freq.get(v, 0) + 1

    entropy = 0.0
    for count in freq.values():
        p = count / n
        if p > 0:
            entropy -= p * math.log2(p)

    # Max possible entropy for the number of unique values
    max_entropy = math.log2(n) if n > 1 else 1.0
    # Normalized entropy (0 to 1)
    normalized = entropy / max_entropy if max_entropy > 0 else 0.0

    # High normalized entropy (>0.95) is suspicious
    threshold = 0.95
    return StatResult(
        method="entropy",
        metric="shannon",
        score=normalized,
        p_value=None,
        threshold=threshold,
        is_anomaly=normalized > threshold,
        details=f"H={entropy:.4f} bits, normalized={normalized:.4f}, unique={len(freq)}",
    )


def ipd_regularity(delays: list[float]) -> StatResult:
    """Measure regularity of inter-packet delays.

    Low coefficient of variation (CV) suggests artificially timed traffic.

    Args:
        delays: List of inter-packet delays in seconds.

    Returns:
        StatResult with CV score.
    """
    if len(delays) < 5:
        return StatResult(
            method="ipd_regularity",
            metric="coefficient_of_variation",
            score=0.0,
            p_value=None,
            threshold=0.0,
            is_anomaly=False,
            details="Insufficient data",
        )

    arr = np.array(delays)
    mean = float(np.mean(arr))
    std = float(np.std(arr))

    cv = std / mean if mean > 0 else 0.0

    # Very low CV (<0.1) suggests regular timing (possible stego)
    threshold = 0.1
    return StatResult(
        method="ipd_regularity",
        metric="coefficient_of_variation",
        score=cv,
        p_value=None,
        threshold=threshold,
        is_anomaly=cv < threshold,
        details=f"CV={cv:.4f}, mean={mean:.4f}s, std={std:.4f}s",
    )
