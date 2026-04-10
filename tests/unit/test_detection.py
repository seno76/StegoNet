"""Unit tests for detection modules."""

import numpy as np
import pytest

from netstego.detection.statistical import (
    chi_squared_uniformity,
    ipd_regularity,
    ks_test_ipd,
    shannon_entropy,
)
from netstego.detection.ml_detector import detect_isolation_forest, extract_features
from netstego.detection.signatures import detect_signatures, scan_for_magic
from netstego.core.fragmentation import MAGIC


class TestChiSquared:
    def test_uniform_distribution(self) -> None:
        # Truly uniform data should not be flagged
        values = list(range(256)) * 10
        result = chi_squared_uniformity(values, alpha=0.05)
        assert not result.is_anomaly

    def test_skewed_distribution(self) -> None:
        # Highly skewed data
        values = [1] * 200 + [2] * 10
        result = chi_squared_uniformity(values, alpha=0.05)
        assert result.is_anomaly

    def test_insufficient_data(self) -> None:
        result = chi_squared_uniformity([1, 2, 3], alpha=0.05)
        assert not result.is_anomaly
        assert "Insufficient" in result.details


class TestKsTest:
    def test_exponential_delays(self) -> None:
        rng = np.random.default_rng(42)
        delays = rng.exponential(scale=0.1, size=200).tolist()
        result = ks_test_ipd(delays, alpha=0.05)
        # Exponential delays should look normal
        assert not result.is_anomaly

    def test_constant_delays(self) -> None:
        # Very regular delays — not exponential
        delays = [0.1] * 200
        result = ks_test_ipd(delays, alpha=0.05)
        assert result.is_anomaly

    def test_insufficient_data(self) -> None:
        result = ks_test_ipd([0.1, 0.2], alpha=0.05)
        assert not result.is_anomaly


class TestEntropy:
    def test_high_entropy(self) -> None:
        # All unique values — max entropy
        values = list(range(1000))
        result = shannon_entropy(values)
        assert result.score > 0.9

    def test_low_entropy(self) -> None:
        values = [1] * 1000
        result = shannon_entropy(values)
        assert result.score < 0.1

    def test_empty(self) -> None:
        result = shannon_entropy([])
        assert result.score == 0.0


class TestIpdRegularity:
    def test_regular_timing(self) -> None:
        delays = [0.1] * 100
        result = ipd_regularity(delays)
        assert result.is_anomaly  # Very low CV

    def test_variable_timing(self) -> None:
        rng = np.random.default_rng(42)
        delays = rng.exponential(scale=0.5, size=100).tolist()
        result = ipd_regularity(delays)
        assert not result.is_anomaly  # High CV


class TestMLDetector:
    def test_extract_features_shape(self) -> None:
        values = list(range(20))
        timestamps = [i * 0.1 for i in range(20)]
        features = extract_features(values, timestamps)
        assert features.shape == (20, 9)

    def test_extract_features_empty(self) -> None:
        features = extract_features([], [])
        assert features.shape == (0, 9)

    def test_isolation_forest_normal(self) -> None:
        rng = np.random.default_rng(42)
        features = rng.normal(size=(100, 9))
        result = detect_isolation_forest(features, contamination=0.05)
        assert result.anomaly_ratio < 0.2

    def test_isolation_forest_insufficient(self) -> None:
        features = np.array([[1, 2, 3, 4, 5, 6, 7, 8, 9]])
        result = detect_isolation_forest(features, contamination=0.05)
        assert not result.is_anomaly
        assert "Insufficient" in result.details


class TestSignatures:
    def test_detect_magic(self) -> None:
        payloads = [b"normal data", MAGIC + b"chunk data", b"more normal"]
        matches = scan_for_magic(payloads)
        assert len(matches) == 1
        assert matches[0].packet_index == 1

    def test_no_magic(self) -> None:
        payloads = [b"normal", b"data", b"here"]
        matches = scan_for_magic(payloads)
        assert len(matches) == 0

    def test_detect_all(self) -> None:
        payloads = [b"clean payload"]
        matches = detect_signatures(payloads)
        assert len(matches) == 0
