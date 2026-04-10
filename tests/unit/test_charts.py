"""Unit tests for netstego.stats.charts module.

Tests all chart generation functions and verify PNGs are created correctly.
"""

from pathlib import Path

import pytest

from netstego.stats.charts import (
    chart_detection_accuracy,
    chart_packets_vs_payload,
    chart_redundancy_results,
    chart_throughput_by_payload,
    chart_throughput_comparison,
    chart_timing_breakdown,
    generate_all_charts,
)


# ---------------------------------------------------------------------------
# Fixtures: sample data matching benchmark/monitoring output format
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_pipeline_results() -> list[dict]:
    """Minimal pipeline benchmark results for 2 channels x 2 sizes."""
    return [
        {
            "channel": "icmp",
            "payload_bytes": 1024,
            "ciphertext_bytes": 1068,
            "num_chunks": 1,
            "num_packets": 1,
            "bits_per_packet": 11776,
            "chunk_data_size": 1451,
            "encrypt_ms": 0.2,
            "fragment_ms": 0.05,
            "encode_ms": 0.3,
            "decode_ms": 0.15,
            "reassemble_ms": 0.1,
            "decrypt_ms": 0.1,
            "total_ms": 0.9,
            "throughput_bps": 9102222,
            "throughput_Bps": 1137778,
            "overhead_ratio": 0.039,
            "data_verified": True,
        },
        {
            "channel": "ip-id",
            "payload_bytes": 1024,
            "ciphertext_bytes": 1068,
            "num_chunks": 9,
            "num_packets": 638,
            "bits_per_packet": 16,
            "chunk_data_size": 128,
            "encrypt_ms": 0.2,
            "fragment_ms": 0.1,
            "encode_ms": 250.0,
            "decode_ms": 40.0,
            "reassemble_ms": 0.5,
            "decrypt_ms": 0.1,
            "total_ms": 290.9,
            "throughput_bps": 28148,
            "throughput_Bps": 3519,
            "overhead_ratio": 24.9,
            "data_verified": True,
        },
        {
            "channel": "icmp",
            "payload_bytes": 4096,
            "ciphertext_bytes": 4140,
            "num_chunks": 3,
            "num_packets": 3,
            "bits_per_packet": 11776,
            "chunk_data_size": 1451,
            "encrypt_ms": 0.3,
            "fragment_ms": 0.1,
            "encode_ms": 0.8,
            "decode_ms": 0.4,
            "reassemble_ms": 0.2,
            "decrypt_ms": 0.15,
            "total_ms": 1.95,
            "throughput_bps": 16810256,
            "throughput_Bps": 2101282,
            "overhead_ratio": 0.029,
            "data_verified": True,
        },
        {
            "channel": "ip-id",
            "payload_bytes": 4096,
            "ciphertext_bytes": 4140,
            "num_chunks": 33,
            "num_packets": 2538,
            "bits_per_packet": 16,
            "chunk_data_size": 128,
            "encrypt_ms": 0.3,
            "fragment_ms": 0.2,
            "encode_ms": 1000.0,
            "decode_ms": 150.0,
            "reassemble_ms": 1.0,
            "decrypt_ms": 0.15,
            "total_ms": 1151.65,
            "throughput_bps": 28440,
            "throughput_Bps": 3555,
            "overhead_ratio": 24.8,
            "data_verified": True,
        },
    ]


@pytest.fixture
def sample_redundancy_results() -> list[dict]:
    """Minimal redundancy test results."""
    results = []
    for loss_pct in [10, 20, 30]:
        for i in range(5):
            success = loss_pct < 25 or i < 2
            results.append({
                "channel": "icmp",
                "total_packets": 30,
                "surviving_packets": int(30 * (1 - loss_pct / 100)),
                "loss_rate": loss_pct / 100,
                "unique_chunks": 10,
                "received_unique": 10 if success else 7,
                "duplicates_discarded": 15 if success else 5,
                "reassembly_success": success,
                "data_verified": success,
            })
    return results


@pytest.fixture
def sample_monitoring_metrics() -> list[dict]:
    """Minimal monitoring results metrics."""
    return [
        {"channel": "icmp", "method": "combined", "tp": 8, "fp": 1, "tn": 9, "fn": 2,
         "precision": 0.8889, "recall": 0.8, "f1": 0.8421, "accuracy": 0.85, "fpr": 0.1},
        {"channel": "icmp", "method": "statistical", "tp": 7, "fp": 2, "tn": 8, "fn": 3,
         "precision": 0.7778, "recall": 0.7, "f1": 0.7368, "accuracy": 0.75, "fpr": 0.2},
        {"channel": "ip-id", "method": "combined", "tp": 10, "fp": 0, "tn": 10, "fn": 0,
         "precision": 1.0, "recall": 1.0, "f1": 1.0, "accuracy": 1.0, "fpr": 0.0},
        {"channel": "ip-id", "method": "statistical", "tp": 9, "fp": 1, "tn": 9, "fn": 1,
         "precision": 0.9, "recall": 0.9, "f1": 0.9, "accuracy": 0.9, "fpr": 0.1},
    ]


@pytest.fixture
def benchmark_results(sample_pipeline_results, sample_redundancy_results) -> dict:
    return {
        "pipeline_benchmarks": sample_pipeline_results,
        "redundancy_tests": sample_redundancy_results,
    }


@pytest.fixture
def monitoring_results(sample_monitoring_metrics) -> dict:
    return {
        "parameters": {"n_trials": 10, "n_normal_packets": 100, "stego_payload_bytes": 512},
        "metrics": sample_monitoring_metrics,
    }


# ---------------------------------------------------------------------------
# Individual chart tests
# ---------------------------------------------------------------------------

class TestChartThroughputComparison:
    def test_creates_png(self, tmp_path: Path, sample_pipeline_results: list[dict]) -> None:
        out = chart_throughput_comparison(sample_pipeline_results, tmp_path, payload_size=1024)
        assert out.exists()
        assert out.suffix == ".png"
        assert out.stat().st_size > 1000  # not empty

    def test_filename(self, tmp_path: Path, sample_pipeline_results: list[dict]) -> None:
        out = chart_throughput_comparison(sample_pipeline_results, tmp_path)
        assert out.name == "throughput_comparison.png"


class TestChartTimingBreakdown:
    def test_creates_png(self, tmp_path: Path, sample_pipeline_results: list[dict]) -> None:
        out = chart_timing_breakdown(sample_pipeline_results, tmp_path, payload_size=1024)
        assert out.exists()
        assert out.suffix == ".png"
        assert out.stat().st_size > 1000

    def test_filename(self, tmp_path: Path, sample_pipeline_results: list[dict]) -> None:
        out = chart_timing_breakdown(sample_pipeline_results, tmp_path)
        assert out.name == "timing_breakdown.png"


class TestChartPacketsVsPayload:
    def test_creates_png(self, tmp_path: Path, sample_pipeline_results: list[dict]) -> None:
        out = chart_packets_vs_payload(sample_pipeline_results, tmp_path)
        assert out.exists()
        assert out.suffix == ".png"
        assert out.stat().st_size > 1000

    def test_filename(self, tmp_path: Path, sample_pipeline_results: list[dict]) -> None:
        out = chart_packets_vs_payload(sample_pipeline_results, tmp_path)
        assert out.name == "packets_vs_payload.png"


class TestChartThroughputByPayload:
    def test_creates_png(self, tmp_path: Path, sample_pipeline_results: list[dict]) -> None:
        out = chart_throughput_by_payload(sample_pipeline_results, tmp_path)
        assert out.exists()
        assert out.suffix == ".png"
        assert out.stat().st_size > 1000

    def test_filename(self, tmp_path: Path, sample_pipeline_results: list[dict]) -> None:
        out = chart_throughput_by_payload(sample_pipeline_results, tmp_path)
        assert out.name == "throughput_by_payload.png"


class TestChartDetectionAccuracy:
    def test_creates_png(self, tmp_path: Path, sample_monitoring_metrics: list[dict]) -> None:
        out = chart_detection_accuracy(sample_monitoring_metrics, tmp_path)
        assert out.exists()
        assert out.suffix == ".png"
        assert out.stat().st_size > 1000

    def test_filename(self, tmp_path: Path, sample_monitoring_metrics: list[dict]) -> None:
        out = chart_detection_accuracy(sample_monitoring_metrics, tmp_path)
        assert out.name == "detection_accuracy.png"


class TestChartRedundancyResults:
    def test_creates_png(self, tmp_path: Path, sample_redundancy_results: list[dict]) -> None:
        out = chart_redundancy_results(sample_redundancy_results, tmp_path)
        assert out.exists()
        assert out.suffix == ".png"
        assert out.stat().st_size > 1000

    def test_filename(self, tmp_path: Path, sample_redundancy_results: list[dict]) -> None:
        out = chart_redundancy_results(sample_redundancy_results, tmp_path)
        assert out.name == "redundancy_results.png"


# ---------------------------------------------------------------------------
# generate_all_charts
# ---------------------------------------------------------------------------

class TestGenerateAllCharts:
    def test_all_benchmark_charts(self, tmp_path: Path, benchmark_results: dict) -> None:
        charts_dir = tmp_path / "charts"
        saved = generate_all_charts(benchmark_results, None, charts_dir)
        assert charts_dir.exists()
        # Without monitoring: throughput, timing, packets_vs_payload, throughput_by_payload, redundancy = 5
        assert len(saved) == 5
        for p in saved:
            assert p.exists()
            assert p.suffix == ".png"

    def test_with_monitoring(
        self, tmp_path: Path, benchmark_results: dict, monitoring_results: dict,
    ) -> None:
        charts_dir = tmp_path / "charts"
        saved = generate_all_charts(benchmark_results, monitoring_results, charts_dir)
        # 5 benchmark charts + 1 detection accuracy = 6
        assert len(saved) == 6
        names = {p.name for p in saved}
        assert "detection_accuracy.png" in names

    def test_empty_pipeline(self, tmp_path: Path) -> None:
        charts_dir = tmp_path / "charts"
        saved = generate_all_charts({"pipeline_benchmarks": [], "redundancy_tests": []}, None, charts_dir)
        assert len(saved) == 0

    def test_creates_output_dir(self, tmp_path: Path, benchmark_results: dict) -> None:
        charts_dir = tmp_path / "deep" / "nested" / "charts"
        saved = generate_all_charts(benchmark_results, None, charts_dir)
        assert charts_dir.exists()
        assert len(saved) > 0

    def test_no_redundancy(self, tmp_path: Path, sample_pipeline_results: list[dict]) -> None:
        charts_dir = tmp_path / "charts"
        results = {"pipeline_benchmarks": sample_pipeline_results, "redundancy_tests": []}
        saved = generate_all_charts(results, None, charts_dir)
        names = {p.name for p in saved}
        assert "redundancy_results.png" not in names
        # 4 pipeline charts (no redundancy)
        assert len(saved) == 4
