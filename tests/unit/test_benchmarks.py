"""Unit tests for netstego.benchmarks module.

Tests pipeline benchmarks, redundancy tests, traffic generators,
and DetectionMetrics dataclass.
"""

import os
from pathlib import Path

import pytest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.packet import Raw

from netstego.benchmarks import (
    CHANNELS,
    DetectionMetrics,
    generate_normal_dns,
    generate_normal_icmp,
    generate_normal_ip_id,
    generate_normal_tcp_syn,
    generate_normal_tcp_ts,
    generate_stego_traffic,
    run_all_benchmarks,
    run_all_monitoring,
    run_pipeline,
    run_redundancy_test,
)
from netstego.core.crypto import generate_key


@pytest.fixture
def key(tmp_path: Path) -> bytes:
    return generate_key(tmp_path / "bench.key")


# ---------------------------------------------------------------------------
# run_pipeline
# ---------------------------------------------------------------------------

class TestRunPipeline:
    def test_icmp_roundtrip(self, key: bytes) -> None:
        result = run_pipeline("icmp", b"hello world", key)
        assert result["data_verified"] is True
        assert result["channel"] == "icmp"
        assert result["payload_bytes"] == 11
        assert result["num_packets"] >= 1
        assert result["total_ms"] > 0
        assert result["throughput_Bps"] > 0

    def test_ip_id_roundtrip(self, key: bytes) -> None:
        result = run_pipeline("ip-id", os.urandom(64), key)
        assert result["data_verified"] is True
        assert result["channel"] == "ip-id"
        assert result["num_packets"] > 1

    def test_tcp_isn_roundtrip(self, key: bytes) -> None:
        result = run_pipeline("tcp-isn", os.urandom(64), key)
        assert result["data_verified"] is True

    def test_dns_roundtrip(self, key: bytes) -> None:
        result = run_pipeline("dns", os.urandom(64), key)
        assert result["data_verified"] is True

    def test_tcp_ts_roundtrip(self, key: bytes) -> None:
        result = run_pipeline("tcp-ts", os.urandom(64), key)
        assert result["data_verified"] is True

    def test_all_timing_fields_present(self, key: bytes) -> None:
        result = run_pipeline("icmp", b"test", key)
        for field in [
            "encrypt_ms", "fragment_ms", "encode_ms",
            "decode_ms", "reassemble_ms", "decrypt_ms",
            "total_ms", "throughput_bps", "throughput_Bps",
            "overhead_ratio",
        ]:
            assert field in result
            assert isinstance(result[field], (int, float))

    def test_large_payload(self, key: bytes) -> None:
        data = os.urandom(4096)
        result = run_pipeline("icmp", data, key)
        assert result["data_verified"] is True
        assert result["payload_bytes"] == 4096


# ---------------------------------------------------------------------------
# run_redundancy_test
# ---------------------------------------------------------------------------

class TestRunRedundancyTest:
    def test_zero_loss_succeeds(self, key: bytes) -> None:
        result = run_redundancy_test("icmp", os.urandom(256), key, loss_rate=0.0)
        assert result["reassembly_success"] is True
        assert result["data_verified"] is True
        assert result["duplicates_discarded"] > 0

    def test_high_loss_may_fail(self, key: bytes) -> None:
        result = run_redundancy_test("icmp", os.urandom(256), key, loss_rate=0.95)
        # At 95% loss with 3x redundancy, likely fails
        assert "reassembly_success" in result
        assert "data_verified" in result

    def test_result_fields(self, key: bytes) -> None:
        # Use larger payload so multiple chunks are created
        result = run_redundancy_test("icmp", os.urandom(4096), key, loss_rate=0.1)
        assert "total_packets" in result
        assert "surviving_packets" in result
        assert "loss_rate" in result
        assert "unique_chunks" in result
        assert "received_unique" in result
        assert result["total_packets"] > result["unique_chunks"]  # 3x redundancy


# ---------------------------------------------------------------------------
# run_all_benchmarks
# ---------------------------------------------------------------------------

class TestRunAllBenchmarks:
    def test_minimal_run(self, key: bytes) -> None:
        """Run with minimal params to keep test fast."""
        result = run_all_benchmarks(
            payload_sizes=[64],
            channels=["icmp"],
            repeat=1,
        )
        assert "pipeline_benchmarks" in result
        assert "redundancy_tests" in result
        assert len(result["pipeline_benchmarks"]) == 1
        assert result["pipeline_benchmarks"][0]["channel"] == "icmp"
        assert result["pipeline_benchmarks"][0]["payload_bytes"] == 64
        assert result["pipeline_benchmarks"][0]["data_verified"] is True

    def test_multiple_channels_and_sizes(self, key: bytes) -> None:
        result = run_all_benchmarks(
            payload_sizes=[64, 256],
            channels=["icmp", "ip-id"],
            repeat=1,
        )
        assert len(result["pipeline_benchmarks"]) == 4  # 2 channels x 2 sizes

    def test_redundancy_only_for_icmp(self, key: bytes) -> None:
        result = run_all_benchmarks(
            payload_sizes=[64],
            channels=["tcp-isn"],
            repeat=1,
        )
        assert len(result["redundancy_tests"]) == 0  # no ICMP, no redundancy tests

    def test_redundancy_included_for_icmp(self, key: bytes) -> None:
        result = run_all_benchmarks(
            payload_sizes=[64],
            channels=["icmp"],
            repeat=1,
        )
        assert len(result["redundancy_tests"]) > 0

    def test_averaging_with_repeat(self, key: bytes) -> None:
        result = run_all_benchmarks(
            payload_sizes=[64],
            channels=["icmp"],
            repeat=3,
        )
        # Still only 1 result (averaged)
        assert len(result["pipeline_benchmarks"]) == 1


# ---------------------------------------------------------------------------
# Normal traffic generators
# ---------------------------------------------------------------------------

class TestNormalTrafficGenerators:
    def test_icmp_generates_correct_count(self) -> None:
        pkts = generate_normal_icmp("10.0.0.1", 20)
        assert len(pkts) == 20
        for p in pkts:
            assert p.haslayer(ICMP)
            assert p[ICMP].type == 8  # Echo Request

    def test_icmp_sequential_ip_ids(self) -> None:
        pkts = generate_normal_icmp("10.0.0.1", 10)
        ip_ids = [p[IP].id for p in pkts]
        # Should be roughly sequential (delta 1-3)
        for i in range(1, len(ip_ids)):
            delta = (ip_ids[i] - ip_ids[i - 1]) % 65535
            assert 1 <= delta <= 3

    def test_tcp_syn_generates_syn_flags(self) -> None:
        pkts = generate_normal_tcp_syn("10.0.0.1", 15)
        assert len(pkts) == 15
        for p in pkts:
            assert p.haslayer(TCP)
            assert p[TCP].flags & 0x02  # SYN bit set

    def test_dns_generates_queries(self) -> None:
        pkts = generate_normal_dns("10.0.0.1", 10)
        assert len(pkts) == 10
        for p in pkts:
            assert p.haslayer(DNS)
            assert p.haslayer(DNSQR)
            assert p[UDP].dport == 53

    def test_dns_uses_real_domains(self) -> None:
        pkts = generate_normal_dns("10.0.0.1", 5)
        for p in pkts:
            qname = p[DNSQR].qname
            if isinstance(qname, bytes):
                qname = qname.decode()
            # Should contain real domain components
            assert "." in qname

    def test_tcp_ts_monotonic_tsval(self) -> None:
        pkts = generate_normal_tcp_ts("10.0.0.1", 20)
        assert len(pkts) == 20
        tsvals = []
        for p in pkts:
            for opt_name, opt_val in p[TCP].options:
                if opt_name == "Timestamp":
                    tsvals.append(opt_val[0])
                    break
        # TSval should be monotonically increasing
        for i in range(1, len(tsvals)):
            assert tsvals[i] > tsvals[i - 1]

    def test_ip_id_strictly_incremental(self) -> None:
        pkts = generate_normal_ip_id("10.0.0.1", 10)
        assert len(pkts) == 10
        ip_ids = [p[IP].id for p in pkts]
        for i in range(1, len(ip_ids)):
            assert (ip_ids[i] - ip_ids[i - 1]) % 65535 == 1

    def test_all_generators_set_timestamps(self) -> None:
        for gen in [
            generate_normal_icmp,
            generate_normal_tcp_syn,
            generate_normal_dns,
            generate_normal_tcp_ts,
            generate_normal_ip_id,
        ]:
            pkts = gen("10.0.0.1", 5)
            times = [float(p.time) for p in pkts]
            # Timestamps should be increasing
            for i in range(1, len(times)):
                assert times[i] > times[i - 1]


# ---------------------------------------------------------------------------
# Stego traffic generator
# ---------------------------------------------------------------------------

class TestStegoTrafficGenerator:
    def test_generates_packets(self, key: bytes) -> None:
        pkts = generate_stego_traffic("icmp", "10.0.0.1", key, payload_size=128)
        assert len(pkts) >= 1
        for p in pkts:
            assert p.haslayer(IP)

    def test_different_channels(self, key: bytes) -> None:
        for ch in CHANNELS:
            pkts = generate_stego_traffic(ch, "10.0.0.1", key, payload_size=64)
            assert len(pkts) >= 1

    def test_timestamps_set(self, key: bytes) -> None:
        pkts = generate_stego_traffic("icmp", "10.0.0.1", key)
        times = [float(p.time) for p in pkts]
        for i in range(1, len(times)):
            assert times[i] > times[i - 1]


# ---------------------------------------------------------------------------
# DetectionMetrics
# ---------------------------------------------------------------------------

class TestDetectionMetrics:
    def test_perfect_detection(self) -> None:
        m = DetectionMetrics(channel="icmp", method="combined", tp=10, fp=0, tn=10, fn=0)
        assert m.precision == 1.0
        assert m.recall == 1.0
        assert m.f1 == 1.0
        assert m.accuracy == 1.0
        assert m.fpr == 0.0

    def test_no_detection(self) -> None:
        m = DetectionMetrics(channel="icmp", method="combined", tp=0, fp=0, tn=10, fn=10)
        assert m.precision == 0.0
        assert m.recall == 0.0
        assert m.f1 == 0.0
        assert m.accuracy == 0.5

    def test_all_false_positives(self) -> None:
        m = DetectionMetrics(channel="icmp", method="combined", tp=0, fp=10, tn=0, fn=0)
        assert m.precision == 0.0
        assert m.fpr == 1.0

    def test_mixed_results(self) -> None:
        m = DetectionMetrics(channel="icmp", method="combined", tp=7, fp=2, tn=8, fn=3)
        assert 0 < m.precision < 1
        assert 0 < m.recall < 1
        assert 0 < m.f1 < 1

    def test_to_dict(self) -> None:
        m = DetectionMetrics(channel="icmp", method="combined", tp=5, fp=1, tn=9, fn=5)
        d = m.to_dict()
        assert d["channel"] == "icmp"
        assert d["method"] == "combined"
        assert d["tp"] == 5
        assert "precision" in d
        assert "recall" in d
        assert "f1" in d
        assert "accuracy" in d
        assert "fpr" in d

    def test_zero_division_safety(self) -> None:
        m = DetectionMetrics(channel="x", method="y", tp=0, fp=0, tn=0, fn=0)
        assert m.precision == 0.0
        assert m.recall == 0.0
        assert m.f1 == 0.0
        assert m.accuracy == 0.0
        assert m.fpr == 0.0


# ---------------------------------------------------------------------------
# run_all_monitoring (minimal)
# ---------------------------------------------------------------------------

class TestRunAllMonitoring:
    def test_minimal_run(self) -> None:
        result = run_all_monitoring(
            channels=["icmp"],
            n_trials=2,
            n_normal_pkts=20,
            stego_payload=64,
        )
        assert "parameters" in result
        assert "metrics" in result
        assert result["parameters"]["n_trials"] == 2
        # 1 channel x (1 combined + 3 per-method + 1 ml_supervised) = 5 metric entries
        assert len(result["metrics"]) == 5

    def test_metrics_have_required_fields(self) -> None:
        result = run_all_monitoring(
            channels=["icmp"],
            n_trials=1,
            n_normal_pkts=20,
            stego_payload=64,
        )
        for m in result["metrics"]:
            assert "channel" in m
            assert "method" in m
            assert "precision" in m
            assert "recall" in m
            assert "f1" in m
            assert "tp" in m
            assert "fp" in m
            assert "tn" in m
            assert "fn" in m

    def test_combined_method_present(self) -> None:
        result = run_all_monitoring(
            channels=["ip-id"],
            n_trials=1,
            n_normal_pkts=20,
            stego_payload=64,
        )
        methods = [m["method"] for m in result["metrics"]]
        assert "combined" in methods
        assert "statistical" in methods
        assert "ml" in methods
        assert "signatures" in methods
        assert "ml_supervised" in methods
