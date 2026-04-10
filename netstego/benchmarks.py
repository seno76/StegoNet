"""Reusable benchmark and monitoring functions.

Provides run_pipeline(), run_redundancy_test(), run_all_benchmarks(),
and run_all_monitoring() for use by CLI and tools/ scripts.
"""

import os
import random
import time
from dataclasses import dataclass
from pathlib import Path

import numpy as np
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.packet import Packet, Raw

from netstego.core.crypto import decrypt, encrypt, generate_key
from netstego.core.fragmentation import fragment
from netstego.core.reassembly import Reassembler
from netstego.detection.analyzer import analyze_packets
from netstego.detection.ml_detector import detect_random_forest, extract_features
from netstego.network.receiver import unframe_chunks
from netstego.network.sender import frame_chunks, get_channel

DEST_IP = "192.168.1.100"
CHANNELS = ["icmp", "ip-id", "tcp-isn", "dns", "tcp-ts"]
DEFAULT_PAYLOAD_SIZES = [64, 256, 1024, 4096, 16384]


# ---------------------------------------------------------------------------
# Pipeline benchmark
# ---------------------------------------------------------------------------

def run_pipeline(channel_name: str, plaintext: bytes, key: bytes) -> dict:
    """Run the full stego pipeline and measure each stage.

    Returns dict with timing and throughput metrics.
    """
    channel = get_channel(channel_name)
    bytes_per_packet = channel.bits_per_packet // 8
    overhead = 17 + 4
    if bytes_per_packet > overhead + 33:
        chunk_data_size = bytes_per_packet - overhead
    else:
        chunk_data_size = 128

    t0 = time.perf_counter()
    ciphertext = encrypt(plaintext, key)
    t_encrypt = time.perf_counter() - t0

    t0 = time.perf_counter()
    chunks = fragment(ciphertext, chunk_data_size)
    t_fragment = time.perf_counter() - t0

    t0 = time.perf_counter()
    framed = frame_chunks(chunks)
    packets = channel.encode(framed, DEST_IP)
    t_encode = time.perf_counter() - t0

    num_packets = len(packets)

    t0 = time.perf_counter()
    raw_data = channel.decode(packets)
    t_decode = time.perf_counter() - t0

    t0 = time.perf_counter()
    decoded_chunks = unframe_chunks(raw_data)
    reassembler = Reassembler()
    for chunk in decoded_chunks:
        reassembler.add_chunk(chunk)
    reassembled = reassembler.try_reassemble()
    t_reassemble = time.perf_counter() - t0

    t0 = time.perf_counter()
    recovered = decrypt(reassembled, key)
    t_decrypt = time.perf_counter() - t0

    assert recovered == plaintext, "Data integrity check FAILED!"

    total_time = t_encrypt + t_fragment + t_encode + t_decode + t_reassemble + t_decrypt
    throughput_bps = (len(plaintext) * 8) / total_time if total_time > 0 else 0

    return {
        "channel": channel_name,
        "payload_bytes": len(plaintext),
        "ciphertext_bytes": len(ciphertext),
        "num_chunks": len(chunks),
        "num_packets": num_packets,
        "bits_per_packet": channel.bits_per_packet,
        "chunk_data_size": chunk_data_size,
        "encrypt_ms": t_encrypt * 1000,
        "fragment_ms": t_fragment * 1000,
        "encode_ms": t_encode * 1000,
        "decode_ms": t_decode * 1000,
        "reassemble_ms": t_reassemble * 1000,
        "decrypt_ms": t_decrypt * 1000,
        "total_ms": total_time * 1000,
        "throughput_bps": throughput_bps,
        "throughput_Bps": throughput_bps / 8,
        "overhead_ratio": num_packets * (20 + 20) / len(plaintext),
        "data_verified": True,
    }


def run_redundancy_test(
    channel_name: str, plaintext: bytes, key: bytes, loss_rate: float = 0.30,
) -> dict:
    """Test packet loss tolerance with redundancy (3x).

    Simulates packet loss and checks if data can be recovered.
    """
    channel = get_channel(channel_name)
    bytes_per_packet = channel.bits_per_packet // 8
    overhead = 17 + 4
    if bytes_per_packet > overhead + 33:
        chunk_data_size = bytes_per_packet - overhead
    else:
        chunk_data_size = 128

    ciphertext = encrypt(plaintext, key)
    chunks = fragment(ciphertext, chunk_data_size)

    redundant_chunks = []
    for chunk in chunks:
        for _ in range(3):
            redundant_chunks.append(chunk)
    random.shuffle(redundant_chunks)

    framed = frame_chunks(redundant_chunks)
    packets = channel.encode(framed, DEST_IP)

    surviving = [p for p in packets if random.random() > loss_rate]

    raw_data = channel.decode(surviving)
    decoded_chunks = unframe_chunks(raw_data)

    reassembler = Reassembler()
    bad = 0
    for chunk in decoded_chunks:
        try:
            reassembler.add_chunk(chunk)
        except Exception:
            bad += 1

    success = reassembler.is_complete()
    result = {
        "channel": channel_name,
        "total_packets": len(packets),
        "surviving_packets": len(surviving),
        "loss_rate": 1 - len(surviving) / len(packets) if packets else 0,
        "unique_chunks": len(chunks),
        "received_unique": reassembler.received_count,
        "duplicates_discarded": reassembler.duplicates_received,
        "reassembly_success": success,
    }

    if success:
        reassembled = reassembler.try_reassemble()
        recovered = decrypt(reassembled, key)
        result["data_verified"] = recovered == plaintext
    else:
        result["data_verified"] = False
        result["missing"] = reassembler.missing_seqs

    return result


def run_all_benchmarks(
    payload_sizes: list[int] | None = None,
    channels: list[str] | None = None,
    repeat: int = 3,
) -> dict:
    """Run all benchmarks and return results dict.

    Args:
        payload_sizes: Sizes to test. Defaults to [64, 256, 1024, 4096, 16384].
        channels: Channels to test. Defaults to all 5.
        repeat: Number of repetitions for averaging.

    Returns:
        Dict with 'pipeline_benchmarks' and 'redundancy_tests' keys.
    """
    if payload_sizes is None:
        payload_sizes = DEFAULT_PAYLOAD_SIZES
    if channels is None:
        channels = CHANNELS

    key_path = Path("benchmark_key.tmp")
    key = generate_key(key_path)

    results = []
    for channel_name in channels:
        for size in payload_sizes:
            plaintext = os.urandom(size)
            timings = []
            for _ in range(repeat):
                r = run_pipeline(channel_name, plaintext, key)
                timings.append(r)

            avg = {k: v for k, v in timings[0].items()}
            numeric_keys = [
                k for k in avg
                if isinstance(avg[k], (int, float))
                and k not in (
                    "payload_bytes", "ciphertext_bytes", "num_chunks",
                    "num_packets", "bits_per_packet", "chunk_data_size", "data_verified",
                )
            ]
            for k in numeric_keys:
                avg[k] = sum(t[k] for t in timings) / repeat
            results.append(avg)

    # Redundancy tests (ICMP only — chunk=packet alignment)
    redundancy_results = []
    if "icmp" in channels:
        for loss_pct in [10, 20, 30, 40, 50]:
            plaintext = os.urandom(4096)
            for _ in range(10):
                r = run_redundancy_test("icmp", plaintext, key, loss_rate=loss_pct / 100)
                redundancy_results.append(r)

    key_path.unlink(missing_ok=True)

    return {
        "pipeline_benchmarks": results,
        "redundancy_tests": redundancy_results,
    }


# ---------------------------------------------------------------------------
# Normal traffic generators (mimic real OS behavior)
# ---------------------------------------------------------------------------

def generate_normal_icmp(dest_ip: str, count: int) -> list[Packet]:
    """Generate normal ICMP Echo Request packets (Windows-style)."""
    packets = []
    win_payload = bytes(range(0x61, 0x61 + 23)) + bytes(range(0x61, 0x61 + 9))
    ip_id = random.randint(1000, 60000)
    t = time.time()
    for i in range(count):
        ip_id = (ip_id + random.randint(1, 3)) % 65535
        pkt = IP(dst=dest_ip, id=ip_id) / ICMP(type=8, code=0, seq=i) / Raw(load=win_payload)
        t += random.uniform(0.8, 1.5)
        pkt.time = t
        packets.append(pkt)
    return packets


def generate_normal_tcp_syn(dest_ip: str, count: int) -> list[Packet]:
    """Generate normal-looking TCP SYN packets with realistic ISN."""
    packets = []
    base_isn = random.randint(100000, 4000000000)
    ip_id = random.randint(1000, 60000)
    t = time.time()
    for i in range(count):
        isn = (base_isn + i * random.randint(50000, 200000)) & 0xFFFFFFFF
        ip_id = (ip_id + random.randint(1, 3)) % 65535
        pkt = IP(dst=dest_ip, id=ip_id) / TCP(
            sport=random.randint(49152, 65535),
            dport=random.choice([80, 443, 8080, 22]),
            seq=isn, flags="S",
        )
        t += random.uniform(0.3, 5.0)
        pkt.time = t
        packets.append(pkt)
    return packets


def generate_normal_dns(dest_ip: str, count: int) -> list[Packet]:
    """Generate normal DNS queries with realistic domain names."""
    domains = [
        "www.google.com.", "mail.yandex.ru.", "api.github.com.",
        "cdn.cloudflare.com.", "fonts.googleapis.com.", "login.microsoftonline.com.",
        "static.example.org.", "update.mozilla.org.", "images.unsplash.com.",
        "docs.python.org.", "registry.npmjs.org.", "releases.ubuntu.com.",
    ]
    packets = []
    ip_id = random.randint(1000, 60000)
    t = time.time()
    for i in range(count):
        ip_id = (ip_id + random.randint(1, 3)) % 65535
        pkt = (
            IP(dst=dest_ip, id=ip_id)
            / UDP(sport=random.randint(30000, 60000), dport=53)
            / DNS(id=random.randint(0, 65535), qd=DNSQR(qname=random.choice(domains), qtype="A"))
        )
        t += random.uniform(0.1, 2.0)
        pkt.time = t
        packets.append(pkt)
    return packets


def generate_normal_tcp_ts(dest_ip: str, count: int) -> list[Packet]:
    """Generate normal TCP ACK packets with monotonically increasing TSval."""
    packets = []
    tsval = random.randint(100000, 500000)
    ip_id = random.randint(1000, 60000)
    t = time.time()
    for i in range(count):
        tsval += random.randint(90, 110)
        ip_id = (ip_id + random.randint(1, 3)) % 65535
        ts_option = ("Timestamp", (tsval, tsval - random.randint(10, 50)))
        pkt = IP(dst=dest_ip, id=ip_id) / TCP(
            sport=random.randint(49152, 65535), dport=443,
            seq=random.randint(1, 4000000000), flags="A",
            options=[ts_option],
        )
        t += random.uniform(0.005, 0.02)
        pkt.time = t
        packets.append(pkt)
    return packets


def generate_normal_ip_id(dest_ip: str, count: int) -> list[Packet]:
    """Generate normal ICMP packets with incremental IP ID (Windows-style)."""
    packets = []
    ip_id = random.randint(1000, 60000)
    win_payload = bytes(range(0x61, 0x61 + 23)) + bytes(range(0x61, 0x61 + 9))
    t = time.time()
    for i in range(count):
        ip_id = (ip_id + 1) % 65535
        pkt = IP(dst=dest_ip, id=ip_id) / ICMP(type=8, code=0, seq=i) / Raw(load=win_payload)
        t += random.uniform(0.8, 1.5)
        pkt.time = t
        packets.append(pkt)
    return packets


NORMAL_GENERATORS = {
    "icmp": generate_normal_icmp,
    "ip-id": generate_normal_ip_id,
    "tcp-isn": generate_normal_tcp_syn,
    "dns": generate_normal_dns,
    "tcp-ts": generate_normal_tcp_ts,
}


def generate_stego_traffic(
    channel_name: str, dest_ip: str, key: bytes, payload_size: int = 512,
) -> list[Packet]:
    """Generate steganographic packets using the real NetStego pipeline."""
    plaintext = os.urandom(payload_size)
    ciphertext = encrypt(plaintext, key)

    channel = get_channel(channel_name)
    bytes_per_packet = channel.bits_per_packet // 8
    overhead = 17 + 4
    if bytes_per_packet > overhead + 33:
        chunk_data_size = bytes_per_packet - overhead
    else:
        chunk_data_size = 128

    chunks = fragment(ciphertext, chunk_data_size)
    framed = frame_chunks(chunks)
    packets = channel.encode(framed, dest_ip)

    t = time.time()
    for pkt in packets:
        pkt.time = t
        t += random.uniform(0.08, 0.12)

    return packets


# ---------------------------------------------------------------------------
# Detection metrics
# ---------------------------------------------------------------------------

@dataclass
class DetectionMetrics:
    """Detection accuracy metrics for one experiment."""
    channel: str
    method: str
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def accuracy(self) -> float:
        total = self.tp + self.fp + self.tn + self.fn
        return (self.tp + self.tn) / total if total > 0 else 0.0

    @property
    def fpr(self) -> float:
        return self.fp / (self.fp + self.tn) if (self.fp + self.tn) > 0 else 0.0

    def to_dict(self) -> dict:
        return {
            "channel": self.channel,
            "method": self.method,
            "tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "accuracy": round(self.accuracy, 4),
            "fpr": round(self.fpr, 4),
        }


# ---------------------------------------------------------------------------
# Monitoring experiment
# ---------------------------------------------------------------------------

def run_all_monitoring(
    channels: list[str] | None = None,
    n_trials: int = 10,
    n_normal_pkts: int = 100,
    stego_payload: int = 512,
) -> dict:
    """Run detection monitoring experiment and return results.

    Args:
        channels: Channels to test. Defaults to all 5.
        n_trials: Number of trials per channel.
        n_normal_pkts: Normal packets per trial.
        stego_payload: Bytes of data to hide in stego traffic.

    Returns:
        Dict with 'parameters' and 'metrics' keys.
    """
    if channels is None:
        channels = CHANNELS

    key_path = Path("monitoring_key.tmp")
    key = generate_key(key_path)

    all_metrics = []

    for channel_name in channels:
        gen_normal = NORMAL_GENERATORS[channel_name]

        combined = DetectionMetrics(channel=channel_name, method="combined")
        method_stats = {
            "statistical": DetectionMetrics(channel=channel_name, method="statistical"),
            "ml": DetectionMetrics(channel=channel_name, method="ml"),
            "signatures": DetectionMetrics(channel=channel_name, method="signatures"),
        }
        rf_metrics = DetectionMetrics(channel=channel_name, method="ml_supervised")

        for trial in range(n_trials):
            # Test on stego traffic
            stego_pkts = generate_stego_traffic(channel_name, DEST_IP, key, stego_payload)
            stego_report = analyze_packets(stego_pkts, source=f"stego_{channel_name}_trial{trial}")
            if stego_report.is_suspicious:
                combined.tp += 1
            else:
                combined.fn += 1

            for method_name in ["statistical", "ml", "signatures"]:
                method_report = analyze_packets(
                    stego_pkts,
                    source=f"stego_{channel_name}_{method_name}",
                    methods=[method_name],
                )
                if method_report.is_suspicious:
                    method_stats[method_name].tp += 1
                else:
                    method_stats[method_name].fn += 1

            # Test on normal traffic
            normal_pkts = gen_normal(DEST_IP, n_normal_pkts)
            normal_report = analyze_packets(normal_pkts, source=f"normal_{channel_name}_trial{trial}")
            if normal_report.is_suspicious:
                combined.fp += 1
            else:
                combined.tn += 1

            for method_name in ["statistical", "ml", "signatures"]:
                method_report = analyze_packets(
                    normal_pkts,
                    source=f"normal_{channel_name}_{method_name}",
                    methods=[method_name],
                )
                if method_report.is_suspicious:
                    method_stats[method_name].fp += 1
                else:
                    method_stats[method_name].tn += 1

        # Supervised ML (RandomForest): train on half trials, test on other half
        train_stego = generate_stego_traffic(channel_name, DEST_IP, key, stego_payload)
        train_normal = gen_normal(DEST_IP, n_normal_pkts)
        test_stego = generate_stego_traffic(channel_name, DEST_IP, key, stego_payload)
        test_normal = gen_normal(DEST_IP, n_normal_pkts)

        def _pkt_features(pkts):
            field_vals = []
            ts = []
            szs = []
            pays = []
            for p in pkts:
                field_vals.append(p[IP].id if p.haslayer(IP) else 0)
                ts.append(float(p.time) if hasattr(p, "time") else 0.0)
                szs.append(len(p))
                pays.append(bytes(p[Raw].load) if p.haslayer(Raw) else b"")
            return extract_features(field_vals, ts, szs, pays)

        train_feat_s = _pkt_features(train_stego)
        train_feat_n = _pkt_features(train_normal)
        test_feat_s = _pkt_features(test_stego)
        test_feat_n = _pkt_features(test_normal)

        if len(train_feat_s) > 0 and len(train_feat_n) > 0:
            train_X = np.vstack([train_feat_n, train_feat_s])
            train_y = np.array([0]*len(train_feat_n) + [1]*len(train_feat_s))
            test_X = np.vstack([test_feat_n, test_feat_s])
            test_y = np.array([0]*len(test_feat_n) + [1]*len(test_feat_s))

            rf_result = detect_random_forest(train_X, train_y, test_X, test_y)
            preds = rf_result.predictions
            for pred, truth in zip(preds, test_y):
                if truth == 1 and pred == 1:
                    rf_metrics.tp += 1
                elif truth == 1 and pred == 0:
                    rf_metrics.fn += 1
                elif truth == 0 and pred == 1:
                    rf_metrics.fp += 1
                else:
                    rf_metrics.tn += 1

        all_metrics.append(combined.to_dict())
        for m_stats in method_stats.values():
            all_metrics.append(m_stats.to_dict())
        all_metrics.append(rf_metrics.to_dict())

    key_path.unlink(missing_ok=True)

    return {
        "parameters": {
            "n_trials": n_trials,
            "n_normal_packets": n_normal_pkts,
            "stego_payload_bytes": stego_payload,
            "dest_ip": DEST_IP,
        },
        "metrics": all_metrics,
    }
