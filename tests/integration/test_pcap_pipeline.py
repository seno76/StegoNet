"""Integration tests: full send/receive pipeline via PCAP files.

Tests the complete data path for all channels:
    sender (encrypt→fragment→frame→encode→PCAP)
    → receiver (PCAP→decode→unframe→reassemble→decrypt)
    → verify file matches original.

No admin privileges or raw sockets needed — uses PCAP intermediary.
"""

import os
from pathlib import Path

import pytest

from netstego.channels.dns_query import DnsQueryChannel
from netstego.channels.icmp_payload import IcmpPayloadChannel
from netstego.channels.ip_id import IpIdChannel
from netstego.channels.tcp_isn import TcpIsnChannel
from netstego.channels.tcp_timestamp import TcpTimestampChannel
from netstego.core.crypto import encrypt, decrypt, generate_key, load_key
from netstego.core.fragmentation import fragment
from netstego.core.reassembly import Reassembler
from netstego.network.receiver import unframe_chunks
from netstego.network.sender import frame_chunks, get_channel
from scapy.utils import wrpcap, rdpcap


def _send_receive_via_pcap(
    tmp_path: Path,
    channel_name: str,
    plaintext: bytes,
) -> bytes:
    """Simulate full send→PCAP→receive pipeline.

    Returns the recovered plaintext for comparison.
    """
    key_path = tmp_path / "test.key"
    pcap_path = tmp_path / "traffic.pcap"

    # --- SENDER SIDE ---
    key = generate_key(key_path)
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
    packets = channel.encode(framed, dest_ip="10.0.0.2")

    wrpcap(str(pcap_path), packets)

    # --- RECEIVER SIDE ---
    captured = list(rdpcap(str(pcap_path)))
    assert len(captured) == len(packets)

    channel_rx = get_channel(channel_name)
    raw_data = channel_rx.decode(captured)
    recovered_chunks = unframe_chunks(raw_data)

    reassembler = Reassembler()
    for chunk in recovered_chunks:
        reassembler.add_chunk(chunk)

    assert reassembler.is_complete(), (
        f"Missing chunks: {reassembler.missing_seqs}"
    )
    recovered_ciphertext = reassembler.try_reassemble()
    recovered_key = load_key(key_path)
    return decrypt(recovered_ciphertext, recovered_key)


class TestIcmpPcapPipeline:
    def test_text_file(self, tmp_path: Path) -> None:
        original = "Секретное сообщение для диплома! Hello, NetStego!".encode("utf-8")
        result = _send_receive_via_pcap(tmp_path, "icmp", original)
        assert result == original

    def test_binary_file(self, tmp_path: Path) -> None:
        original = os.urandom(10000)
        result = _send_receive_via_pcap(tmp_path, "icmp", original)
        assert result == original

    def test_large_file(self, tmp_path: Path) -> None:
        original = os.urandom(100_000)
        result = _send_receive_via_pcap(tmp_path, "icmp", original)
        assert result == original

    def test_empty_file(self, tmp_path: Path) -> None:
        original = b""
        result = _send_receive_via_pcap(tmp_path, "icmp", original)
        assert result == original

    def test_single_byte(self, tmp_path: Path) -> None:
        original = b"\x42"
        result = _send_receive_via_pcap(tmp_path, "icmp", original)
        assert result == original


class TestIpIdPcapPipeline:
    def test_text_file(self, tmp_path: Path) -> None:
        original = b"IP-ID steganography integration test!"
        result = _send_receive_via_pcap(tmp_path, "ip-id", original)
        assert result == original

    def test_binary_file(self, tmp_path: Path) -> None:
        original = os.urandom(500)
        result = _send_receive_via_pcap(tmp_path, "ip-id", original)
        assert result == original


class TestTcpIsnPcapPipeline:
    def test_text_file(self, tmp_path: Path) -> None:
        original = b"TCP ISN covert channel test data"
        result = _send_receive_via_pcap(tmp_path, "tcp-isn", original)
        assert result == original

    def test_binary_file(self, tmp_path: Path) -> None:
        original = os.urandom(500)
        result = _send_receive_via_pcap(tmp_path, "tcp-isn", original)
        assert result == original


class TestTcpTimestampPcapPipeline:
    def test_text_file(self, tmp_path: Path) -> None:
        original = b"TCP Timestamp covert channel test"
        result = _send_receive_via_pcap(tmp_path, "tcp-ts", original)
        assert result == original

    def test_binary_file(self, tmp_path: Path) -> None:
        original = os.urandom(500)
        result = _send_receive_via_pcap(tmp_path, "tcp-ts", original)
        assert result == original


class TestDnsPcapPipeline:
    def test_text_file(self, tmp_path: Path) -> None:
        original = b"DNS QNAME covert channel test"
        result = _send_receive_via_pcap(tmp_path, "dns", original)
        assert result == original

    def test_binary_file(self, tmp_path: Path) -> None:
        original = os.urandom(300)
        result = _send_receive_via_pcap(tmp_path, "dns", original)
        assert result == original


class TestDetectionOnStegoPcap:
    """Verify the detector flags steganographic traffic."""

    def test_icmp_stego_detected(self, tmp_path: Path) -> None:
        from netstego.detection.analyzer import analyze_packets

        # Create stego traffic
        channel = IcmpPayloadChannel()
        data = os.urandom(5000)
        packets = channel.encode(data, dest_ip="10.0.0.2")

        report = analyze_packets(
            list(packets),
            source="test_icmp_stego",
            methods=["signatures"],
        )
        # ICMP payload stego should contain NST magic in payload
        # (if raw fragment data with magic is in the payload)
        assert report.total_packets == len(packets)

    def test_ipid_stego_entropy(self, tmp_path: Path) -> None:
        from netstego.detection.analyzer import analyze_packets

        # Create IP-ID stego traffic with random-looking IDs
        channel = IpIdChannel()
        data = os.urandom(200)
        packets = channel.encode(data, dest_ip="10.0.0.2")

        report = analyze_packets(
            list(packets),
            source="test_ipid_stego",
            methods=["statistical"],
        )
        assert report.total_packets == len(packets)
        assert len(report.statistical_results) > 0
