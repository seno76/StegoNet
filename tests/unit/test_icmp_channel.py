"""Unit tests for channels/icmp_payload.py — roundtrip without network."""

import os

from netstego.channels.icmp_payload import IcmpPayloadChannel


class TestIcmpPayloadRoundtrip:
    """Test encode/decode roundtrip using Scapy packet objects (no network)."""

    def setup_method(self) -> None:
        self.channel = IcmpPayloadChannel()

    def test_roundtrip_small(self) -> None:
        data = b"Hello ICMP steganography!"
        packets = self.channel.encode(data, dest_ip="127.0.0.1")
        result = self.channel.decode(packets)
        assert result == data

    def test_roundtrip_exact_one_packet(self) -> None:
        # 1470 bytes = max data per packet (1472 - 2 length prefix)
        data = b"\xAA" * 1470
        packets = self.channel.encode(data, dest_ip="127.0.0.1")
        assert len(packets) == 1
        result = self.channel.decode(packets)
        assert result == data

    def test_roundtrip_multi_packet(self) -> None:
        data = os.urandom(5000)
        packets = self.channel.encode(data, dest_ip="127.0.0.1")
        assert len(packets) > 1
        result = self.channel.decode(packets)
        assert result == data

    def test_roundtrip_empty(self) -> None:
        data = b""
        packets = self.channel.encode(data, dest_ip="127.0.0.1")
        result = self.channel.decode(packets)
        assert result == data

    def test_bits_per_packet(self) -> None:
        assert self.channel.bits_per_packet == 1472 * 8

    def test_protocol_filter(self) -> None:
        f = self.channel.protocol_filter
        assert "icmp" in f
        assert "{ip}" in f

    def test_packets_are_icmp_echo(self) -> None:
        from scapy.layers.inet import ICMP
        data = b"test"
        packets = self.channel.encode(data, dest_ip="10.0.0.1")
        for pkt in packets:
            assert pkt.haslayer(ICMP)
            assert pkt[ICMP].type == 8  # Echo Request
