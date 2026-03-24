"""Unit tests for channels/dns_query.py — roundtrip without network."""

import os

from netstego.channels.dns_query import DnsQueryChannel


class TestDnsQueryRoundtrip:
    def setup_method(self) -> None:
        self.channel = DnsQueryChannel()

    def test_roundtrip_small(self) -> None:
        data = b"DNS stego test!"
        packets = self.channel.encode(data, dest_ip="127.0.0.1")
        result = self.channel.decode(packets)
        assert result == data

    def test_roundtrip_exact_chunk(self) -> None:
        data = b"\xAA" * 30  # exactly MAX_RAW_BYTES
        packets = self.channel.encode(data, dest_ip="127.0.0.1")
        result = self.channel.decode(packets)
        assert result == data

    def test_roundtrip_multi_packet(self) -> None:
        data = os.urandom(100)
        packets = self.channel.encode(data, dest_ip="127.0.0.1")
        assert len(packets) > 2  # multiple data packets + termination
        result = self.channel.decode(packets)
        assert result == data

    def test_roundtrip_empty(self) -> None:
        data = b""
        packets = self.channel.encode(data, dest_ip="127.0.0.1")
        result = self.channel.decode(packets)
        assert result == data

    def test_bits_per_packet(self) -> None:
        assert self.channel.bits_per_packet == 30 * 8

    def test_protocol_filter(self) -> None:
        f = self.channel.protocol_filter
        assert "udp" in f
        assert "53" in f
