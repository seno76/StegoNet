"""Unit tests for channels/ip_id.py — roundtrip without network."""

import os

from netstego.channels.ip_id import IpIdChannel


class TestIpIdRoundtrip:
    def setup_method(self) -> None:
        self.channel = IpIdChannel()

    def test_roundtrip_small(self) -> None:
        data = b"Hello IP-ID stego!"
        packets = self.channel.encode(data, dest_ip="127.0.0.1")
        result = self.channel.decode(packets)
        assert result == data

    def test_roundtrip_exact_two_bytes(self) -> None:
        data = b"\xAB\xCD"
        packets = self.channel.encode(data, dest_ip="127.0.0.1")
        result = self.channel.decode(packets)
        assert result == data

    def test_roundtrip_odd_length(self) -> None:
        data = b"\x01\x02\x03"  # 3 bytes — odd
        packets = self.channel.encode(data, dest_ip="127.0.0.1")
        result = self.channel.decode(packets)
        assert result == data

    def test_roundtrip_large(self) -> None:
        data = os.urandom(500)
        packets = self.channel.encode(data, dest_ip="127.0.0.1")
        result = self.channel.decode(packets)
        assert result == data

    def test_roundtrip_empty(self) -> None:
        data = b""
        packets = self.channel.encode(data, dest_ip="127.0.0.1")
        result = self.channel.decode(packets)
        assert result == data

    def test_bits_per_packet(self) -> None:
        assert self.channel.bits_per_packet == 16

    def test_protocol_filter(self) -> None:
        f = self.channel.protocol_filter
        assert "icmp" in f
        assert "{ip}" in f
