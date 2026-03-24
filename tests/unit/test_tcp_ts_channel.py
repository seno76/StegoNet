"""Unit tests for channels/tcp_timestamp.py — roundtrip without network."""

import os

from netstego.channels.tcp_timestamp import TcpTimestampChannel


class TestTcpTimestampRoundtrip:
    def setup_method(self) -> None:
        self.channel = TcpTimestampChannel()

    def test_roundtrip_small(self) -> None:
        data = b"TCP TS stego test!"
        packets = self.channel.encode(data, dest_ip="127.0.0.1")
        result = self.channel.decode(packets)
        assert result == data

    def test_roundtrip_exact_four_bytes(self) -> None:
        data = b"\xDE\xAD\xBE\xEF"
        packets = self.channel.encode(data, dest_ip="127.0.0.1")
        result = self.channel.decode(packets)
        assert result == data

    def test_roundtrip_non_aligned(self) -> None:
        data = b"\x01\x02\x03"  # 3 bytes
        packets = self.channel.encode(data, dest_ip="127.0.0.1")
        result = self.channel.decode(packets)
        assert result == data

    def test_roundtrip_large(self) -> None:
        data = os.urandom(400)
        packets = self.channel.encode(data, dest_ip="127.0.0.1")
        result = self.channel.decode(packets)
        assert result == data

    def test_bits_per_packet(self) -> None:
        assert self.channel.bits_per_packet == 32

    def test_timestamp_option(self) -> None:
        from scapy.layers.inet import TCP
        data = b"test"
        packets = self.channel.encode(data, dest_ip="127.0.0.1")
        for pkt in packets:
            options = pkt[TCP].options
            has_ts = any(name == "Timestamp" for name, _ in options)
            assert has_ts
