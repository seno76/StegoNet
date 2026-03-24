"""End-to-end pipeline test: encrypt -> fragment -> encode -> decode -> reassemble -> decrypt.

Tests the full data path without touching the network (no raw sockets needed).
"""

import os
import struct
from pathlib import Path

import pytest

from netstego.channels.icmp_payload import IcmpPayloadChannel
from netstego.channels.ip_id import IpIdChannel
from netstego.channels.tcp_isn import TcpIsnChannel
from netstego.channels.tcp_timestamp import TcpTimestampChannel
from netstego.channels.dns_query import DnsQueryChannel
from netstego.core.crypto import decrypt, encrypt, generate_key, load_key
from netstego.core.fragmentation import fragment
from netstego.core.reassembly import Reassembler
from netstego.network.sender import frame_chunks
from netstego.network.receiver import unframe_chunks


class TestFrameUnframe:
    """Test length-prefix framing used by sender/receiver."""

    def test_roundtrip(self) -> None:
        chunks = [b"chunk_one", b"chunk_two", b"chunk_three"]
        framed = frame_chunks(chunks)
        result = unframe_chunks(framed)
        assert result == chunks

    def test_single_chunk(self) -> None:
        chunks = [b"only_one"]
        framed = frame_chunks(chunks)
        result = unframe_chunks(framed)
        assert result == chunks

    def test_empty(self) -> None:
        framed = frame_chunks([])
        result = unframe_chunks(framed)
        assert result == []

    def test_binary_data(self) -> None:
        chunks = [os.urandom(100), os.urandom(50), os.urandom(200)]
        framed = frame_chunks(chunks)
        result = unframe_chunks(framed)
        assert result == chunks


def _full_pipeline(channel, plaintext: bytes, chunk_data_size: int, key: bytes) -> bytes:
    """Run full pipeline: encrypt -> fragment -> frame -> encode -> decode -> unframe -> reassemble -> decrypt."""
    # Encrypt
    ciphertext = encrypt(plaintext, key)

    # Fragment
    chunks = fragment(ciphertext, chunk_data_size)

    # Frame and encode
    framed = frame_chunks(chunks)
    packets = channel.encode(framed, dest_ip="127.0.0.1")

    # Decode and unframe
    decoded = channel.decode(packets)
    recovered_chunks = unframe_chunks(decoded)

    # Reassemble
    reassembler = Reassembler()
    for chunk in recovered_chunks:
        reassembler.add_chunk(chunk)
    assert reassembler.is_complete()
    recovered_ciphertext = reassembler.try_reassemble()

    # Decrypt
    return decrypt(recovered_ciphertext, key)


class TestFullPipelineIcmp:
    """Full pipeline test with ICMP channel."""

    def setup_method(self) -> None:
        self.channel = IcmpPayloadChannel()
        self.key = os.urandom(32)
        # ICMP: 1472 bytes per packet, minus 2 length prefix = 1470 usable
        # chunk = header(17) + data(N), framed = len(4) + chunk
        # Ensure chunk fits in one ICMP packet: 4 + 17 + N <= 1470 => N <= 1449
        self.chunk_data_size = 1449

    def test_small_file(self) -> None:
        plaintext = b"Hello, NetStego!"
        result = _full_pipeline(self.channel, plaintext, self.chunk_data_size, self.key)
        assert result == plaintext

    def test_medium_file(self) -> None:
        plaintext = os.urandom(5000)
        result = _full_pipeline(self.channel, plaintext, self.chunk_data_size, self.key)
        assert result == plaintext

    def test_large_file(self) -> None:
        plaintext = os.urandom(50000)
        result = _full_pipeline(self.channel, plaintext, self.chunk_data_size, self.key)
        assert result == plaintext

    def test_empty_file(self) -> None:
        plaintext = b""
        result = _full_pipeline(self.channel, plaintext, self.chunk_data_size, self.key)
        assert result == plaintext


class TestFullPipelineIpId:
    """Full pipeline test with IP ID channel."""

    def setup_method(self) -> None:
        self.channel = IpIdChannel()
        self.key = os.urandom(32)
        # IP ID: 2 bytes per packet. Smaller chunk_data_size since each chunk
        # will produce many packets.
        self.chunk_data_size = 50

    def test_small_file(self) -> None:
        plaintext = b"IP-ID pipeline"
        result = _full_pipeline(self.channel, plaintext, self.chunk_data_size, self.key)
        assert result == plaintext

    def test_binary_data(self) -> None:
        plaintext = os.urandom(200)
        result = _full_pipeline(self.channel, plaintext, self.chunk_data_size, self.key)
        assert result == plaintext


class TestFullPipelineTcpIsn:
    """Full pipeline test with TCP ISN channel."""

    def setup_method(self) -> None:
        self.channel = TcpIsnChannel()
        self.key = os.urandom(32)
        self.chunk_data_size = 50

    def test_small_file(self) -> None:
        plaintext = b"TCP-ISN pipeline"
        result = _full_pipeline(self.channel, plaintext, self.chunk_data_size, self.key)
        assert result == plaintext

    def test_binary_data(self) -> None:
        plaintext = os.urandom(200)
        result = _full_pipeline(self.channel, plaintext, self.chunk_data_size, self.key)
        assert result == plaintext


class TestFullPipelineTcpTimestamp:
    """Full pipeline test with TCP Timestamp channel."""

    def setup_method(self) -> None:
        self.channel = TcpTimestampChannel()
        self.key = os.urandom(32)
        self.chunk_data_size = 50

    def test_small_file(self) -> None:
        plaintext = b"TCP-TS pipeline"
        result = _full_pipeline(self.channel, plaintext, self.chunk_data_size, self.key)
        assert result == plaintext

    def test_binary_data(self) -> None:
        plaintext = os.urandom(200)
        result = _full_pipeline(self.channel, plaintext, self.chunk_data_size, self.key)
        assert result == plaintext


class TestFullPipelineDns:
    """Full pipeline test with DNS channel."""

    def setup_method(self) -> None:
        self.channel = DnsQueryChannel()
        self.key = os.urandom(32)
        self.chunk_data_size = 50

    def test_small_file(self) -> None:
        plaintext = b"DNS pipeline"
        result = _full_pipeline(self.channel, plaintext, self.chunk_data_size, self.key)
        assert result == plaintext

    def test_binary_data(self) -> None:
        plaintext = os.urandom(150)
        result = _full_pipeline(self.channel, plaintext, self.chunk_data_size, self.key)
        assert result == plaintext


class TestKeygenAndPipeline:
    """Test key generation + pipeline integration."""

    def test_with_generated_key(self, tmp_path: Path) -> None:
        key_path = tmp_path / "test.key"
        generate_key(key_path)
        key = load_key(key_path)

        channel = IcmpPayloadChannel()
        plaintext = b"Key generation pipeline test!"
        result = _full_pipeline(channel, plaintext, 1449, key)
        assert result == plaintext
