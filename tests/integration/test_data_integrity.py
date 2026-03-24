"""Data integrity verification tests.

Explicitly verifies that data recovered after the full steganographic
pipeline (encrypt → fragment → encode → PCAP → decode → reassemble → decrypt)
is byte-for-byte identical to the original.

Checks:
    - SHA-256 hash match before/after
    - Byte length match
    - Byte-for-byte comparison
    - Various data types: text (UTF-8, ASCII), binary, images, zeros, patterns
    - Various sizes: 1 byte, 100 bytes, 10 KB, 100 KB
    - All 5 channels
"""

import hashlib
import os
from pathlib import Path

import pytest
from scapy.utils import rdpcap, wrpcap

from netstego.core.crypto import decrypt, encrypt, generate_key, load_key
from netstego.core.fragmentation import fragment
from netstego.core.reassembly import Reassembler
from netstego.network.receiver import unframe_chunks
from netstego.network.sender import frame_chunks, get_channel


def _full_roundtrip(tmp_path: Path, channel_name: str, original: bytes) -> bytes:
    """Full send → PCAP file → receive roundtrip.

    Returns recovered bytes for comparison.
    """
    key_path = tmp_path / "test.key"
    pcap_path = tmp_path / "traffic.pcap"

    # --- SEND ---
    key = generate_key(key_path)
    ciphertext = encrypt(original, key)

    channel = get_channel(channel_name)
    bpp = channel.bits_per_packet // 8
    overhead = 17 + 4
    chunk_data_size = (bpp - overhead) if bpp > overhead + 33 else 128

    chunks = fragment(ciphertext, chunk_data_size)
    framed = frame_chunks(chunks)
    packets = channel.encode(framed, dest_ip="10.0.0.2")
    wrpcap(str(pcap_path), packets)

    # --- RECEIVE ---
    captured = list(rdpcap(str(pcap_path)))
    channel_rx = get_channel(channel_name)
    decoded = channel_rx.decode(captured)
    recovered_chunks = unframe_chunks(decoded)

    reassembler = Reassembler()
    for c in recovered_chunks:
        reassembler.add_chunk(c)

    assert reassembler.is_complete(), f"Incomplete: missing {reassembler.missing_seqs}"
    recovered_ct = reassembler.try_reassemble()
    return decrypt(recovered_ct, load_key(key_path))


def _assert_integrity(original: bytes, recovered: bytes, label: str) -> None:
    """Assert byte-for-byte integrity with detailed diagnostics."""
    original_sha = hashlib.sha256(original).hexdigest()
    recovered_sha = hashlib.sha256(recovered).hexdigest()

    assert len(recovered) == len(original), (
        f"[{label}] Length mismatch: original={len(original)}, recovered={len(recovered)}"
    )
    assert recovered_sha == original_sha, (
        f"[{label}] SHA-256 mismatch:\n"
        f"  original:  {original_sha}\n"
        f"  recovered: {recovered_sha}"
    )
    assert recovered == original, f"[{label}] Byte-for-byte comparison failed"


# ============================================================
# Test data types
# ============================================================

ALL_CHANNELS = ["icmp", "ip-id", "tcp-isn", "tcp-ts", "dns"]


class TestTextIntegrity:
    """Verify text data survives the pipeline."""

    @pytest.mark.parametrize("channel_name", ALL_CHANNELS)
    def test_ascii_text(self, tmp_path: Path, channel_name: str) -> None:
        original = b"The quick brown fox jumps over the lazy dog. 0123456789!"
        recovered = _full_roundtrip(tmp_path, channel_name, original)
        _assert_integrity(original, recovered, f"ASCII/{channel_name}")

    @pytest.mark.parametrize("channel_name", ALL_CHANNELS)
    def test_utf8_cyrillic(self, tmp_path: Path, channel_name: str) -> None:
        original = "Привет мир! Это тест стеганографии для дипломной работы.".encode("utf-8")
        recovered = _full_roundtrip(tmp_path, channel_name, original)
        _assert_integrity(original, recovered, f"UTF8-Cyrillic/{channel_name}")
        assert recovered.decode("utf-8") == original.decode("utf-8")

    @pytest.mark.parametrize("channel_name", ALL_CHANNELS)
    def test_utf8_emoji(self, tmp_path: Path, channel_name: str) -> None:
        original = "Hello 🌍🔒🛡️ Steganography! 日本語テスト".encode("utf-8")
        recovered = _full_roundtrip(tmp_path, channel_name, original)
        _assert_integrity(original, recovered, f"UTF8-Emoji/{channel_name}")


class TestBinaryIntegrity:
    """Verify binary data survives the pipeline."""

    @pytest.mark.parametrize("channel_name", ALL_CHANNELS)
    def test_random_bytes_small(self, tmp_path: Path, channel_name: str) -> None:
        original = os.urandom(100)
        recovered = _full_roundtrip(tmp_path, channel_name, original)
        _assert_integrity(original, recovered, f"Random100B/{channel_name}")

    @pytest.mark.parametrize("channel_name", ALL_CHANNELS)
    def test_random_bytes_10kb(self, tmp_path: Path, channel_name: str) -> None:
        original = os.urandom(10_000)
        recovered = _full_roundtrip(tmp_path, channel_name, original)
        _assert_integrity(original, recovered, f"Random10KB/{channel_name}")

    @pytest.mark.parametrize("channel_name", ["icmp"])
    def test_random_bytes_100kb(self, tmp_path: Path, channel_name: str) -> None:
        """100KB test only for ICMP (high capacity). Others would be too slow."""
        original = os.urandom(100_000)
        recovered = _full_roundtrip(tmp_path, channel_name, original)
        _assert_integrity(original, recovered, f"Random100KB/{channel_name}")


class TestEdgeCases:
    """Verify edge cases survive the pipeline."""

    @pytest.mark.parametrize("channel_name", ALL_CHANNELS)
    def test_single_byte(self, tmp_path: Path, channel_name: str) -> None:
        original = b"\x42"
        recovered = _full_roundtrip(tmp_path, channel_name, original)
        _assert_integrity(original, recovered, f"1Byte/{channel_name}")

    @pytest.mark.parametrize("channel_name", ALL_CHANNELS)
    def test_empty(self, tmp_path: Path, channel_name: str) -> None:
        original = b""
        recovered = _full_roundtrip(tmp_path, channel_name, original)
        _assert_integrity(original, recovered, f"Empty/{channel_name}")

    @pytest.mark.parametrize("channel_name", ALL_CHANNELS)
    def test_all_zeros(self, tmp_path: Path, channel_name: str) -> None:
        original = b"\x00" * 500
        recovered = _full_roundtrip(tmp_path, channel_name, original)
        _assert_integrity(original, recovered, f"Zeros/{channel_name}")

    @pytest.mark.parametrize("channel_name", ALL_CHANNELS)
    def test_all_0xff(self, tmp_path: Path, channel_name: str) -> None:
        original = b"\xff" * 500
        recovered = _full_roundtrip(tmp_path, channel_name, original)
        _assert_integrity(original, recovered, f"0xFF/{channel_name}")

    @pytest.mark.parametrize("channel_name", ALL_CHANNELS)
    def test_repeating_pattern(self, tmp_path: Path, channel_name: str) -> None:
        original = (b"\xDE\xAD\xBE\xEF" * 250)  # 1000 bytes
        recovered = _full_roundtrip(tmp_path, channel_name, original)
        _assert_integrity(original, recovered, f"Pattern/{channel_name}")

    @pytest.mark.parametrize("channel_name", ALL_CHANNELS)
    def test_all_byte_values(self, tmp_path: Path, channel_name: str) -> None:
        """Data containing every possible byte value 0x00-0xFF."""
        original = bytes(range(256)) * 2  # 512 bytes
        recovered = _full_roundtrip(tmp_path, channel_name, original)
        _assert_integrity(original, recovered, f"AllBytes/{channel_name}")


class TestSimulatedFileTypes:
    """Verify various file-like content survives the pipeline."""

    @pytest.mark.parametrize("channel_name", ALL_CHANNELS)
    def test_json_content(self, tmp_path: Path, channel_name: str) -> None:
        import json
        data = {"secret": "value", "numbers": [1, 2, 3], "nested": {"key": True}}
        original = json.dumps(data).encode("utf-8")
        recovered = _full_roundtrip(tmp_path, channel_name, original)
        _assert_integrity(original, recovered, f"JSON/{channel_name}")
        assert json.loads(recovered.decode()) == data

    @pytest.mark.parametrize("channel_name", ALL_CHANNELS)
    def test_fake_png_header(self, tmp_path: Path, channel_name: str) -> None:
        """Binary content starting with PNG magic bytes."""
        png_header = b"\x89PNG\r\n\x1a\n"
        original = png_header + os.urandom(500)
        recovered = _full_roundtrip(tmp_path, channel_name, original)
        _assert_integrity(original, recovered, f"PNGlike/{channel_name}")
        assert recovered[:8] == png_header


class TestHashVerification:
    """Explicitly compute and compare SHA-256 at each stage."""

    def test_sha256_at_every_stage(self, tmp_path: Path) -> None:
        """Trace SHA-256 through each pipeline stage for ICMP."""
        original = os.urandom(5000)
        original_sha = hashlib.sha256(original).hexdigest()

        key = generate_key(tmp_path / "k.key")

        # Stage 1: encrypt
        ciphertext = encrypt(original, key)
        ct_sha = hashlib.sha256(ciphertext).hexdigest()
        assert ct_sha != original_sha, "Ciphertext should differ from plaintext"

        # Stage 2: fragment
        channel = get_channel("icmp")
        chunks = fragment(ciphertext, 1451)
        all_chunk_data = b"".join(chunks)
        assert len(chunks) >= 1

        # Stage 3: frame + encode
        framed = frame_chunks(chunks)
        packets = channel.encode(framed, "10.0.0.2")
        wrpcap(str(tmp_path / "t.pcap"), packets)

        # Stage 4: read PCAP + decode
        captured = list(rdpcap(str(tmp_path / "t.pcap")))
        decoded = channel.decode(captured)
        assert decoded == framed, "Decoded framed data should match original framed data"

        # Stage 5: unframe
        recovered_chunks = unframe_chunks(decoded)
        assert len(recovered_chunks) == len(chunks)
        for i, (orig_c, recv_c) in enumerate(zip(chunks, recovered_chunks)):
            assert orig_c == recv_c, f"Chunk {i} mismatch"

        # Stage 6: reassemble
        r = Reassembler()
        for c in recovered_chunks:
            r.add_chunk(c)
        recovered_ct = r.try_reassemble()
        assert hashlib.sha256(recovered_ct).hexdigest() == ct_sha

        # Stage 7: decrypt
        recovered = decrypt(recovered_ct, key)
        recovered_sha = hashlib.sha256(recovered).hexdigest()

        assert recovered_sha == original_sha
        assert recovered == original
