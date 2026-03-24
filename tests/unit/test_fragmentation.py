"""Unit tests for core/fragmentation.py and core/reassembly.py."""

import os

import pytest

from netstego.core.fragmentation import (
    FLAG_FIRST,
    FLAG_LAST,
    HEADER_SIZE,
    fragment,
    parse_header,
)
from netstego.core.reassembly import Reassembler, ReassemblyError


class TestFragmentation:
    def test_single_chunk(self) -> None:
        data = b"Hello"
        chunks = fragment(data, chunk_size=100)
        assert len(chunks) == 1
        seq, total, crc, flags, payload = parse_header(chunks[0])
        assert seq == 0
        assert total == 1
        assert flags == (FLAG_FIRST | FLAG_LAST)

    def test_multiple_chunks(self) -> None:
        data = b"A" * 200
        chunks = fragment(data, chunk_size=50)
        assert len(chunks) > 1
        # First chunk has FLAG_FIRST
        _, _, _, flags0, _ = parse_header(chunks[0])
        assert flags0 & FLAG_FIRST
        # Last chunk has FLAG_LAST
        _, _, _, flags_last, _ = parse_header(chunks[-1])
        assert flags_last & FLAG_LAST

    def test_chunk_size_too_small(self) -> None:
        with pytest.raises(ValueError, match="chunk_size must be >= 33"):
            fragment(b"data", chunk_size=10)

    def test_parse_header_invalid_magic(self) -> None:
        bad = b"XXXX" + b"\x00" * 13
        with pytest.raises(ValueError, match="Invalid magic"):
            parse_header(bad)

    def test_parse_header_too_short(self) -> None:
        with pytest.raises(ValueError, match="too short"):
            parse_header(b"short")


class TestReassembly:
    def test_roundtrip_small(self) -> None:
        data = b"Test payload for reassembly"
        chunks = fragment(data, chunk_size=50)
        r = Reassembler()
        for chunk in chunks:
            r.add_chunk(chunk)
        assert r.is_complete()
        result = r.try_reassemble()
        assert result == data

    def test_roundtrip_large(self) -> None:
        data = os.urandom(5000)
        chunks = fragment(data, chunk_size=100)
        r = Reassembler()
        for chunk in chunks:
            r.add_chunk(chunk)
        assert r.is_complete()
        assert r.try_reassemble() == data

    def test_out_of_order(self) -> None:
        data = b"Out of order test data here!!"
        chunks = fragment(data, chunk_size=40)
        r = Reassembler()
        # Add in reverse order
        for chunk in reversed(chunks):
            r.add_chunk(chunk)
        assert r.is_complete()
        assert r.try_reassemble() == data

    def test_missing_chunk_raises(self) -> None:
        data = b"X" * 200
        chunks = fragment(data, chunk_size=50)
        r = Reassembler()
        # Skip chunk index 1
        for i, chunk in enumerate(chunks):
            if i != 1:
                r.add_chunk(chunk)
        assert not r.is_complete()
        with pytest.raises(ReassemblyError, match="Missing"):
            r.try_reassemble()

    def test_corrupted_crc_raises(self) -> None:
        data = b"CRC test"
        chunks = fragment(data, chunk_size=50)
        # Corrupt data portion of first chunk
        corrupted = bytearray(chunks[0])
        corrupted[-1] ^= 0xFF
        r = Reassembler()
        with pytest.raises(ReassemblyError, match="CRC32 mismatch"):
            r.add_chunk(bytes(corrupted))

    def test_reset(self) -> None:
        data = b"reset test"
        chunks = fragment(data, chunk_size=50)
        r = Reassembler()
        for chunk in chunks:
            r.add_chunk(chunk)
        r.reset()
        assert r.received_count == 0
        assert r.total_expected is None

    def test_missing_seqs(self) -> None:
        data = b"A" * 200
        chunks = fragment(data, chunk_size=50)
        r = Reassembler()
        r.add_chunk(chunks[0])
        # After adding first chunk we know total
        assert len(r.missing_seqs) == len(chunks) - 1
