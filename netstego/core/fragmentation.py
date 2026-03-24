"""Payload fragmentation with internal chunk header.

Chunk header format (17 bytes):
    Offset  Size    Field
    0       4       MAGIC: b"NST\\x00"
    4       4       SEQ NUMBER (uint32 BE)
    8       4       TOTAL CHUNKS (uint32 BE)
    12      4       CRC32 (uint32 BE) — checksum of DATA only
    16      1       FLAGS (uint8)
    17      N       DATA

Flags:
    0x01 — first chunk (DATA starts with SHA-256 of original file)
    0x02 — last chunk
    0x04 — NACK (retransmit request)
"""

import hashlib
import struct
import zlib

MAGIC = b"NST\x00"
HEADER_SIZE = 17

FLAG_FIRST = 0x01
FLAG_LAST = 0x02
FLAG_NACK = 0x04


def _make_header(seq: int, total: int, crc: int, flags: int) -> bytes:
    """Build a 17-byte chunk header."""
    return struct.pack(">4sIIIB", MAGIC, seq, total, crc, flags)


def parse_header(chunk: bytes) -> tuple[int, int, int, int, bytes]:
    """Parse a chunk into (seq, total, crc32, flags, data).

    Args:
        chunk: Raw chunk bytes including header.

    Returns:
        Tuple of (seq, total, crc32, flags, data).

    Raises:
        ValueError: If magic bytes are wrong or chunk too short.
    """
    if len(chunk) < HEADER_SIZE:
        msg = f"Chunk too short: {len(chunk)} < {HEADER_SIZE}"
        raise ValueError(msg)
    magic, seq, total, crc, flags = struct.unpack(">4sIIIB", chunk[:HEADER_SIZE])
    if magic != MAGIC:
        msg = f"Invalid magic: {magic!r}"
        raise ValueError(msg)
    data = chunk[HEADER_SIZE:]
    return seq, total, crc, flags, data


def fragment(payload: bytes, chunk_size: int) -> list[bytes]:
    """Split payload into chunks with headers.

    The first chunk includes the SHA-256 hash of the original payload
    prepended to the data (32 bytes).

    Args:
        payload: Data to fragment.
        chunk_size: Maximum data bytes per chunk (excluding header).

    Returns:
        List of complete chunks (header + data).

    Raises:
        ValueError: If chunk_size is too small.
    """
    if chunk_size < 33:
        msg = "chunk_size must be >= 33 to fit SHA-256 hash in first chunk"
        raise ValueError(msg)

    sha256 = hashlib.sha256(payload).digest()

    # First chunk data starts with SHA-256 hash
    first_data_limit = chunk_size - 32  # reserve space for hash
    pieces: list[bytes] = []

    if len(payload) <= first_data_limit:
        pieces.append(sha256 + payload)
    else:
        pieces.append(sha256 + payload[:first_data_limit])
        remaining = payload[first_data_limit:]
        while remaining:
            pieces.append(remaining[:chunk_size])
            remaining = remaining[chunk_size:]

    total = len(pieces)
    chunks: list[bytes] = []

    for i, data in enumerate(pieces):
        flags = 0
        if i == 0:
            flags |= FLAG_FIRST
        if i == total - 1:
            flags |= FLAG_LAST
        crc = zlib.crc32(data) & 0xFFFFFFFF
        header = _make_header(seq=i, total=total, crc=crc, flags=flags)
        chunks.append(header + data)

    return chunks
