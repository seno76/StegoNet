"""Chunk reassembly with out-of-order support and integrity verification.

Collects fragmented chunks, reorders by sequence number,
verifies CRC32 per chunk and SHA-256 of the full payload.
"""

import hashlib
import zlib

from netstego.core.fragmentation import FLAG_FIRST, FLAG_LAST, parse_header


class ReassemblyError(Exception):
    """Raised when reassembly fails."""


class Reassembler:
    """Collects chunks and reassembles the original payload.

    Supports out-of-order delivery. Call `add_chunk` for each
    received chunk, then `try_reassemble` to attempt full assembly.
    """

    def __init__(self) -> None:
        self._chunks: dict[int, tuple[int, bytes]] = {}  # seq -> (flags, data)
        self._total: int | None = None
        self._duplicates: int = 0

    @property
    def received_count(self) -> int:
        """Number of unique chunks received so far."""
        return len(self._chunks)

    @property
    def duplicates_received(self) -> int:
        """Number of duplicate chunks discarded."""
        return self._duplicates

    @property
    def total_expected(self) -> int | None:
        """Total chunks expected, or None if unknown yet."""
        return self._total

    @property
    def missing_seqs(self) -> list[int]:
        """List of missing sequence numbers."""
        if self._total is None:
            return []
        return [i for i in range(self._total) if i not in self._chunks]

    def add_chunk(self, raw_chunk: bytes) -> int:
        """Parse and store a chunk.

        Args:
            raw_chunk: Complete chunk bytes (header + data).

        Returns:
            The sequence number of the added chunk.

        Raises:
            ValueError: If chunk is malformed.
            ReassemblyError: If CRC32 check fails.
        """
        seq, total, crc, flags, data = parse_header(raw_chunk)

        # Verify CRC32
        actual_crc = zlib.crc32(data) & 0xFFFFFFFF
        if actual_crc != crc:
            msg = f"CRC32 mismatch for chunk {seq}: expected {crc:#010x}, got {actual_crc:#010x}"
            raise ReassemblyError(msg)

        # Verify/set total
        if self._total is None:
            self._total = total
        elif self._total != total:
            msg = f"Total mismatch: expected {self._total}, got {total}"
            raise ReassemblyError(msg)

        if seq in self._chunks:
            self._duplicates += 1
            return seq

        self._chunks[seq] = (flags, data)
        return seq

    def is_complete(self) -> bool:
        """Check if all chunks have been received."""
        if self._total is None:
            return False
        return len(self._chunks) == self._total

    def try_reassemble(self) -> bytes:
        """Attempt to reassemble the full payload.

        Returns:
            The original payload bytes.

        Raises:
            ReassemblyError: If chunks are missing, flags are inconsistent,
                or SHA-256 verification fails.
        """
        if not self.is_complete():
            missing = self.missing_seqs
            msg = f"Missing {len(missing)} chunks: {missing[:10]}"
            raise ReassemblyError(msg)

        # Sort by sequence
        ordered = sorted(self._chunks.items())

        # Verify first/last flags
        first_flags = ordered[0][1][0]
        if not (first_flags & FLAG_FIRST):
            msg = "First chunk missing FLAG_FIRST"
            raise ReassemblyError(msg)

        last_flags = ordered[-1][1][0]
        if not (last_flags & FLAG_LAST):
            msg = "Last chunk missing FLAG_LAST"
            raise ReassemblyError(msg)

        # Extract SHA-256 from first chunk (first 32 bytes of data)
        first_data = ordered[0][1][1]
        if len(first_data) < 32:
            msg = "First chunk too short to contain SHA-256 hash"
            raise ReassemblyError(msg)

        expected_hash = first_data[:32]
        payload_parts = [first_data[32:]]

        # Append remaining chunks
        for _seq, (_, data) in ordered[1:]:
            payload_parts.append(data)

        payload = b"".join(payload_parts)

        # Verify SHA-256
        actual_hash = hashlib.sha256(payload).digest()
        if actual_hash != expected_hash:
            msg = "SHA-256 verification failed: payload corrupted"
            raise ReassemblyError(msg)

        return payload

    def reset(self) -> None:
        """Clear all received chunks."""
        self._chunks.clear()
        self._total = None
        self._duplicates = 0
