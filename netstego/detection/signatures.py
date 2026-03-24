"""Signature-based detection for NetStego's internal protocol.

Scans packet payloads and field patterns for the NST magic header
and other markers of the steganographic protocol.
"""

from dataclasses import dataclass

from netstego.core.fragmentation import MAGIC


@dataclass
class SignatureMatch:
    """A detected signature match."""

    packet_index: int
    field: str
    pattern: str
    confidence: float
    details: str = ""


def scan_for_magic(payloads: list[bytes]) -> list[SignatureMatch]:
    """Scan packet payloads for NST magic bytes.

    Args:
        payloads: List of raw payload bytes from packets.

    Returns:
        List of SignatureMatch for each detected occurrence.
    """
    matches = []
    for i, payload in enumerate(payloads):
        idx = payload.find(MAGIC)
        if idx != -1:
            matches.append(SignatureMatch(
                packet_index=i,
                field="payload",
                pattern="NST_MAGIC",
                confidence=1.0,
                details=f"Magic 'NST\\x00' at offset {idx}",
            ))
    return matches


def scan_for_length_prefix_pattern(payloads: list[bytes]) -> list[SignatureMatch]:
    """Detect 4-byte length prefix framing pattern.

    Checks if payloads start with a plausible 4-byte big-endian length
    followed by data of matching size.

    Args:
        payloads: List of raw payload bytes.

    Returns:
        List of SignatureMatch.
    """
    import struct

    matches = []
    for i, payload in enumerate(payloads):
        if len(payload) < 4:
            continue
        claimed_len = struct.unpack(">I", payload[:4])[0]
        if 17 <= claimed_len <= len(payload) - 4:
            # Check if the data after length prefix starts with magic
            data_after = payload[4 : 4 + claimed_len]
            if data_after[:4] == MAGIC:
                matches.append(SignatureMatch(
                    packet_index=i,
                    field="payload",
                    pattern="LENGTH_PREFIX_MAGIC",
                    confidence=0.95,
                    details=f"Length prefix {claimed_len} followed by NST magic",
                ))
    return matches


def detect_signatures(payloads: list[bytes]) -> list[SignatureMatch]:
    """Run all signature detection methods.

    Args:
        payloads: List of raw payload bytes from packets.

    Returns:
        Combined list of all signature matches.
    """
    matches = []
    matches.extend(scan_for_magic(payloads))
    matches.extend(scan_for_length_prefix_pattern(payloads))
    return matches
