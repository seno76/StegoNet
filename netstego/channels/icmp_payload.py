"""ICMP Echo payload steganographic channel.

Hides data in the payload (data) field of ICMP Echo Request packets.
Maximum payload: 1472 bytes (MTU 1500 - 20 IP header - 8 ICMP header).

Reference: RFC 792 — Echo / Echo Reply message format.
"""

import struct

from scapy.layers.inet import ICMP, IP
from scapy.packet import Packet, Raw

from netstego.channels.base import StegoChannel

MAX_ICMP_PAYLOAD = 1472


class IcmpPayloadChannel(StegoChannel):
    """Steganographic channel using ICMP Echo Request payload.

    Each packet carries up to 1472 bytes of hidden data in the
    ICMP payload field. A 2-byte length prefix is prepended so the
    decoder knows how many bytes are valid in each packet.
    """

    @property
    def bits_per_packet(self) -> int:
        return MAX_ICMP_PAYLOAD * 8

    @property
    def protocol_filter(self) -> str:
        return "icmp and src host {ip}"

    def encode(self, data: bytes, dest_ip: str, **kwargs) -> list[Packet]:
        """Encode data into ICMP Echo Request packets.

        Args:
            data: Payload bytes to embed.
            dest_ip: Destination IP address.

        Returns:
            List of ICMP packets with hidden data.
        """
        # Max data per packet: MAX_ICMP_PAYLOAD - 2 bytes for length prefix
        max_data = MAX_ICMP_PAYLOAD - 2
        packets: list[Packet] = []
        offset = 0
        seq = 0

        while offset < len(data):
            chunk = data[offset : offset + max_data]
            # Length prefix (uint16 BE) + chunk data, padded to look normal
            payload = struct.pack(">H", len(chunk)) + chunk
            pkt = IP(dst=dest_ip) / ICMP(type=8, code=0, seq=seq) / Raw(load=payload)
            packets.append(pkt)
            offset += max_data
            seq += 1

        return packets

    def decode(self, packets: list[Packet]) -> bytes:
        """Decode hidden data from ICMP packets.

        Args:
            packets: List of captured ICMP packets.

        Returns:
            Extracted payload bytes.
        """
        # Sort by ICMP sequence number
        sorted_pkts = sorted(packets, key=lambda p: p[ICMP].seq)
        parts: list[bytes] = []

        for pkt in sorted_pkts:
            raw = bytes(pkt[Raw].load)
            length = struct.unpack(">H", raw[:2])[0]
            parts.append(raw[2 : 2 + length])

        return b"".join(parts)
