"""IP Identification field steganographic channel.

Hides data in the 16-bit IP ID field of IPv4 packets.
Each packet carries 2 bytes (16 bits) of hidden data.

Reference: RFC 791, Section 3.1 — Internet Header Format.
"""

import struct

from scapy.layers.inet import IP, ICMP
from scapy.packet import Packet, Raw

from netstego.channels.base import StegoChannel

BITS_PER_PACKET = 16


class IpIdChannel(StegoChannel):
    """Steganographic channel using the IPv4 Identification field.

    Each packet embeds 2 bytes of data in the IP ID field (16-bit).
    ICMP Echo Request is used as carrier protocol.
    """

    @property
    def bits_per_packet(self) -> int:
        return BITS_PER_PACKET

    @property
    def protocol_filter(self) -> str:
        return "icmp and src host {ip}"

    def encode(self, data: bytes, dest_ip: str, **kwargs) -> list[Packet]:
        """Encode data into IP packets using the ID field.

        Args:
            data: Payload bytes to embed.
            dest_ip: Destination IP address.

        Returns:
            List of IP/ICMP packets with data in the IP ID field.
        """
        packets: list[Packet] = []
        offset = 0
        seq = 0

        while offset < len(data):
            chunk = data[offset : offset + 2]
            # Pad to 2 bytes if needed (last chunk might be 1 byte)
            if len(chunk) == 1:
                chunk = chunk + b"\x00"
            ip_id = struct.unpack(">H", chunk)[0]
            pkt = (
                IP(dst=dest_ip, id=ip_id)
                / ICMP(type=8, code=0, seq=seq)
                / Raw(load=b"\x00" * 32)  # normal-looking ICMP payload
            )
            packets.append(pkt)
            offset += 2
            seq += 1

        # Append a termination packet with total data length in payload
        # so the decoder knows exact byte count
        term_payload = struct.pack(">I", len(data))
        pkt = (
            IP(dst=dest_ip, id=0xFFFF)
            / ICMP(type=8, code=0, seq=seq)
            / Raw(load=term_payload)
        )
        packets.append(pkt)
        return packets

    def decode(self, packets: list[Packet]) -> bytes:
        """Decode hidden data from IP ID fields.

        Args:
            packets: List of captured IP packets.

        Returns:
            Extracted payload bytes.
        """
        # Sort by ICMP sequence number
        icmp_pkts = [p for p in packets if p.haslayer(ICMP)]
        sorted_pkts = sorted(icmp_pkts, key=lambda p: p[ICMP].seq)

        if not sorted_pkts:
            return b""

        # Last packet is termination — extract original data length
        term_pkt = sorted_pkts[-1]
        term_raw = bytes(term_pkt[Raw].load) if term_pkt.haslayer(Raw) else b""
        if len(term_raw) >= 4 and term_pkt[IP].id == 0xFFFF:
            total_len = struct.unpack(">I", term_raw[:4])[0]
            data_pkts = sorted_pkts[:-1]
        else:
            # No termination packet — use all packets
            total_len = len(sorted_pkts) * 2
            data_pkts = sorted_pkts

        parts: list[bytes] = []
        for pkt in data_pkts:
            ip_id = pkt[IP].id
            parts.append(struct.pack(">H", ip_id))

        result = b"".join(parts)
        return result[:total_len]
