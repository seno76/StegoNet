"""TCP Initial Sequence Number steganographic channel.

Hides data in the 32-bit TCP Sequence Number field of SYN packets.
Each SYN packet carries 4 bytes (32 bits) of hidden data.

Reference: RFC 793, Section 3.1 — TCP Header Format.
           RFC 6528 — Defending Against Sequence Number Attacks.
"""

import struct

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet

from netstego.channels.base import StegoChannel

BITS_PER_PACKET = 32


class TcpIsnChannel(StegoChannel):
    """Steganographic channel using TCP Initial Sequence Numbers.

    Each TCP SYN packet embeds 4 bytes of data in the sequence number.
    Uses incrementing destination ports to maintain ordering.
    """

    @property
    def bits_per_packet(self) -> int:
        return BITS_PER_PACKET

    @property
    def protocol_filter(self) -> str:
        return "tcp[tcpflags] & tcp-syn != 0 and src host {ip}"

    def encode(self, data: bytes, dest_ip: str, **kwargs) -> list[Packet]:
        """Encode data into TCP SYN packets using the sequence number.

        Args:
            data: Payload bytes to embed.
            dest_ip: Destination IP address.

        Returns:
            List of TCP SYN packets with data in ISN.
        """
        base_port = kwargs.get("base_port", 10000)
        packets: list[Packet] = []
        offset = 0
        port_offset = 0

        while offset < len(data):
            chunk = data[offset : offset + 4]
            # Pad to 4 bytes if needed
            padded = chunk.ljust(4, b"\x00")
            isn = struct.unpack(">I", padded)[0]
            dport = base_port + port_offset
            pkt = IP(dst=dest_ip) / TCP(
                sport=40000 + port_offset,
                dport=dport,
                seq=isn,
                flags="S",
            )
            packets.append(pkt)
            offset += 4
            port_offset += 1

        # Termination SYN with total data length in seq, flagged by special sport
        term_pkt = IP(dst=dest_ip) / TCP(
            sport=65535,
            dport=base_port + port_offset,
            seq=len(data),
            flags="S",
        )
        packets.append(term_pkt)
        return packets

    def decode(self, packets: list[Packet]) -> bytes:
        """Decode hidden data from TCP SYN sequence numbers.

        Args:
            packets: List of captured TCP SYN packets.

        Returns:
            Extracted payload bytes.
        """
        tcp_pkts = [p for p in packets if p.haslayer(TCP) and p[TCP].flags & 0x02]
        sorted_pkts = sorted(tcp_pkts, key=lambda p: p[TCP].dport)

        if not sorted_pkts:
            return b""

        # Check for termination packet (sport=65535)
        term_pkt = sorted_pkts[-1]
        if term_pkt[TCP].sport == 65535:
            total_len = term_pkt[TCP].seq
            data_pkts = sorted_pkts[:-1]
        else:
            total_len = len(sorted_pkts) * 4
            data_pkts = sorted_pkts

        parts: list[bytes] = []
        for pkt in data_pkts:
            isn = pkt[TCP].seq
            parts.append(struct.pack(">I", isn))

        result = b"".join(parts)
        return result[:total_len]
