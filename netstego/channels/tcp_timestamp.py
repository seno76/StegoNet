"""TCP Timestamp steganographic channel.

Hides data in the TCP Timestamp Value (TSval) option field.
Each packet carries 4 bytes (32 bits) of hidden data in the TSval.

Reference: RFC 7323, Section 3 — TCP Timestamps Option.
"""

import struct

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet

from netstego.channels.base import StegoChannel

BITS_PER_PACKET = 32


class TcpTimestampChannel(StegoChannel):
    """Steganographic channel using TCP Timestamp (TSval).

    Each packet embeds 4 bytes of data in the TCP Timestamp Value option.
    Uses ACK packets with incrementing sequence numbers for ordering.
    """

    @property
    def bits_per_packet(self) -> int:
        return BITS_PER_PACKET

    @property
    def protocol_filter(self) -> str:
        return "tcp and src host {ip}"

    def encode(self, data: bytes, dest_ip: str, **kwargs) -> list[Packet]:
        """Encode data into TCP packets using the Timestamp option.

        Args:
            data: Payload bytes to embed.
            dest_ip: Destination IP address.

        Returns:
            List of TCP packets with data in TSval.
        """
        base_port = kwargs.get("base_port", 20000)
        packets: list[Packet] = []
        offset = 0
        seq_num = 0

        while offset < len(data):
            chunk = data[offset : offset + 4]
            padded = chunk.ljust(4, b"\x00")
            tsval = struct.unpack(">I", padded)[0]
            # TSecr is set to 0 (no echo)
            ts_option = ("Timestamp", (tsval, 0))
            pkt = IP(dst=dest_ip) / TCP(
                sport=50000 + seq_num,
                dport=base_port,
                seq=seq_num,
                flags="A",
                options=[ts_option],
            )
            packets.append(pkt)
            offset += 4
            seq_num += 1

        # Termination packet with total data length in TSval
        ts_option = ("Timestamp", (len(data), 1))  # TSecr=1 marks termination
        term_pkt = IP(dst=dest_ip) / TCP(
            sport=50000 + seq_num,
            dport=base_port,
            seq=seq_num,
            flags="A",
            options=[ts_option],
        )
        packets.append(term_pkt)
        return packets

    def decode(self, packets: list[Packet]) -> bytes:
        """Decode hidden data from TCP Timestamp options.

        Args:
            packets: List of captured TCP packets.

        Returns:
            Extracted payload bytes.
        """
        tcp_pkts = [p for p in packets if p.haslayer(TCP)]
        sorted_pkts = sorted(tcp_pkts, key=lambda p: p[TCP].seq)

        if not sorted_pkts:
            return b""

        total_len = None
        data_pkts = []

        for pkt in sorted_pkts:
            options = pkt[TCP].options
            tsval, tsecr = None, None
            for opt_name, opt_val in options:
                if opt_name == "Timestamp":
                    tsval, tsecr = opt_val
                    break

            if tsval is None:
                continue

            if tsecr == 1:
                # Termination packet
                total_len = tsval
            else:
                data_pkts.append((tsval,))

        parts: list[bytes] = []
        for (tsval,) in data_pkts:
            parts.append(struct.pack(">I", tsval))

        result = b"".join(parts)
        if total_len is not None:
            result = result[:total_len]
        return result
