"""DNS QNAME subdomain steganographic channel.

Hides data in DNS query names using base32-encoded subdomains.
Each DNS query carries up to ~63 bytes of encoded data per label,
with up to 3 labels, yielding ~30 raw bytes per packet.

Reference: RFC 1035, Section 4 — Domain Name Message Format.
"""

import base64
import struct

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.packet import Packet

from netstego.channels.base import StegoChannel

# Max label length 63, base32 expands 5 bytes to 8 chars
# Use 2 labels of 55 chars each → ~34 raw bytes per label pair
# Conservative: 30 raw bytes per packet
MAX_RAW_BYTES = 30
DOMAIN_SUFFIX = "stego.local"


class DnsQueryChannel(StegoChannel):
    """Steganographic channel using DNS QNAME subdomains.

    Data is base32-encoded into subdomain labels of DNS queries.
    """

    @property
    def bits_per_packet(self) -> int:
        return MAX_RAW_BYTES * 8

    @property
    def protocol_filter(self) -> str:
        return "udp port 53 and src host {ip}"

    def encode(self, data: bytes, dest_ip: str, **kwargs) -> list[Packet]:
        """Encode data into DNS query packets.

        Args:
            data: Payload bytes to embed.
            dest_ip: Destination IP (DNS server).

        Returns:
            List of DNS query packets with data in QNAME.
        """
        packets: list[Packet] = []
        offset = 0
        tx_id = 0

        while offset < len(data):
            chunk = data[offset : offset + MAX_RAW_BYTES]
            # Base32 encode without padding
            encoded = base64.b32encode(chunk).rstrip(b"=").decode("ascii").lower()
            # Split into labels of max 63 chars
            labels = []
            for i in range(0, len(encoded), 63):
                labels.append(encoded[i : i + 63])
            qname = ".".join(labels) + "." + DOMAIN_SUFFIX + "."

            pkt = (
                IP(dst=dest_ip)
                / UDP(sport=30000 + tx_id, dport=53)
                / DNS(id=tx_id, qd=DNSQR(qname=qname, qtype="A"))
            )
            packets.append(pkt)
            offset += MAX_RAW_BYTES
            tx_id += 1

        # Termination query with data length in DNS ID field
        # and special marker in qname
        term_qname = f"term.{DOMAIN_SUFFIX}."
        term_payload = struct.pack(">I", len(data))
        term_encoded = base64.b32encode(term_payload).rstrip(b"=").decode("ascii").lower()
        term_qname = f"{term_encoded}.term.{DOMAIN_SUFFIX}."
        pkt = (
            IP(dst=dest_ip)
            / UDP(sport=30000 + tx_id, dport=53)
            / DNS(id=tx_id, qd=DNSQR(qname=term_qname, qtype="A"))
        )
        packets.append(pkt)
        return packets

    def decode(self, packets: list[Packet]) -> bytes:
        """Decode hidden data from DNS query names.

        Args:
            packets: List of captured DNS query packets.

        Returns:
            Extracted payload bytes.
        """
        dns_pkts = [p for p in packets if p.haslayer(DNS) and p.haslayer(DNSQR)]
        sorted_pkts = sorted(dns_pkts, key=lambda p: p[DNS].id)

        if not sorted_pkts:
            return b""

        total_len = None
        data_pkts = []

        for pkt in sorted_pkts:
            qname = pkt[DNSQR].qname
            if isinstance(qname, bytes):
                qname = qname.decode("ascii", errors="ignore")
            qname = qname.rstrip(".")

            # Check for termination packet
            parts = qname.split(".")
            suffix = ".".join(parts[-2:])  # e.g., "term.stego.local" or "stego.local"

            if len(parts) >= 3 and parts[-2] == "term":
                # Termination packet — extract length from first label
                encoded = parts[0].upper()
                # Restore base32 padding
                pad = (8 - len(encoded) % 8) % 8
                encoded += "=" * pad
                try:
                    length_bytes = base64.b32decode(encoded)
                    if len(length_bytes) >= 4:
                        total_len = struct.unpack(">I", length_bytes[:4])[0]
                except Exception:
                    pass
            else:
                data_pkts.append(pkt)

        parts_data: list[bytes] = []
        for pkt in data_pkts:
            qname = pkt[DNSQR].qname
            if isinstance(qname, bytes):
                qname = qname.decode("ascii", errors="ignore")
            qname = qname.rstrip(".")

            # Remove domain suffix
            labels = qname.split(".")
            # Remove last 2 labels (stego.local)
            data_labels = labels[:-2]
            encoded = "".join(data_labels).upper()
            # Restore base32 padding
            pad = (8 - len(encoded) % 8) % 8
            encoded += "=" * pad
            try:
                decoded = base64.b32decode(encoded)
                parts_data.append(decoded)
            except Exception:
                continue

        result = b"".join(parts_data)
        if total_len is not None:
            result = result[:total_len]
        return result
