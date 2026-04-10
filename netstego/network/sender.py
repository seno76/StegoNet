"""Sender module: encrypts, fragments, encodes, and transmits steganographic packets.

Handles the full pipeline:
    1. Read file -> encrypt with AES-256-GCM
    2. Fragment ciphertext into chunks with internal headers
    3. Frame chunks with length prefixes and encode via StegoChannel
    4. Send packets with configurable rate limiting and jitter
    5. Optionally save sent packets to PCAP
"""

import platform
import random
import struct
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.progress import Progress
from scapy.sendrecv import send as scapy_send
from scapy.utils import wrpcap

from netstego.channels.base import StegoChannel
from netstego.config import TimingConfig
from netstego.core.crypto import encrypt, load_key
from netstego.core.fragmentation import fragment

console = Console()


def check_privileges() -> None:
    """Verify that we have raw socket privileges.

    On Linux/macOS checks for root or CAP_NET_RAW.
    On Windows, Scapy uses Npcap/WinPcap which requires admin.

    Raises:
        SystemExit: If insufficient privileges.
    """
    if platform.system() == "Windows":
        import ctypes

        if not ctypes.windll.shell32.IsUserAnAdmin():
            console.print(
                "[red]Error:[/red] Administrator privileges required.\n"
                "Run the terminal as Administrator."
            )
            sys.exit(1)
    else:
        import os

        if os.geteuid() != 0:
            try:
                import socket

                s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
                s.close()
            except (PermissionError, OSError):
                console.print(
                    "[red]Error:[/red] Root or CAP_NET_RAW required.\n"
                    "Run: sudo netstego ... or setcap cap_net_raw+ep $(which python3)"
                )
                sys.exit(1)


def get_channel(channel_name: str) -> StegoChannel:
    """Instantiate a StegoChannel by config name.

    Args:
        channel_name: One of 'icmp', 'ip-id', 'tcp-isn', 'dns', 'tcp-ts'.

    Returns:
        An instance of the corresponding StegoChannel.

    Raises:
        ValueError: If channel name is unknown.
    """
    if channel_name == "icmp":
        from netstego.channels.icmp_payload import IcmpPayloadChannel

        return IcmpPayloadChannel()
    if channel_name == "ip-id":
        from netstego.channels.ip_id import IpIdChannel

        return IpIdChannel()
    if channel_name == "tcp-isn":
        from netstego.channels.tcp_isn import TcpIsnChannel

        return TcpIsnChannel()
    if channel_name == "dns":
        from netstego.channels.dns_query import DnsQueryChannel

        return DnsQueryChannel()
    if channel_name == "tcp-ts":
        from netstego.channels.tcp_timestamp import TcpTimestampChannel

        return TcpTimestampChannel()

    msg = f"Unknown channel: {channel_name!r}"
    raise ValueError(msg)


def frame_chunks(chunks: list[bytes]) -> bytes:
    """Frame chunks with 4-byte length prefixes for transmission.

    Format: [len1(4)][chunk1][len2(4)][chunk2]...

    Args:
        chunks: List of raw chunk bytes (header + data).

    Returns:
        Framed byte stream.
    """
    parts = []
    for chunk in chunks:
        parts.append(struct.pack(">I", len(chunk)))
        parts.append(chunk)
    return b"".join(parts)


def send_data(
    data: bytes,
    dest_ip: str,
    key_path: Path,
    channel_name: str,
    timing: TimingConfig | None = None,
    redundancy: int = 1,
    pcap_out: Path | None = None,
    dry_run: bool = False,
) -> int:
    """Encrypt, fragment, and send data through a steganographic channel.

    Args:
        data: Raw plaintext bytes to send.
        dest_ip: Destination IP address.
        key_path: Path to the AES-256 key file.
        channel_name: Name of the steganographic channel.
        timing: Timing configuration (rate, jitter). Uses defaults if None.
        redundancy: Number of times to send each chunk (for packet loss tolerance).
        pcap_out: Optional path to save sent packets as PCAP.
        dry_run: If True, build packets and save PCAP without sending over network.

    Returns:
        Total number of packets sent.
    """
    if not dry_run:
        check_privileges()

    if timing is None:
        timing = TimingConfig()

    key = load_key(key_path)
    console.print(f"[dim]Key loaded from {key_path}[/dim]")

    console.print(f"[dim]Data size: {len(data)} bytes[/dim]")

    ciphertext = encrypt(data, key)
    console.print(f"[dim]Ciphertext size: {len(ciphertext)} bytes[/dim]")

    channel = get_channel(channel_name)

    bytes_per_packet = channel.bits_per_packet // 8
    overhead = 17 + 4  # fragmentation header + length-prefix frame
    if bytes_per_packet > overhead + 33:
        chunk_data_size = bytes_per_packet - overhead
    else:
        chunk_data_size = 128

    chunks = fragment(ciphertext, chunk_data_size)
    console.print(
        f"[dim]Fragmented into {len(chunks)} chunks "
        f"({chunk_data_size} data bytes/chunk)[/dim]"
    )

    # Apply redundancy: repeat each chunk N times for packet loss tolerance.
    if redundancy > 1:
        redundant_chunks = []
        for chunk in chunks:
            for _ in range(redundancy):
                redundant_chunks.append(chunk)
        random.shuffle(redundant_chunks)
        console.print(
            f"[dim]Redundancy x{redundancy}: {len(redundant_chunks)} chunks "
            f"({len(chunks)} unique)[/dim]"
        )
        chunks = redundant_chunks

    framed = frame_chunks(chunks)
    all_packets = channel.encode(framed, dest_ip)

    total_packets = len(all_packets)
    console.print(
        f"[bold green]Sending {total_packets} packets[/bold green] "
        f"via [cyan]{channel.name}[/cyan] to [cyan]{dest_ip}[/cyan]"
    )

    base_delay = 1.0 / timing.rate_pps if timing.rate_pps > 0 else 0.0

    with Progress(console=console) as progress:
        label = "[green]Building packets..." if dry_run else "[green]Transmitting..."
        task = progress.add_task(label, total=total_packets)
        for pkt in all_packets:
            if not dry_run:
                scapy_send(pkt, verbose=False)
            progress.advance(task)

            if not dry_run and base_delay > 0:
                jitter = random.uniform(
                    -timing.jitter_factor * base_delay,
                    timing.jitter_factor * base_delay,
                )
                delay = max(0.0, base_delay + jitter)
                time.sleep(delay)

    if pcap_out is not None:
        wrpcap(str(pcap_out), all_packets)
        console.print(f"[dim]Packets saved to {pcap_out}[/dim]")

    console.print(
        f"[bold green]Done![/bold green] Sent {total_packets} packets "
        f"({len(ciphertext)} bytes encrypted)."
    )
    return total_packets
