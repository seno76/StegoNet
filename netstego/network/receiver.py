"""Receiver module: sniffs packets, decodes, reassembles, and decrypts.

Handles the full receive pipeline:
    1. Sniff packets via AsyncSniffer with BPF filter (or read from PCAP)
    2. Decode packets via the chosen StegoChannel
    3. Unframe length-prefixed chunks
    4. Reassemble chunks with out-of-order support
    5. Decrypt with AES-256-GCM and write output file
"""

import struct
import sys
from pathlib import Path

from rich.console import Console
from scapy.sendrecv import AsyncSniffer
from scapy.utils import rdpcap, wrpcap

from netstego.channels.base import StegoChannel
from netstego.core.crypto import decrypt, load_key
from netstego.core.reassembly import Reassembler
from netstego.network.sender import check_privileges, get_channel

console = Console()


def unframe_chunks(data: bytes) -> list[bytes]:
    """Extract length-prefixed chunks from a framed byte stream.

    Format: [len1(4)][chunk1][len2(4)][chunk2]...

    Args:
        data: Framed byte stream from channel.decode().

    Returns:
        List of raw chunk bytes.
    """
    chunks = []
    offset = 0
    while offset + 4 <= len(data):
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        offset += 4
        if offset + length > len(data):
            break
        chunks.append(data[offset : offset + length])
        offset += length
    return chunks


def receive_file(
    bind_ip: str,
    key_path: Path,
    output_path: Path,
    channel_name: str,
    timeout: int = 60,
    pcap_out: Path | None = None,
    pcap_in: Path | None = None,
) -> bool:
    """Receive and reconstruct a file from a steganographic channel.

    Args:
        bind_ip: IP address to listen on (used in BPF filter).
        key_path: Path to the AES-256 key file.
        output_path: Path to write the decrypted output file.
        channel_name: Name of the steganographic channel.
        timeout: Sniffing timeout in seconds.
        pcap_out: Optional path to save captured packets as PCAP.
        pcap_in: Optional PCAP file to read instead of sniffing.

    Returns:
        True if file was successfully received and written.
    """
    if pcap_in is None:
        check_privileges()

    key = load_key(key_path)
    console.print(f"[dim]Key loaded from {key_path}[/dim]")

    channel = get_channel(channel_name)

    if pcap_in is not None:
        # Read from PCAP file instead of sniffing
        console.print(f"[bold blue]Reading from PCAP:[/bold blue] {pcap_in}")
        all_packets = list(rdpcap(str(pcap_in)))
    else:
        # Sniff live traffic
        bpf_filter = channel.protocol_filter.format(ip=bind_ip)
        console.print(
            f"[bold blue]Listening[/bold blue] on {bind_ip} "
            f"via [cyan]{channel.name}[/cyan] (timeout={timeout}s)"
        )
        console.print(f"[dim]BPF filter: {bpf_filter}[/dim]")

        sniffer = AsyncSniffer(filter=bpf_filter, store=True)
        sniffer.start()

        try:
            sniffer.join(timeout=timeout)
        except KeyboardInterrupt:
            console.print("[yellow]Interrupted by user[/yellow]")
        finally:
            sniffer.stop()

        all_packets = list(sniffer.results) if sniffer.results else []

    console.print(f"[dim]Captured {len(all_packets)} packets[/dim]")

    if not all_packets:
        console.print("[red]Error:[/red] No packets received.")
        return False

    # Save captured packets if requested
    if pcap_out is not None:
        wrpcap(str(pcap_out), all_packets)
        console.print(f"[dim]Packets saved to {pcap_out}[/dim]")

    # Decode packets via channel
    try:
        raw_data = channel.decode(all_packets)
    except Exception as e:
        console.print(f"[red]Error decoding packets:[/red] {e}")
        return False

    console.print(f"[dim]Decoded {len(raw_data)} bytes from packets[/dim]")

    # Unframe and reassemble chunks
    chunks = unframe_chunks(raw_data)
    console.print(f"[dim]Extracted {len(chunks)} chunks[/dim]")

    if not chunks:
        console.print("[red]Error:[/red] No valid chunks found in decoded data.")
        return False

    reassembler = Reassembler()
    for chunk in chunks:
        try:
            reassembler.add_chunk(chunk)
        except Exception as e:
            console.print(f"[yellow]Warning:[/yellow] Skipping bad chunk: {e}")

    if not reassembler.is_complete():
        missing = reassembler.missing_seqs
        console.print(
            f"[red]Error:[/red] Reassembly incomplete. "
            f"Missing {len(missing)} chunks: {missing[:10]}"
        )
        return False

    try:
        ciphertext = reassembler.try_reassemble()
    except Exception as e:
        console.print(f"[red]Error during reassembly:[/red] {e}")
        return False

    console.print(f"[dim]Reassembled {len(ciphertext)} bytes of ciphertext[/dim]")

    # Decrypt
    try:
        plaintext = decrypt(ciphertext, key)
    except Exception as e:
        console.print(f"[red]Error during decryption:[/red] {e}")
        return False

    # Write output file
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(plaintext)
    console.print(
        f"[bold green]Done![/bold green] Received {len(plaintext)} bytes "
        f"-> {output_path}"
    )
    return True
