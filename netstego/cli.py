"""CLI entry point for NetStego."""

from pathlib import Path

import click
from rich.console import Console

from netstego.config import TimingConfig

console = Console()


@click.group()
@click.version_option(package_name="netstego")
def cli() -> None:
    """NetStego — network packet steganography tool."""


@cli.command()
@click.option("--file", "file_path", required=True, type=click.Path(exists=True), help="File to send.")
@click.option("--channel", required=True, type=click.Choice(["ip-id", "tcp-isn", "icmp", "dns", "tcp-ts"]))
@click.option("--dest", required=True, help="Destination IP address.")
@click.option("--key-file", required=True, type=click.Path(exists=True), help="Encryption key file.")
@click.option("--rate", default=10, type=int, help="Packets per second.")
@click.option("--pcap-out", default=None, type=click.Path(), help="Save sent packets to PCAP.")
def send(file_path: str, channel: str, dest: str, key_file: str, rate: int, pcap_out: str | None) -> None:
    """Send a file through a steganographic channel."""
    from netstego.network.sender import send_file

    timing = TimingConfig(rate_pps=rate)
    send_file(
        file_path=Path(file_path),
        dest_ip=dest,
        key_path=Path(key_file),
        channel_name=channel,
        timing=timing,
        pcap_out=Path(pcap_out) if pcap_out else None,
    )


@cli.command()
@click.option("--channel", required=True, type=click.Choice(["ip-id", "tcp-isn", "icmp", "dns", "tcp-ts"]))
@click.option("--bind", required=True, help="Bind IP address.")
@click.option("--key-file", required=True, type=click.Path(exists=True), help="Encryption key file.")
@click.option("--output", required=True, type=click.Path(), help="Output file path.")
@click.option("--timeout", default=60, type=int, help="Receive timeout in seconds.")
@click.option("--pcap-out", default=None, type=click.Path(), help="Save captured packets to PCAP.")
@click.option("--pcap-in", default=None, type=click.Path(exists=True), help="Read from PCAP instead of sniffing.")
def receive(
    channel: str,
    bind: str,
    key_file: str,
    output: str,
    timeout: int,
    pcap_out: str | None,
    pcap_in: str | None,
) -> None:
    """Receive a file from a steganographic channel."""
    from netstego.network.receiver import receive_file

    success = receive_file(
        bind_ip=bind,
        key_path=Path(key_file),
        output_path=Path(output),
        channel_name=channel,
        timeout=timeout,
        pcap_out=Path(pcap_out) if pcap_out else None,
        pcap_in=Path(pcap_in) if pcap_in else None,
    )
    if not success:
        raise SystemExit(1)


@cli.command()
@click.option("--input", "input_source", required=True, help="PCAP file path.")
@click.option("--methods", default="statistical,ml,signatures", help="Detection methods (comma-separated).")
@click.option("--report", default=None, type=click.Path(), help="Report output path (JSON).")
@click.option("--threshold", default=0.05, type=float, help="Statistical significance alpha.")
def detect(input_source: str, methods: str, report: str | None, threshold: float) -> None:
    """Detect covert channels in traffic."""
    import json

    from netstego.detection.analyzer import analyze_pcap, print_report

    method_list = [m.strip() for m in methods.split(",")]
    result = analyze_pcap(
        pcap_path=Path(input_source),
        methods=method_list,
        alpha=threshold,
    )
    print_report(result)

    if report:
        report_path = Path(report)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(result.to_dict(), indent=2))
        console.print(f"[dim]Report saved to {report}[/dim]")


@cli.command()
@click.option("--session-id", default=None, help="Session ID to query.")
@click.option("--format", "fmt", default="table", type=click.Choice(["json", "table", "csv", "html"]))
@click.option("--export", "export_path", default=None, type=click.Path(), help="Export path.")
@click.option("--db", "db_path", default=None, help="Stats database path.")
def stats(session_id: str | None, fmt: str, export_path: str | None, db_path: str | None) -> None:
    """View session statistics."""
    from netstego.stats.reporter import export_csv, export_html, export_json, print_table

    if export_path and session_id:
        out = Path(export_path)
        if fmt == "json":
            export_json(db_path, session_id, out)
        elif fmt == "csv":
            export_csv(db_path, session_id, out)
        elif fmt == "html":
            export_html(db_path, session_id, out)
        else:
            print_table(db_path, session_id)
    else:
        print_table(db_path, session_id)


@cli.command()
@click.option("--channel", required=True, type=click.Choice(["ip-id", "tcp-isn", "icmp", "dns", "tcp-ts"]))
@click.option("--dest", required=True, help="Destination IP address.")
@click.option("--duration", default=10, type=int, help="Benchmark duration in seconds.")
def benchmark(channel: str, dest: str, duration: int) -> None:
    """Benchmark a steganographic channel."""
    import os
    import time

    from netstego.network.sender import get_channel

    ch = get_channel(channel)
    console.print(
        f"[bold cyan]Benchmarking[/bold cyan] {ch.name} to {dest} for {duration}s"
    )

    # Generate test data
    test_data = os.urandom(1024)
    packets_sent = 0
    start = time.time()

    while time.time() - start < duration:
        packets = ch.encode(test_data, dest)
        packets_sent += len(packets)

    elapsed = time.time() - start
    pps = packets_sent / elapsed if elapsed > 0 else 0
    bps = (packets_sent * ch.bits_per_packet) / elapsed if elapsed > 0 else 0

    console.print(f"[bold]Results:[/bold]")
    console.print(f"  Packets created: {packets_sent}")
    console.print(f"  Rate: {pps:.1f} packets/sec")
    console.print(f"  Throughput: {bps:.0f} bits/sec ({bps/8:.0f} bytes/sec)")
    console.print(f"  Bits per packet: {ch.bits_per_packet}")


@cli.command()
@click.option("--output", required=True, type=click.Path(), help="Key file output path.")
def keygen(output: str) -> None:
    """Generate a new AES-256 encryption key."""
    from netstego.core.crypto import generate_key

    key = generate_key(Path(output))
    console.print(f"[bold green]Key generated:[/bold green] {output} ({len(key)} bytes)")
