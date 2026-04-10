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
@click.option("--file", "file_path", default=None, type=click.Path(exists=True), help="File to send.")
@click.option("--text", "text_input", default=None, help="Text string to send (alternative to --file).")
@click.option("--channel", required=True, type=click.Choice(["ip-id", "tcp-isn", "icmp", "dns", "tcp-ts"]))
@click.option("--dest", required=True, help="Destination IP address.")
@click.option("--key-file", required=True, type=click.Path(exists=True), help="Encryption key file.")
@click.option("--rate", default=10, type=int, help="Packets per second.")
@click.option("--redundancy", default=1, type=int, help="Send each chunk N times for loss tolerance.")
@click.option("--pcap-out", default=None, type=click.Path(), help="Save sent packets to PCAP.")
@click.option("--dry-run", is_flag=True, help="Build packets and save PCAP without sending over network.")
def send(
    file_path: str | None,
    text_input: str | None,
    channel: str,
    dest: str,
    key_file: str,
    rate: int,
    redundancy: int,
    pcap_out: str | None,
    dry_run: bool,
) -> None:
    """Send a file or text through a steganographic channel."""
    from netstego.network.sender import send_data

    if file_path is None and text_input is None:
        raise click.UsageError("Either --file or --text must be provided.")
    if file_path is not None and text_input is not None:
        raise click.UsageError("Use either --file or --text, not both.")
    if dry_run and pcap_out is None:
        raise click.UsageError("--dry-run requires --pcap-out to save packets.")

    if text_input is not None:
        data = text_input.encode("utf-8")
        console.print(f"[dim]Text input: {len(data)} bytes[/dim]")
    else:
        data = Path(file_path).read_bytes()
        console.print(f"[dim]File: {file_path} ({len(data)} bytes)[/dim]")

    timing = TimingConfig(rate_pps=rate)
    send_data(
        data=data,
        dest_ip=dest,
        key_path=Path(key_file),
        channel_name=channel,
        timing=timing,
        redundancy=redundancy,
        pcap_out=Path(pcap_out) if pcap_out else None,
        dry_run=dry_run,
    )


@cli.command()
@click.option("--channel", required=True, type=click.Choice(["ip-id", "tcp-isn", "icmp", "dns", "tcp-ts"]))
@click.option("--sender-ip", required=True, help="Sender's IP address (used in BPF filter).")
@click.option("--key-file", required=True, type=click.Path(exists=True), help="Encryption key file.")
@click.option("--output", required=True, type=click.Path(), help="Output file path.")
@click.option("--timeout", default=60, type=int, help="Receive timeout in seconds.")
@click.option("--pcap-out", default=None, type=click.Path(), help="Save captured packets to PCAP.")
@click.option("--pcap-in", default=None, type=click.Path(exists=True), help="Read from PCAP instead of sniffing.")
@click.option("--iface", default=None, help="Network interface for sniffing (e.g. eth0, Wi-Fi).")
def receive(
    channel: str,
    sender_ip: str,
    key_file: str,
    output: str,
    timeout: int,
    pcap_out: str | None,
    pcap_in: str | None,
    iface: str | None,
) -> None:
    """Receive a file from a steganographic channel."""
    from netstego.network.receiver import receive_file

    success = receive_file(
        sender_ip=sender_ip,
        key_path=Path(key_file),
        output_path=Path(output),
        channel_name=channel,
        timeout=timeout,
        pcap_out=Path(pcap_out) if pcap_out else None,
        pcap_in=Path(pcap_in) if pcap_in else None,
        iface=iface,
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


@cli.command()
@click.option("--output-dir", default="results", type=click.Path(), help="Output directory for reports and charts.")
@click.option("--skip-monitoring", is_flag=True, help="Skip detection monitoring (faster).")
@click.option("--repeat", default=3, type=int, help="Benchmark repeat count for averaging.")
@click.option("--payload-sizes", default="64,256,1024,4096,16384", help="Comma-separated payload sizes.")
def report(output_dir: str, skip_monitoring: bool, repeat: int, payload_sizes: str) -> None:
    """Run full benchmarks, generate charts and reports."""
    import json

    from rich.table import Table

    from netstego.benchmarks import run_all_benchmarks, run_all_monitoring
    from netstego.stats.charts import generate_all_charts

    out = Path(output_dir)
    data_dir = out / "data"
    charts_dir = out / "charts"
    data_dir.mkdir(parents=True, exist_ok=True)

    sizes = [int(s.strip()) for s in payload_sizes.split(",")]

    console.print("[bold cyan]Running pipeline benchmarks...[/bold cyan]")
    bench_results = run_all_benchmarks(payload_sizes=sizes, repeat=repeat)

    bench_path = data_dir / "benchmark_results.json"
    bench_path.write_text(json.dumps(bench_results, indent=2))
    console.print(f"[dim]Benchmark data saved to {bench_path}[/dim]")

    # Print summary table
    pipeline = bench_results["pipeline_benchmarks"]
    table = Table(title="Pipeline Benchmark Summary (1024 B payload)")
    table.add_column("Channel")
    table.add_column("Packets", justify="right")
    table.add_column("Total ms", justify="right")
    table.add_column("Throughput", justify="right")

    for r in pipeline:
        if r["payload_bytes"] == 1024:
            if r["throughput_Bps"] >= 1_000_000:
                tp = f"{r['throughput_Bps'] / 1_000_000:.1f} MB/s"
            elif r["throughput_Bps"] >= 1000:
                tp = f"{r['throughput_Bps'] / 1000:.1f} KB/s"
            else:
                tp = f"{r['throughput_Bps']:.0f} B/s"
            table.add_row(r["channel"], str(r["num_packets"]), f"{r['total_ms']:.2f}", tp)
    console.print(table)

    # Run monitoring (optional)
    mon_results = None
    if not skip_monitoring:
        console.print("\n[bold cyan]Running detection monitoring...[/bold cyan]")
        mon_results = run_all_monitoring()
        mon_path = data_dir / "monitoring_results.json"
        mon_path.write_text(json.dumps(mon_results, indent=2, ensure_ascii=False))
        console.print(f"[dim]Monitoring data saved to {mon_path}[/dim]")

    # Generate charts
    console.print("\n[bold cyan]Generating charts...[/bold cyan]")
    saved_charts = generate_all_charts(bench_results, mon_results, charts_dir)

    console.print(f"\n[bold green]Done![/bold green] Generated {len(saved_charts)} charts:")
    for path in saved_charts:
        console.print(f"  {path}")
