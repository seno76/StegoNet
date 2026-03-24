"""Detection orchestrator: combines statistical, ML, and signature methods.

Analyzes PCAP files or live packet captures for signs of
steganographic covert channels.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console
from rich.table import Table
from scapy.layers.dns import DNSQR
from scapy.layers.inet import ICMP, IP, TCP
from scapy.packet import Raw
from scapy.utils import rdpcap

from netstego.detection.ml_detector import MLResult, detect_isolation_forest, extract_features
from netstego.detection.signatures import SignatureMatch, detect_signatures
from netstego.detection.statistical import (
    StatResult,
    chi_squared_uniformity,
    ipd_regularity,
    ks_test_ipd,
    shannon_entropy,
)

console = Console()


@dataclass
class AnalysisReport:
    """Complete analysis report."""

    source: str
    total_packets: int
    statistical_results: list[StatResult] = field(default_factory=list)
    ml_result: MLResult | None = None
    signature_matches: list[SignatureMatch] = field(default_factory=list)
    is_suspicious: bool = False
    confidence: float = 0.0

    def to_dict(self) -> dict:
        """Serialize report to dictionary."""
        return {
            "source": self.source,
            "total_packets": self.total_packets,
            "is_suspicious": self.is_suspicious,
            "confidence": self.confidence,
            "statistical": [
                {
                    "method": r.method,
                    "metric": r.metric,
                    "score": r.score,
                    "p_value": r.p_value,
                    "is_anomaly": r.is_anomaly,
                    "details": r.details,
                }
                for r in self.statistical_results
            ],
            "ml": {
                "method": self.ml_result.method,
                "anomaly_ratio": self.ml_result.anomaly_ratio,
                "is_anomaly": self.ml_result.is_anomaly,
                "details": self.ml_result.details,
            }
            if self.ml_result
            else None,
            "signatures": [
                {
                    "packet_index": m.packet_index,
                    "pattern": m.pattern,
                    "confidence": m.confidence,
                    "details": m.details,
                }
                for m in self.signature_matches
            ],
        }


def _extract_packet_data(packets: list) -> dict:
    """Extract field values, timestamps, and payloads from packets.

    Returns dict with keys: ip_ids, tcp_seqs, timestamps, payloads, ipds, sizes.
    """
    ip_ids = []
    tcp_seqs = []
    timestamps = []
    payloads = []
    sizes = []

    for pkt in packets:
        if pkt.haslayer(IP):
            ip_ids.append(pkt[IP].id)
        if pkt.haslayer(TCP):
            tcp_seqs.append(pkt[TCP].seq)
        ts = float(pkt.time) if hasattr(pkt, "time") else 0.0
        timestamps.append(ts)
        if pkt.haslayer(Raw):
            payloads.append(bytes(pkt[Raw].load))
        else:
            payloads.append(b"")
        sizes.append(len(pkt))

    # Compute inter-packet delays
    ipds = []
    for i in range(1, len(timestamps)):
        ipds.append(timestamps[i] - timestamps[i - 1])

    return {
        "ip_ids": ip_ids,
        "tcp_seqs": tcp_seqs,
        "timestamps": timestamps,
        "payloads": payloads,
        "ipds": ipds,
        "sizes": sizes,
    }


def analyze_packets(
    packets: list,
    source: str = "unknown",
    methods: list[str] | None = None,
    alpha: float = 0.05,
    ml_contamination: float = 0.05,
) -> AnalysisReport:
    """Run detection analysis on a list of packets.

    Args:
        packets: List of Scapy packets.
        source: Source description (file path or interface).
        methods: List of methods to run: 'statistical', 'ml', 'signatures'.
                 Default: all methods.
        alpha: Significance level for statistical tests.
        ml_contamination: IsolationForest contamination parameter.

    Returns:
        AnalysisReport with all results.
    """
    if methods is None:
        methods = ["statistical", "ml", "signatures"]

    report = AnalysisReport(source=source, total_packets=len(packets))
    data = _extract_packet_data(packets)

    # Statistical tests
    if "statistical" in methods:
        if data["ip_ids"]:
            report.statistical_results.append(
                chi_squared_uniformity(data["ip_ids"], alpha)
            )
            report.statistical_results.append(shannon_entropy(data["ip_ids"]))
        if data["tcp_seqs"]:
            report.statistical_results.append(
                chi_squared_uniformity(data["tcp_seqs"], alpha)
            )
            report.statistical_results.append(shannon_entropy(data["tcp_seqs"]))
        if data["ipds"]:
            report.statistical_results.append(ks_test_ipd(data["ipds"], alpha))
            report.statistical_results.append(ipd_regularity(data["ipds"]))

    # ML detection
    if "ml" in methods:
        field_values = data["ip_ids"] or data["tcp_seqs"] or [0] * len(packets)
        features = extract_features(
            field_values, data["timestamps"], data["sizes"]
        )
        if len(features) >= 10:
            report.ml_result = detect_isolation_forest(features, ml_contamination)

    # Signature detection
    if "signatures" in methods:
        report.signature_matches = detect_signatures(data["payloads"])

    # Compute overall suspicion
    anomaly_count = sum(1 for r in report.statistical_results if r.is_anomaly)
    total_tests = len(report.statistical_results)
    stat_ratio = anomaly_count / total_tests if total_tests > 0 else 0.0

    ml_suspicious = report.ml_result.is_anomaly if report.ml_result else False
    sig_count = len(report.signature_matches)

    # Weighted confidence
    confidence = 0.0
    if stat_ratio > 0.5:
        confidence += 0.4
    if ml_suspicious:
        confidence += 0.3
    if sig_count > 0:
        confidence += 0.3

    report.is_suspicious = confidence >= 0.4
    report.confidence = confidence

    return report


def analyze_pcap(
    pcap_path: Path,
    methods: list[str] | None = None,
    alpha: float = 0.05,
    ml_contamination: float = 0.05,
) -> AnalysisReport:
    """Analyze a PCAP file for covert channels.

    Args:
        pcap_path: Path to the PCAP file.
        methods: Detection methods to use.
        alpha: Statistical significance level.
        ml_contamination: ML contamination parameter.

    Returns:
        AnalysisReport.
    """
    packets = rdpcap(str(pcap_path))
    return analyze_packets(
        list(packets),
        source=str(pcap_path),
        methods=methods,
        alpha=alpha,
        ml_contamination=ml_contamination,
    )


def print_report(report: AnalysisReport) -> None:
    """Print analysis report to console using rich."""
    verdict = "[bold red]SUSPICIOUS[/bold red]" if report.is_suspicious else "[bold green]CLEAN[/bold green]"
    console.print(f"\n{'='*60}")
    console.print(f"[bold]Detection Report:[/bold] {report.source}")
    console.print(f"Packets analyzed: {report.total_packets}")
    console.print(f"Verdict: {verdict} (confidence: {report.confidence:.0%})")
    console.print(f"{'='*60}")

    if report.statistical_results:
        table = Table(title="Statistical Tests")
        table.add_column("Method")
        table.add_column("Metric")
        table.add_column("Score")
        table.add_column("P-value")
        table.add_column("Anomaly")

        for r in report.statistical_results:
            style = "red" if r.is_anomaly else "green"
            table.add_row(
                r.method,
                r.metric,
                f"{r.score:.4f}",
                f"{r.p_value:.6f}" if r.p_value is not None else "N/A",
                f"[{style}]{'YES' if r.is_anomaly else 'NO'}[/{style}]",
            )
        console.print(table)

    if report.ml_result:
        ml = report.ml_result
        style = "red" if ml.is_anomaly else "green"
        console.print(f"\n[bold]ML Detection ({ml.method}):[/bold]")
        console.print(f"  Anomaly ratio: [{style}]{ml.anomaly_ratio:.2%}[/{style}]")
        console.print(f"  Details: {ml.details}")

    if report.signature_matches:
        console.print(f"\n[bold red]Signatures found: {len(report.signature_matches)}[/bold red]")
        for m in report.signature_matches[:10]:
            console.print(f"  Packet #{m.packet_index}: {m.pattern} — {m.details}")
