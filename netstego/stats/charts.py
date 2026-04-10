"""Chart generation for benchmark and monitoring results.

All functions accept data dicts (as produced by netstego.benchmarks)
and save PNG files to the specified output directory.
"""

from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np

CHANNELS = ["icmp", "ip-id", "tcp-isn", "dns", "tcp-ts"]
CHANNEL_LABELS = {
    "icmp": "ICMP Payload",
    "ip-id": "IP ID",
    "tcp-isn": "TCP ISN",
    "dns": "DNS QNAME",
    "tcp-ts": "TCP Timestamp",
}
CHANNEL_COLORS = {
    "icmp": "#4CAF50",
    "ip-id": "#2196F3",
    "tcp-isn": "#FF9800",
    "dns": "#9C27B0",
    "tcp-ts": "#F44336",
}

_STYLE = "seaborn-v0_8-whitegrid"
_DPI = 150
_FONT_SIZE = 12


def _setup_style() -> None:
    try:
        plt.style.use(_STYLE)
    except OSError:
        plt.style.use("ggplot")
    plt.rcParams.update({"font.size": _FONT_SIZE})


def chart_throughput_comparison(
    results: list[dict], output_dir: Path, payload_size: int = 1024,
) -> Path:
    """Bar chart: throughput (B/s) per channel for a given payload size."""
    _setup_style()

    filtered = [r for r in results if r["payload_bytes"] == payload_size]
    channels = [r["channel"] for r in filtered]
    throughputs = [r["throughput_Bps"] for r in filtered]
    colors = [CHANNEL_COLORS.get(c, "#666") for c in channels]
    labels = [CHANNEL_LABELS.get(c, c) for c in channels]

    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(labels, throughputs, color=colors, edgecolor="white", linewidth=0.5)

    for bar, val in zip(bars, throughputs):
        if val >= 1_000_000:
            label = f"{val / 1_000_000:.1f} MB/s"
        elif val >= 1000:
            label = f"{val / 1000:.1f} KB/s"
        else:
            label = f"{val:.0f} B/s"
        ax.text(
            bar.get_x() + bar.get_width() / 2, bar.get_height(),
            label, ha="center", va="bottom", fontsize=11, fontweight="bold",
        )

    ax.set_ylabel("Throughput (bytes/sec)")
    ax.set_title(f"Channel Throughput Comparison ({payload_size} B payload)")
    ax.set_yscale("log")
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(
        lambda x, _: f"{x/1000:.0f}K" if x >= 1000 else f"{x:.0f}"
    ))

    fig.tight_layout()
    out = output_dir / "throughput_comparison.png"
    fig.savefig(out, dpi=_DPI, bbox_inches="tight")
    plt.close(fig)
    return out


def chart_timing_breakdown(
    results: list[dict], output_dir: Path, payload_size: int = 1024,
) -> Path:
    """Stacked horizontal bar: time breakdown per pipeline stage."""
    _setup_style()

    filtered = [r for r in results if r["payload_bytes"] == payload_size]
    channels = [r["channel"] for r in filtered]
    labels = [CHANNEL_LABELS.get(c, c) for c in channels]

    stages = ["encrypt_ms", "fragment_ms", "encode_ms", "decode_ms", "reassemble_ms", "decrypt_ms"]
    stage_labels = ["Encrypt", "Fragment", "Encode", "Decode", "Reassemble", "Decrypt"]
    stage_colors = ["#E53935", "#FB8C00", "#43A047", "#1E88E5", "#8E24AA", "#6D4C41"]

    fig, ax = plt.subplots(figsize=(10, 6))

    y_pos = np.arange(len(filtered))
    left = np.zeros(len(filtered))

    for stage, label, color in zip(stages, stage_labels, stage_colors):
        values = [r[stage] for r in filtered]
        ax.barh(y_pos, values, left=left, label=label, color=color, edgecolor="white", linewidth=0.5)
        left += np.array(values)

    ax.set_yticks(y_pos)
    ax.set_yticklabels(labels)
    ax.set_xlabel("Time (ms)")
    ax.set_title(f"Pipeline Timing Breakdown ({payload_size} B payload)")
    ax.legend(loc="lower right", fontsize=10)
    ax.invert_yaxis()

    fig.tight_layout()
    out = output_dir / "timing_breakdown.png"
    fig.savefig(out, dpi=_DPI, bbox_inches="tight")
    plt.close(fig)
    return out


def chart_packets_vs_payload(results: list[dict], output_dir: Path) -> Path:
    """Line chart: number of packets vs payload size for each channel."""
    _setup_style()

    fig, ax = plt.subplots(figsize=(10, 6))

    channel_data: dict[str, tuple[list, list]] = {}
    for r in results:
        ch = r["channel"]
        if ch not in channel_data:
            channel_data[ch] = ([], [])
        channel_data[ch][0].append(r["payload_bytes"])
        channel_data[ch][1].append(r["num_packets"])

    for ch in CHANNELS:
        if ch not in channel_data:
            continue
        sizes, packets = channel_data[ch]
        ax.plot(
            sizes, packets,
            marker="o", linewidth=2, markersize=6,
            label=CHANNEL_LABELS.get(ch, ch),
            color=CHANNEL_COLORS.get(ch, "#666"),
        )

    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("Payload Size (bytes)")
    ax.set_ylabel("Number of Packets")
    ax.set_title("Packets Required vs Payload Size")
    ax.legend(fontsize=10)
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(
        lambda x, _: f"{int(x)}" if x < 1000 else f"{x/1024:.0f}K"
    ))

    fig.tight_layout()
    out = output_dir / "packets_vs_payload.png"
    fig.savefig(out, dpi=_DPI, bbox_inches="tight")
    plt.close(fig)
    return out


def chart_detection_accuracy(metrics: list[dict], output_dir: Path) -> Path:
    """Grouped bar chart: Precision / Recall / F1 per channel (combined method)."""
    _setup_style()

    combined = [m for m in metrics if m["method"] == "combined"]
    if not combined:
        combined = metrics[:5]

    channels = [m["channel"] for m in combined]
    labels = [CHANNEL_LABELS.get(c, c) for c in channels]
    precision = [m["precision"] for m in combined]
    recall = [m["recall"] for m in combined]
    f1 = [m["f1"] for m in combined]

    x = np.arange(len(channels))
    width = 0.25

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.bar(x - width, precision, width, label="Precision", color="#1E88E5", edgecolor="white")
    ax.bar(x, recall, width, label="Recall", color="#43A047", edgecolor="white")
    ax.bar(x + width, f1, width, label="F1 Score", color="#E53935", edgecolor="white")

    ax.set_ylabel("Score")
    ax.set_title("Detection Accuracy by Channel (Combined Method)")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylim(0, 1.15)
    ax.legend(fontsize=10)
    ax.axhline(y=1.0, color="gray", linestyle="--", alpha=0.3)

    fig.tight_layout()
    out = output_dir / "detection_accuracy.png"
    fig.savefig(out, dpi=_DPI, bbox_inches="tight")
    plt.close(fig)
    return out


def chart_redundancy_results(redundancy_data: list[dict], output_dir: Path) -> Path:
    """Bar chart: recovery success rate vs packet loss percentage."""
    _setup_style()

    # Group by loss rate bucket
    buckets: dict[int, list[bool]] = {}
    for r in redundancy_data:
        loss_pct = round(r["loss_rate"] * 100 / 10) * 10  # round to nearest 10%
        if loss_pct not in buckets:
            buckets[loss_pct] = []
        buckets[loss_pct].append(r["reassembly_success"] and r.get("data_verified", False))

    sorted_buckets = sorted(buckets.keys())
    loss_labels = [f"{p}%" for p in sorted_buckets]
    success_rates = [sum(buckets[p]) / len(buckets[p]) * 100 for p in sorted_buckets]

    fig, ax = plt.subplots(figsize=(8, 5))

    colors = []
    for rate in success_rates:
        if rate >= 80:
            colors.append("#43A047")
        elif rate >= 50:
            colors.append("#FB8C00")
        else:
            colors.append("#E53935")

    bars = ax.bar(loss_labels, success_rates, color=colors, edgecolor="white", linewidth=0.5)

    for bar, val in zip(bars, success_rates):
        ax.text(
            bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
            f"{val:.0f}%", ha="center", va="bottom", fontsize=11, fontweight="bold",
        )

    ax.set_xlabel("Packet Loss Rate")
    ax.set_ylabel("Recovery Success Rate (%)")
    ax.set_title("Redundancy Test: Data Recovery vs Packet Loss (ICMP, 3x redundancy)")
    ax.set_ylim(0, 115)

    fig.tight_layout()
    out = output_dir / "redundancy_results.png"
    fig.savefig(out, dpi=_DPI, bbox_inches="tight")
    plt.close(fig)
    return out


def chart_throughput_by_payload(results: list[dict], output_dir: Path) -> Path:
    """Line chart: throughput vs payload size for each channel."""
    _setup_style()

    fig, ax = plt.subplots(figsize=(10, 6))

    channel_data: dict[str, tuple[list, list]] = {}
    for r in results:
        ch = r["channel"]
        if ch not in channel_data:
            channel_data[ch] = ([], [])
        channel_data[ch][0].append(r["payload_bytes"])
        channel_data[ch][1].append(r["throughput_Bps"])

    for ch in CHANNELS:
        if ch not in channel_data:
            continue
        sizes, throughputs = channel_data[ch]
        ax.plot(
            sizes, throughputs,
            marker="s", linewidth=2, markersize=6,
            label=CHANNEL_LABELS.get(ch, ch),
            color=CHANNEL_COLORS.get(ch, "#666"),
        )

    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("Payload Size (bytes)")
    ax.set_ylabel("Throughput (bytes/sec)")
    ax.set_title("Throughput Scaling by Payload Size")
    ax.legend(fontsize=10)
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(
        lambda x, _: f"{int(x)}" if x < 1000 else f"{x/1024:.0f}K"
    ))

    fig.tight_layout()
    out = output_dir / "throughput_by_payload.png"
    fig.savefig(out, dpi=_DPI, bbox_inches="tight")
    plt.close(fig)
    return out


def generate_all_charts(
    benchmark_results: dict,
    monitoring_results: dict | None = None,
    output_dir: Path = Path("results/charts"),
) -> list[Path]:
    """Generate all charts and return list of saved file paths.

    Args:
        benchmark_results: Output from run_all_benchmarks().
        monitoring_results: Output from run_all_monitoring() (optional).
        output_dir: Directory to save chart PNGs.

    Returns:
        List of paths to generated PNG files.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    saved: list[Path] = []

    pipeline = benchmark_results.get("pipeline_benchmarks", [])
    redundancy = benchmark_results.get("redundancy_tests", [])

    if pipeline:
        saved.append(chart_throughput_comparison(pipeline, output_dir))
        saved.append(chart_timing_breakdown(pipeline, output_dir))
        saved.append(chart_packets_vs_payload(pipeline, output_dir))
        saved.append(chart_throughput_by_payload(pipeline, output_dir))

    if redundancy:
        saved.append(chart_redundancy_results(redundancy, output_dir))

    if monitoring_results:
        metrics = monitoring_results.get("metrics", [])
        if metrics:
            saved.append(chart_detection_accuracy(metrics, output_dir))

    return saved
