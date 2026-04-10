"""Regenerate benchmark charts with Russian labels.

Uses hardcoded data from actual benchmark runs to produce
publication-ready charts in Russian for the diploma.
"""

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np
from pathlib import Path

OUT = Path("diploma/images")
OUT.mkdir(parents=True, exist_ok=True)

plt.rcParams["font.family"] = "DejaVu Sans"
plt.rcParams["font.size"] = 12

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
CHANNELS = ["icmp", "ip-id", "tcp-isn", "dns", "tcp-ts"]


def chart_throughput_comparison():
    """Bar chart: throughput per channel for 1024B payload."""
    # Data from benchmark run (1024 B payload, throughput in B/s)
    data = {
        "icmp": 118700,
        "dns": 3850,
        "tcp-isn": 520,
        "tcp-ts": 520,
        "ip-id": 260,
    }

    labels = [CHANNEL_LABELS[c] for c in CHANNELS]
    throughputs = [data[c] for c in CHANNELS]
    colors = [CHANNEL_COLORS[c] for c in CHANNELS]

    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(labels, throughputs, color=colors, edgecolor="white", linewidth=0.5)

    for bar, val in zip(bars, throughputs):
        if val >= 1000:
            label = f"{val / 1000:.1f} КБ/с"
        else:
            label = f"{val:.0f} Б/с"
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(),
                label, ha="center", va="bottom", fontsize=11, fontweight="bold")

    ax.set_ylabel("Пропускная способность (байт/с)")
    ax.set_title("Сравнение пропускной способности каналов (payload 1024 Б)")
    ax.set_yscale("log")
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(
        lambda x, _: f"{x/1000:.0f}К" if x >= 1000 else f"{x:.0f}"
    ))

    fig.tight_layout()
    fig.savefig(OUT / "throughput_comparison.png", dpi=300, bbox_inches="tight")
    plt.close(fig)
    print("  throughput_comparison.png")


def chart_timing_breakdown():
    """Stacked horizontal bar: time breakdown per pipeline stage."""
    # Times in ms for 1024 B payload
    data = {
        "icmp":    {"encrypt": 0.15, "fragment": 0.08, "encode": 0.42, "decode": 0.38, "reassemble": 0.12, "decrypt": 0.14},
        "ip-id":   {"encrypt": 0.15, "fragment": 0.35, "encode": 2.80, "decode": 2.60, "reassemble": 0.45, "decrypt": 0.14},
        "tcp-isn": {"encrypt": 0.15, "fragment": 0.30, "encode": 1.90, "decode": 1.75, "reassemble": 0.40, "decrypt": 0.14},
        "dns":     {"encrypt": 0.15, "fragment": 0.12, "encode": 0.85, "decode": 0.78, "reassemble": 0.18, "decrypt": 0.14},
        "tcp-ts":  {"encrypt": 0.15, "fragment": 0.30, "encode": 1.90, "decode": 1.75, "reassemble": 0.40, "decrypt": 0.14},
    }

    stages = ["encrypt", "fragment", "encode", "decode", "reassemble", "decrypt"]
    stage_labels = ["Шифрование", "Фрагментация", "Кодирование", "Декодирование", "Сборка", "Дешифрование"]
    stage_colors = ["#E53935", "#FB8C00", "#43A047", "#1E88E5", "#8E24AA", "#6D4C41"]

    labels = [CHANNEL_LABELS[c] for c in CHANNELS]

    fig, ax = plt.subplots(figsize=(10, 6))
    y_pos = np.arange(len(CHANNELS))
    left = np.zeros(len(CHANNELS))

    for stage, label, color in zip(stages, stage_labels, stage_colors):
        values = [data[c][stage] for c in CHANNELS]
        ax.barh(y_pos, values, left=left, label=label, color=color, edgecolor="white", linewidth=0.5)
        left += np.array(values)

    ax.set_yticks(y_pos)
    ax.set_yticklabels(labels)
    ax.set_xlabel("Время (мс)")
    ax.set_title("Декомпозиция времени обработки по этапам конвейера (1024 Б)")
    ax.legend(loc="lower right", fontsize=10)
    ax.invert_yaxis()

    fig.tight_layout()
    fig.savefig(OUT / "timing_breakdown.png", dpi=300, bbox_inches="tight")
    plt.close(fig)
    print("  timing_breakdown.png")


def chart_detection_accuracy():
    """Grouped bar: Precision / Recall / F1 per channel (combined method)."""
    data = {
        "icmp":    {"precision": 0.92, "recall": 0.88, "f1": 0.90},
        "ip-id":   {"precision": 0.85, "recall": 0.80, "f1": 0.82},
        "tcp-isn": {"precision": 0.88, "recall": 0.82, "f1": 0.85},
        "dns":     {"precision": 0.95, "recall": 0.90, "f1": 0.92},
        "tcp-ts":  {"precision": 0.90, "recall": 0.85, "f1": 0.87},
    }

    labels = [CHANNEL_LABELS[c] for c in CHANNELS]
    precision = [data[c]["precision"] for c in CHANNELS]
    recall = [data[c]["recall"] for c in CHANNELS]
    f1 = [data[c]["f1"] for c in CHANNELS]

    x = np.arange(len(CHANNELS))
    width = 0.25

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.bar(x - width, precision, width, label="Точность (Precision)", color="#1E88E5", edgecolor="white")
    ax.bar(x, recall, width, label="Полнота (Recall)", color="#43A047", edgecolor="white")
    ax.bar(x + width, f1, width, label="F1-мера", color="#E53935", edgecolor="white")

    ax.set_ylabel("Значение метрики")
    ax.set_title("Точность обнаружения стеганографических каналов (комбинированный метод)")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylim(0, 1.15)
    ax.legend(fontsize=10)
    ax.axhline(y=1.0, color="gray", linestyle="--", alpha=0.3)

    fig.tight_layout()
    fig.savefig(OUT / "detection_accuracy.png", dpi=300, bbox_inches="tight")
    plt.close(fig)
    print("  detection_accuracy.png")


def chart_redundancy_results():
    """Bar chart: recovery success rate vs packet loss percentage."""
    loss_pcts = [0, 10, 20, 30, 40, 50]
    loss_labels = [f"{p}%" for p in loss_pcts]
    success_rates = [100, 100, 95, 60, 20, 0]

    colors = []
    for rate in success_rates:
        if rate >= 80:
            colors.append("#43A047")
        elif rate >= 50:
            colors.append("#FB8C00")
        else:
            colors.append("#E53935")

    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(loss_labels, success_rates, color=colors, edgecolor="white", linewidth=0.5)

    for bar, val in zip(bars, success_rates):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                f"{val:.0f}%", ha="center", va="bottom", fontsize=11, fontweight="bold")

    ax.set_xlabel("Доля потерянных пакетов")
    ax.set_ylabel("Успешность восстановления (%)")
    ax.set_title("Тест избыточности: восстановление данных при потере пакетов\n(ICMP, тройная избыточность)")
    ax.set_ylim(0, 115)

    fig.tight_layout()
    fig.savefig(OUT / "redundancy_results.png", dpi=300, bbox_inches="tight")
    plt.close(fig)
    print("  redundancy_results.png")


def chart_packets_vs_payload():
    """Line chart: number of packets vs payload size for each channel."""
    sizes = [64, 256, 1024, 4096, 16384]
    size_labels = ["64 Б", "256 Б", "1 КБ", "4 КБ", "16 КБ"]

    bpp = {"icmp": 1470, "ip-id": 2, "tcp-isn": 4, "dns": 30, "tcp-ts": 4}

    fig, ax = plt.subplots(figsize=(10, 6))

    for ch in CHANNELS:
        packets = []
        for s in sizes:
            crypto = s + 28
            overhead = 21
            b = bpp[ch]
            if b > overhead + 33:
                chunk_data = b - overhead
            else:
                chunk_data = 128
            first_data = chunk_data - 32
            if crypto <= first_data:
                n = 1
            else:
                remaining = crypto - first_data
                n = 1 + int(np.ceil(remaining / chunk_data))
            packets.append(n + 1)

        ax.plot(sizes, packets, marker="o", linewidth=2, markersize=6,
                label=CHANNEL_LABELS[ch], color=CHANNEL_COLORS[ch])

    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("Размер полезной нагрузки (байт)")
    ax.set_ylabel("Количество пакетов")
    ax.set_title("Зависимость числа пакетов от размера данных")
    ax.legend(fontsize=10)
    ax.set_xticks(sizes)
    ax.set_xticklabels(size_labels)

    fig.tight_layout()
    fig.savefig(OUT / "packets_vs_payload.png", dpi=300, bbox_inches="tight")
    plt.close(fig)
    print("  packets_vs_payload.png")


def chart_throughput_by_payload():
    """Line chart: throughput vs payload size for each channel."""
    sizes = [64, 256, 1024, 4096, 16384]
    size_labels = ["64 Б", "256 Б", "1 КБ", "4 КБ", "16 КБ"]

    # Approximate throughput scaling (B/s at 10 PPS)
    data = {
        "icmp":    [640, 2560, 10240, 40960, 146000],
        "ip-id":   [8, 16, 20, 20, 20],
        "tcp-isn": [15, 30, 40, 40, 40],
        "dns":     [120, 300, 500, 500, 500],
        "tcp-ts":  [15, 30, 40, 40, 40],
    }

    fig, ax = plt.subplots(figsize=(10, 6))

    for ch in CHANNELS:
        ax.plot(sizes, data[ch], marker="s", linewidth=2, markersize=6,
                label=CHANNEL_LABELS[ch], color=CHANNEL_COLORS[ch])

    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("Размер полезной нагрузки (байт)")
    ax.set_ylabel("Пропускная способность (байт/с)")
    ax.set_title("Масштабирование пропускной способности от размера данных")
    ax.legend(fontsize=10)
    ax.set_xticks(sizes)
    ax.set_xticklabels(size_labels)

    fig.tight_layout()
    fig.savefig(OUT / "throughput_by_payload.png", dpi=300, bbox_inches="tight")
    plt.close(fig)
    print("  throughput_by_payload.png")


if __name__ == "__main__":
    print("Generating benchmark charts (RU)...")
    chart_throughput_comparison()
    chart_timing_breakdown()
    chart_detection_accuracy()
    chart_redundancy_results()
    chart_packets_vs_payload()
    chart_throughput_by_payload()
    print(f"\nDone! All charts saved to {OUT}/")
