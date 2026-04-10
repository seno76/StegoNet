"""Generate additional charts for the diploma work — Russian labels."""

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path

OUT = Path("diploma/images")
OUT.mkdir(parents=True, exist_ok=True)

plt.rcParams["font.family"] = "DejaVu Sans"
plt.rcParams["font.size"] = 12


def chart_channel_capacity():
    """Bar chart: bytes per packet for each channel."""
    channels = ["ICMP\nPayload", "DNS\nQNAME", "TCP\nISN", "TCP\nTimestamp", "IP\nID"]
    bytes_per_pkt = [1470, 30, 4, 4, 2]
    colors = ["#e74c3c", "#f39c12", "#3498db", "#2ecc71", "#9b59b6"]

    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(channels, bytes_per_pkt, color=colors, edgecolor="black", linewidth=0.5)
    ax.set_yscale("log")
    ax.set_ylabel("Байт / пакет (лог. шкала)")
    ax.set_title("Сравнение ёмкости стеганографических каналов")
    ax.set_ylim(1, 5000)
    ax.grid(axis="y", alpha=0.3)

    for bar, val in zip(bars, bytes_per_pkt):
        ax.text(bar.get_x() + bar.get_width() / 2, val * 1.3,
                f"{val}", ha="center", va="bottom", fontweight="bold", fontsize=11)

    plt.tight_layout()
    fig.savefig(OUT / "channel_capacity.png", dpi=300, bbox_inches="tight")
    plt.close(fig)
    print("  channel_capacity.png")


def chart_stealth_vs_throughput():
    """Scatter plot: stealth score vs effective throughput at 10 PPS."""
    channels = ["ICMP Payload", "DNS QNAME", "TCP ISN", "TCP Timestamp", "IP ID"]
    throughput = [14700, 300, 40, 40, 20]
    stealth = [1, 2, 4, 4, 5]
    colors = ["#e74c3c", "#f39c12", "#3498db", "#2ecc71", "#9b59b6"]
    sizes = [200, 150, 120, 120, 100]

    fig, ax = plt.subplots(figsize=(8, 6))
    for i, ch in enumerate(channels):
        ax.scatter(throughput[i], stealth[i], s=sizes[i], c=colors[i],
                   edgecolors="black", linewidth=0.8, zorder=5, label=ch)
        ax.annotate(ch, (throughput[i], stealth[i]),
                    textcoords="offset points", xytext=(10, 8), fontsize=9)

    ax.set_xscale("log")
    ax.set_xlabel("Эффективная пропускная способность при 10 PPS (байт/с, лог. шкала)")
    ax.set_ylabel("Уровень скрытности")
    ax.set_title("Компромисс между скрытностью и пропускной способностью")
    ax.set_yticks([1, 2, 3, 4, 5])
    ax.set_yticklabels(["Очень низкий", "Низкий", "Средний", "Высокий", "Очень высокий"])
    ax.grid(True, alpha=0.3)
    ax.set_xlim(10, 50000)
    ax.set_ylim(0.5, 5.5)

    plt.tight_layout()
    fig.savefig(OUT / "stealth_vs_throughput.png", dpi=300, bbox_inches="tight")
    plt.close(fig)
    print("  stealth_vs_throughput.png")


def chart_overhead_analysis():
    """Stacked bar: protocol overhead vs useful data for 1KB file."""
    channels = ["ICMP", "DNS", "TCP ISN", "TCP TS", "IP ID"]

    file_size = 1024
    crypto_overhead = 28
    sha256 = 32
    ciphertext = file_size + crypto_overhead

    chunk_sizes = {
        "ICMP": 1470 - 21,
        "DNS": 128,
        "TCP ISN": 128,
        "TCP TS": 128,
        "IP ID": 128,
    }

    useful_data = []
    overhead_bytes = []

    for ch_name in channels:
        chunk_data = chunk_sizes[ch_name]
        first_chunk_data = chunk_data - sha256
        if ciphertext <= first_chunk_data:
            n_chunks = 1
        else:
            remaining = ciphertext - first_chunk_data
            n_chunks = 1 + int(np.ceil(remaining / chunk_data))
        total_overhead = crypto_overhead + sha256 + n_chunks * 21
        useful_data.append(file_size)
        overhead_bytes.append(total_overhead)

    fig, ax = plt.subplots(figsize=(8, 5))
    x = np.arange(len(channels))
    width = 0.5

    ax.bar(x, useful_data, width, label="Полезные данные", color="#3498db")
    ax.bar(x, overhead_bytes, width, bottom=useful_data,
           label="Накладные расходы протокола", color="#e74c3c", alpha=0.8)

    ax.set_ylabel("Байты")
    ax.set_title("Полезные данные и накладные расходы (файл 1 КБ)")
    ax.set_xticks(x)
    ax.set_xticklabels(channels)
    ax.legend()
    ax.grid(axis="y", alpha=0.3)

    for i, (u, o) in enumerate(zip(useful_data, overhead_bytes)):
        pct = o / (u + o) * 100
        ax.text(i, u + o + 10, f"{pct:.1f}%", ha="center", fontsize=9, fontweight="bold")

    plt.tight_layout()
    fig.savefig(OUT / "overhead_analysis.png", dpi=300, bbox_inches="tight")
    plt.close(fig)
    print("  overhead_analysis.png")


def chart_detection_methods_heatmap():
    """Heatmap: which detection method works for which channel."""
    channels = ["ICMP\nPayload", "IP ID", "TCP ISN", "DNS\nQNAME", "TCP\nTimestamp"]
    methods = ["Хи-квадрат", "KS-тест IPD", "Энтропия\nШеннона", "Регулярность\nIPD",
               "Последов.\nIP ID", "Монотонность\nTSval", "Энтропия\nDNS QNAME",
               "Размер payload\nICMP", "Энтропия байтов\npayload"]

    matrix = np.array([
        [0, 2, 2, 0, 0],
        [1, 1, 1, 1, 1],
        [0, 2, 2, 0, 0],
        [2, 2, 2, 2, 2],
        [0, 3, 0, 0, 0],
        [0, 0, 0, 0, 3],
        [0, 0, 0, 3, 0],
        [3, 0, 0, 0, 0],
        [3, 0, 0, 0, 0],
    ])

    fig, ax = plt.subplots(figsize=(9, 7))
    cmap = plt.cm.RdYlGn_r
    cmap.set_under("white")

    im = ax.imshow(matrix, cmap=cmap, aspect="auto", vmin=0.5, vmax=3)

    ax.set_xticks(np.arange(len(channels)))
    ax.set_yticks(np.arange(len(methods)))
    ax.set_xticklabels(channels, fontsize=10)
    ax.set_yticklabels(methods, fontsize=9)

    labels = {0: "", 1: "Слабая", 2: "Средняя", 3: "Сильная"}
    for i in range(len(methods)):
        for j in range(len(channels)):
            val = matrix[i, j]
            if val > 0:
                color = "white" if val == 3 else "black"
                ax.text(j, i, labels[val], ha="center", va="center",
                        fontsize=8, color=color, fontweight="bold")

    ax.set_title("Эффективность методов обнаружения по типам каналов")
    fig.colorbar(im, ax=ax, shrink=0.6, label="Эффективность")

    plt.tight_layout()
    fig.savefig(OUT / "detection_heatmap.png", dpi=300, bbox_inches="tight")
    plt.close(fig)
    print("  detection_heatmap.png")


def chart_packets_for_sizes():
    """Bar chart: number of packets needed for different file sizes."""
    file_sizes = [64, 256, 1024, 4096]
    size_labels = ["64 Б", "256 Б", "1 КБ", "4 КБ"]

    channels = {
        "ICMP Payload": 1470,
        "DNS QNAME": 30,
        "TCP ISN": 4,
        "TCP Timestamp": 4,
        "IP ID": 2,
    }
    colors = ["#e74c3c", "#f39c12", "#3498db", "#2ecc71", "#9b59b6"]

    # Compute packets for each channel and file size
    data = {}
    for name, bpp in channels.items():
        packets = []
        for s in file_sizes:
            crypto = s + 28
            overhead = 21
            if bpp > overhead + 33:
                chunk_data = bpp - overhead
            else:
                chunk_data = 128
            first_data = chunk_data - 32
            if crypto <= first_data:
                n = 1
            else:
                remaining = crypto - first_data
                n = 1 + int(np.ceil(remaining / chunk_data))
            packets.append(n + 1)
        data[name] = packets

    x = np.arange(len(file_sizes))
    width = 0.15
    fig, ax = plt.subplots(figsize=(10, 6))

    for i, ((name, packets), color) in enumerate(zip(data.items(), colors)):
        offset = (i - 2) * width
        bars = ax.bar(x + offset, packets, width, label=name, color=color,
                      edgecolor="white", linewidth=0.5)
        for bar, val in zip(bars, packets):
            if val > 10:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(),
                        str(val), ha="center", va="bottom", fontsize=7, fontweight="bold")

    ax.set_yscale("log")
    ax.set_xlabel("Размер файла")
    ax.set_ylabel("Количество пакетов (лог. шкала)")
    ax.set_title("Зависимость числа пакетов от размера файла")
    ax.set_xticks(x)
    ax.set_xticklabels(size_labels)
    ax.legend(loc="upper left", fontsize=9)
    ax.grid(axis="y", alpha=0.3)

    plt.tight_layout()
    fig.savefig(OUT / "packets_for_sizes.png", dpi=300, bbox_inches="tight")
    plt.close(fig)
    print("  packets_for_sizes.png")


def chart_transfer_time():
    """Bar chart: transfer time for 1KB at 10 PPS."""
    channels = ["ICMP\nPayload", "DNS\nQNAME", "TCP\nISN", "TCP\nTimestamp", "IP\nID"]
    packets = [1, 44, 320, 320, 638]
    time_sec = [p / 10 for p in packets]
    colors = ["#e74c3c", "#f39c12", "#3498db", "#2ecc71", "#9b59b6"]

    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(channels, time_sec, color=colors, edgecolor="black", linewidth=0.5)
    ax.set_ylabel("Время передачи (секунды)")
    ax.set_title("Время передачи файла 1 КБ при скорости 10 PPS")
    ax.set_yscale("log")
    ax.grid(axis="y", alpha=0.3)

    for bar, t in zip(bars, time_sec):
        label = f"{t:.1f} с" if t < 60 else f"{t/60:.1f} мин"
        ax.text(bar.get_x() + bar.get_width() / 2, t * 1.3,
                label, ha="center", va="bottom", fontweight="bold", fontsize=10)

    plt.tight_layout()
    fig.savefig(OUT / "transfer_time_1kb.png", dpi=300, bbox_inches="tight")
    plt.close(fig)
    print("  transfer_time_1kb.png")


if __name__ == "__main__":
    print("Generating diploma charts (RU)...")
    chart_channel_capacity()
    chart_stealth_vs_throughput()
    chart_overhead_analysis()
    chart_detection_methods_heatmap()
    chart_packets_for_sizes()
    chart_transfer_time()
    print(f"\nDone! All charts saved to {OUT}/")
