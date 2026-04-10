"""Generate charts for Chapter 1 (cyber threat landscape) — Russian labels."""

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path

OUT = Path("diploma/images")
OUT.mkdir(parents=True, exist_ok=True)

plt.rcParams["font.family"] = "DejaVu Sans"
plt.rcParams["font.size"] = 12


def chart_incident_dynamics():
    """Line chart: dynamics of data breach incidents 2019-2024."""
    years = [2019, 2020, 2021, 2022, 2023, 2024]
    incidents_global = [1500, 2000, 2700, 3200, 3800, 4500]
    incidents_russia = [250, 370, 520, 700, 900, 1100]

    fig, ax1 = plt.subplots(figsize=(9, 5.5))
    ax1.plot(years, incidents_global, "o-", color="#e74c3c",
             linewidth=2.5, markersize=8, label="Мир")
    ax1.plot(years, incidents_russia, "s-", color="#3498db",
             linewidth=2.5, markersize=8, label="Россия")

    ax1.set_xlabel("Год")
    ax1.set_ylabel("Количество значимых инцидентов")
    ax1.set_title("Динамика инцидентов кибербезопасности (2019\u20132024)")
    ax1.legend(loc="upper left")
    ax1.grid(True, alpha=0.3)
    ax1.set_xticks(years)

    for i in range(1, len(years)):
        growth = (incidents_global[i] - incidents_global[i-1]) / incidents_global[i-1] * 100
        ax1.annotate(f"+{growth:.0f}%",
                     xy=(years[i], incidents_global[i]),
                     xytext=(0, 12), textcoords="offset points",
                     fontsize=8, ha="center", color="#e74c3c")

    plt.tight_layout()
    fig.savefig(OUT / "incident_dynamics.png", dpi=300, bbox_inches="tight")
    plt.close(fig)
    print("  incident_dynamics.png")


def chart_attack_types():
    """Pie chart: types of cyber attacks distribution."""
    labels = ["Вредоносное\nПО", "Социальная\nинженерия",
              "Эксплуатация\nуязвимостей", "Компрометация\nучётных данных",
              "Атаки на цепочку\nпоставок", "Прочее"]
    sizes = [38, 22, 18, 10, 5, 7]
    colors = ["#e74c3c", "#f39c12", "#3498db", "#2ecc71", "#9b59b6", "#95a5a6"]
    explode = (0.05, 0, 0, 0, 0, 0)

    fig, ax = plt.subplots(figsize=(8, 6))
    wedges, texts, autotexts = ax.pie(
        sizes, explode=explode, labels=labels, colors=colors,
        autopct="%1.0f%%", shadow=False, startangle=90,
        textprops={"fontsize": 10})
    for autotext in autotexts:
        autotext.set_fontweight("bold")
    ax.set_title("Распределение типов кибератак (2024)")

    plt.tight_layout()
    fig.savefig(OUT / "attack_types.png", dpi=300, bbox_inches="tight")
    plt.close(fig)
    print("  attack_types.png")


def chart_stego_in_apt():
    """Horizontal bar: APT groups using steganography techniques."""
    groups = ["Turla\n(Waterbug)", "Equation\nGroup", "APT29\n(Cozy Bear)",
              "Duqu\n(семейство Stuxnet)", "ProjectSauron\n(Strider)"]
    techniques = [
        "DNS-туннелирование,\nHTTP-заголовки",
        "Прошивка HDD,\nшифрованный C2 (RC6)",
        "Стего в Twitter,\nLSB в изображениях",
        "Стего в JPEG,\nфайлы шрифтов",
        "DNS-туннелирование,\nкастомные протоколы"
    ]
    duration = [18, 14, 16, 5, 5]

    fig, ax = plt.subplots(figsize=(10, 5))
    y_pos = np.arange(len(groups))
    bars = ax.barh(y_pos, duration, color=["#e74c3c", "#3498db", "#2ecc71", "#f39c12", "#9b59b6"],
                   edgecolor="black", linewidth=0.5, height=0.6)

    ax.set_yticks(y_pos)
    ax.set_yticklabels(groups, fontsize=10)
    ax.set_xlabel("Годы известной активности")
    ax.set_title("APT-группировки, использующие стеганографические техники")
    ax.invert_yaxis()
    ax.grid(axis="x", alpha=0.3)

    for i, (bar, tech) in enumerate(zip(bars, techniques)):
        ax.text(bar.get_width() + 0.3, bar.get_y() + bar.get_height()/2,
                tech, va="center", fontsize=8, style="italic")

    plt.tight_layout()
    fig.savefig(OUT / "apt_stego.png", dpi=300, bbox_inches="tight")
    plt.close(fig)
    print("  apt_stego.png")


def chart_covert_channel_classification():
    """Grouped bar: covert channel types comparison."""
    categories = ["Каналы\nхранения", "Каналы\nвремени", "Гибридные\nканалы"]
    capacity = [100, 10, 50]
    stealth = [60, 90, 75]
    detection_difficulty = [50, 85, 70]

    x = np.arange(len(categories))
    width = 0.25

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.bar(x - width, capacity, width, label="Пропускная способность", color="#3498db")
    ax.bar(x, stealth, width, label="Скрытность", color="#2ecc71")
    ax.bar(x + width, detection_difficulty, width, label="Сложность обнаружения", color="#e74c3c")

    ax.set_ylabel("Относительная оценка (0\u2013100)")
    ax.set_title("Классификация скрытых каналов: хранения, времени и гибридные")
    ax.set_xticks(x)
    ax.set_xticklabels(categories)
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    ax.set_ylim(0, 110)

    plt.tight_layout()
    fig.savefig(OUT / "channel_classification.png", dpi=300, bbox_inches="tight")
    plt.close(fig)
    print("  channel_classification.png")


if __name__ == "__main__":
    print("Generating Chapter 1 charts (RU)...")
    chart_incident_dynamics()
    chart_attack_types()
    chart_stego_in_apt()
    chart_covert_channel_classification()
    print(f"\nDone! Charts saved to {OUT}/")
