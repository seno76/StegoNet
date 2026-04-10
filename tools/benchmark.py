"""Real benchmark: full encode -> PCAP -> decode pipeline for all channels.

Runs without network access or admin privileges by using PCAP as intermediary.
Measures: encryption time, fragmentation time, encoding time, decoding time,
reassembly time, decryption time, total throughput, packets per payload size.

Uses netstego.benchmarks for core logic.
"""

import json
from pathlib import Path

from netstego.benchmarks import CHANNELS, DEFAULT_PAYLOAD_SIZES, run_all_benchmarks
from netstego.network.sender import get_channel


def main():
    print("=" * 70)
    print("NetStego Benchmark -- Full Pipeline (encode -> PCAP -> decode)")
    print("=" * 70)

    output = run_all_benchmarks()
    results = output["pipeline_benchmarks"]
    redundancy_results = output["redundancy_tests"]

    # Print per-channel results
    current_channel = None
    for r in results:
        if r["channel"] != current_channel:
            current_channel = r["channel"]
            print(f"\n--- Channel: {current_channel} ---")
        print(
            f"  {r['payload_bytes']:>6} B -> {r['num_packets']:>4} pkts | "
            f"total {r['total_ms']:>8.2f} ms | "
            f"throughput {r['throughput_Bps']:>10.0f} B/s | "
            f"verified: {r['data_verified']}"
        )

    # Redundancy summary
    if redundancy_results:
        print("\n" + "=" * 70)
        print("Redundancy Test -- 3x redundancy, ICMP channel (chunk=packet)")
        print("=" * 70)
        buckets: dict[int, list[bool]] = {}
        for r in redundancy_results:
            pct = round(r["loss_rate"] * 100 / 10) * 10
            if pct not in buckets:
                buckets[pct] = []
            buckets[pct].append(r["reassembly_success"] and r.get("data_verified", False))
        for pct in sorted(buckets):
            successes = sum(buckets[pct])
            total = len(buckets[pct])
            print(f"  Loss {pct:>2}%: {successes}/{total} successful recoveries")

    # Network throughput estimates
    print("\n" + "=" * 70)
    print("Estimated Network Throughput at Different PPS Rates")
    print("=" * 70)
    print(f"{'Channel':>10} | {'bits/pkt':>8} | {'10 PPS':>12} | {'50 PPS':>12} | {'100 PPS':>12}")
    print("-" * 70)
    for ch_name in CHANNELS:
        ch = get_channel(ch_name)
        bpp = ch.bits_per_packet
        for_10 = bpp * 10 / 8
        for_50 = bpp * 50 / 8
        for_100 = bpp * 100 / 8
        print(
            f"{ch_name:>10} | {bpp:>8} | {for_10:>9.0f} B/s | "
            f"{for_50:>9.0f} B/s | {for_100:>9.0f} B/s"
        )

    # Save full results
    out_path = Path("benchmark_results.json")
    out_path.write_text(json.dumps(output, indent=2))
    print(f"\nFull results saved to {out_path}")

    # Print summary table
    print("\n" + "=" * 70)
    print("Summary: Throughput by Channel (1024 B payload)")
    print("=" * 70)
    print(f"{'Channel':>10} | {'Packets':>7} | {'Encode ms':>10} | {'Decode ms':>10} | {'Total ms':>10} | {'B/s':>10}")
    print("-" * 70)
    for r in results:
        if r["payload_bytes"] == 1024:
            print(
                f"{r['channel']:>10} | {r['num_packets']:>7} | "
                f"{r['encode_ms']:>10.2f} | {r['decode_ms']:>10.2f} | "
                f"{r['total_ms']:>10.2f} | {r['throughput_Bps']:>10.0f}"
            )


if __name__ == "__main__":
    main()
