"""Detection accuracy monitoring -- automated evaluation of detection methods.

Generates steganographic and normal traffic for each channel,
runs the detector, and computes real precision/recall/F1/confusion matrix.

Uses netstego.benchmarks for core logic.
"""

import json
from pathlib import Path

from netstego.benchmarks import CHANNELS, run_all_monitoring


def main():
    print("=" * 75)
    print("NetStego Detection Monitoring -- Precision/Recall/F1 Evaluation")
    print("=" * 75)

    output = run_all_monitoring()
    metrics = output["metrics"]

    # Group metrics by channel
    for channel_name in CHANNELS:
        print(f"\n--- Channel: {channel_name} ---")
        channel_metrics = [m for m in metrics if m["channel"] == channel_name]
        for m in channel_metrics:
            print(
                f"  {m['method']:>12}: P={m['precision']:.2f}  R={m['recall']:.2f}  "
                f"F1={m['f1']:.2f}  Acc={m['accuracy']:.2f}  FPR={m['fpr']:.2f}"
            )

    # Summary tables
    print("\n" + "=" * 75)
    print("SUMMARY: Combined Detection (all 3 methods)")
    print("=" * 75)
    print(
        f"{'Channel':>10} | {'TP':>3} {'FP':>3} {'TN':>3} {'FN':>3} | "
        f"{'Precision':>9} {'Recall':>6} {'F1':>6} {'Accuracy':>8} {'FPR':>6}"
    )
    print("-" * 75)
    combined = [m for m in metrics if m["method"] == "combined"]
    for m in combined:
        print(
            f"{m['channel']:>10} | {m['tp']:>3} {m['fp']:>3} {m['tn']:>3} {m['fn']:>3} | "
            f"{m['precision']:>9.2%} {m['recall']:>6.2%} {m['f1']:>6.2%} "
            f"{m['accuracy']:>8.2%} {m['fpr']:>6.2%}"
        )

    print("\n" + "=" * 75)
    print("SUMMARY: Per-Method Detection")
    print("=" * 75)
    print(
        f"{'Channel':>10} {'Method':>12} | {'TP':>3} {'FP':>3} {'TN':>3} {'FN':>3} | "
        f"{'Precision':>9} {'Recall':>6} {'F1':>6} {'FPR':>6}"
    )
    print("-" * 75)
    per_method = [m for m in metrics if m["method"] != "combined"]
    for m in per_method:
        print(
            f"{m['channel']:>10} {m['method']:>12} | "
            f"{m['tp']:>3} {m['fp']:>3} {m['tn']:>3} {m['fn']:>3} | "
            f"{m['precision']:>9.2%} {m['recall']:>6.2%} {m['f1']:>6.2%} {m['fpr']:>6.2%}"
        )

    # Confusion matrices
    print("\n" + "=" * 75)
    print("CONFUSION MATRICES (Combined detector)")
    print("=" * 75)
    for m in combined:
        print(f"\n  {m['channel']}:")
        print(f"                Predicted")
        print(f"                Stego    Normal")
        print(f"  Actual Stego  {m['tp']:>5}    {m['fn']:>5}")
        print(f"  Actual Normal {m['fp']:>5}    {m['tn']:>5}")

    # Save results
    out_path = Path("monitoring_results.json")
    out_path.write_text(json.dumps(output, indent=2, ensure_ascii=False))
    print(f"\nResults saved to {out_path}")


if __name__ == "__main__":
    main()
