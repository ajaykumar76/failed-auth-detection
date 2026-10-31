
import sys
import csv
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))
sys.path.insert(0, str(PROJECT_DIR / "tests"))

import main as detector
from test_generalisation import (
    scenarios,
    baseline_detector,
    calculate_metrics,
)

RESULTS_DIR = PROJECT_DIR / "results"
OUTPUT_FILE = RESULTS_DIR / "threshold_sensitivity.csv"
THRESHOLDS = [3, 4, 5, 6]
WINDOW_MINUTES = 5


def main():
    original_threshold = detector.THRESHOLD
    original_window = detector.WINDOW_MINUTES
    output_rows = []

    print("=== Threshold Sensitivity Experiment ===")
    print("Scenarios: 9")
    print(f"Window: {WINDOW_MINUTES} minutes")
    print()

    try:
        for threshold in THRESHOLDS:
            detector.THRESHOLD = threshold
            detector.WINDOW_MINUTES = WINDOW_MINUTES

            rows = []

            for case in scenarios():
                expected = case["expected_suspicious"]
                events = case["events"]

                rows.append({
                    "expected_suspicious": expected,
                    "baseline_detected": bool(baseline_detector(events)),
                    "enhanced_detected": bool(
                        detector.detect_repeated_failures(events)
                    ),
                })

            for name, field in [
                ("baseline", "baseline_detected"),
                ("enhanced", "enhanced_detected"),
            ]:
                metrics = calculate_metrics(rows, field)

                result = {
                    "threshold": threshold,
                    "detector": name,
                    **metrics,
                }
                output_rows.append(result)

                print(
                    f"Threshold={threshold}, Detector={name}: "
                    f"TP={metrics['TP']} FP={metrics['FP']} "
                    f"TN={metrics['TN']} FN={metrics['FN']} "
                    f"Precision={metrics['precision']} "
                    f"Recall={metrics['recall']} "
                    f"F1={metrics['f1_score']} "
                    f"FPR={metrics['false_positive_rate']}"
                )

            print()

    finally:
        detector.THRESHOLD = original_threshold
        detector.WINDOW_MINUTES = original_window

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "threshold",
        "detector",
        "TP",
        "FP",
        "TN",
        "FN",
        "precision",
        "recall",
        "f1_score",
        "false_positive_rate",
    ]

    with OUTPUT_FILE.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(output_rows)

    print(f"Saved {len(output_rows)} rows to: {OUTPUT_FILE}")
    print("Original detector settings restored.")


if __name__ == "__main__":
    main()
