import csv
import sys
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

import main as original_detector
import experimental_detector as experimental

from test_extended_scenarios import get_scenarios

RESULTS_DIR = PROJECT_DIR / "results"


def classify(expected, detected):
    if expected and detected:
        return "TP"
    if expected and not detected:
        return "FN"
    if not expected and detected:
        return "FP"
    return "TN"


def calculate_metrics(rows, prefix):
    outcomes = [row[f"{prefix}_outcome"] for row in rows]

    return {
        "TP": outcomes.count("TP"),
        "FP": outcomes.count("FP"),
        "TN": outcomes.count("TN"),
        "FN": outcomes.count("FN"),
    }


def evaluate():
    rows = []

    original_threshold = original_detector.THRESHOLD
    original_window = original_detector.WINDOW_MINUTES

    try:
        original_detector.THRESHOLD = 5
        original_detector.WINDOW_MINUTES = 5

        for scenario in get_scenarios():
            events = scenario["events"]
            expected = scenario["expected_suspicious"]

            original_alerts = (
                original_detector.detect_repeated_failures(events)
            )

            experimental_alerts = experimental.detect_experimental(events)

            original_detected = bool(original_alerts)
            experimental_detected = bool(experimental_alerts)
            combined_detected = (
                original_detected or experimental_detected
            )

            rows.append({
                "scenario": scenario["name"],
                "expected_suspicious": expected,
                "original_detected": original_detected,
                "original_outcome": classify(
                    expected, original_detected
                ),
                "experimental_detected": experimental_detected,
                "experimental_outcome": classify(
                    expected, experimental_detected
                ),
                "combined_detected": combined_detected,
                "combined_outcome": classify(
                    expected, combined_detected
                ),
                "experimental_rules": "; ".join(
                    sorted({
                        alert["rule"]
                        for alert in experimental_alerts
                    })
                ),
            })

    finally:
        original_detector.THRESHOLD = original_threshold
        original_detector.WINDOW_MINUTES = original_window

    return rows


def main():
    rows = evaluate()

    original = calculate_metrics(rows, "original")
    enhanced = calculate_metrics(rows, "experimental")
    combined = calculate_metrics(rows, "combined")

    output_file = RESULTS_DIR / "experimental_generalisation.csv"
    RESULTS_DIR.mkdir(exist_ok=True)

    with output_file.open(
        "w", newline="", encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "scenario",
                "expected_suspicious",
                "original_detected",
                "original_outcome",
                "experimental_detected",
                "experimental_outcome",
                "combined_detected",
                "combined_outcome",
                "experimental_rules",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    print("=== Experimental Generalisation Evaluation ===")
    print(f"Scenarios: {len(rows)}")

    print("\nOriginal detector")
    print(original)

    print("\nExperimental detector")
    print(enhanced)

    print("\nCombined detector (original + experimental)")
    print(combined)

    print("\nScenario comparison")
    for row in rows:
        print(
            f"{row['scenario']}: "
            f"original={row['original_outcome']}, "
            f"experimental={row['experimental_outcome']}, "
            f"combined={row['combined_outcome']}, "
            f"rules={row['experimental_rules'] or 'none'}"
        )

    print(f"\nSaved: {output_file}")


if __name__ == "__main__":
    main()