
import csv
import sys
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

from main import detect_repeated_failures

from datetime import datetime, timedelta


def make_scenario(failures, start_minute=0, successful_logins=0):
    """Create one labelled synthetic test scenario."""
    start = datetime(2026, 10, 31, 9, 0, 0)
    events = []

    for minute in range(failures):
        events.append({
            "timestamp": start + timedelta(minutes=start_minute + minute),
            "username": "test_user",
            "source_ip": "192.0.2.25",
            "status": "failure",
        })

    for minute in range(successful_logins):
        events.append({
            "timestamp": start + timedelta(minutes=minute),
            "username": "normal_user",
            "source_ip": "192.0.2.30",
            "status": "success",
        })

    return sorted(events, key=lambda event: event["timestamp"])


def main():
    # Labels are defined before running the detector.
    scenarios = [
        ("repeated_failures", True, make_scenario(6)),
        ("four_failures", False, make_scenario(4)),
        ("normal_successes", False, make_scenario(0, successful_logins=6)),
    ]

    tp = fp = tn = fn = 0
    rows = []

    for name, expected_suspicious, events in scenarios:
        alerts = detect_repeated_failures(events)
        detected = len(alerts) > 0

        if expected_suspicious and detected:
            tp += 1
            outcome = "TP"
        elif expected_suspicious and not detected:
            fn += 1
            outcome = "FN"
        elif not expected_suspicious and detected:
            fp += 1
            outcome = "FP"
        else:
            tn += 1
            outcome = "TN"

        rows.append({
            "scenario": name,
            "expected_suspicious": expected_suspicious,
            "detected": detected,
            "outcome": outcome,
        })

    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0
    )
    false_positive_rate = fp / (fp + tn) if fp + tn else 0

    results_dir = PROJECT_DIR / "results"
    results_dir.mkdir(exist_ok=True)
    output_file = results_dir / "evaluation_results.csv"

    with output_file.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "scenario",
                "expected_suspicious",
                "detected",
                "outcome",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    print("=== Evaluation Results ===")
    print(f"TP={tp}, FP={fp}, TN={tn}, FN={fn}")
    print(f"Precision: {precision:.3f}")
    print(f"Recall: {recall:.3f}")
    print(f"F1-score: {f1:.3f}")
    print(f"False-positive rate: {false_positive_rate:.3f}")
    print(f"Scenario results saved to: {output_file}")


if __name__ == "__main__":
    main()
