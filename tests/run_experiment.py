
import csv
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

import main as detector

RESULTS_DIR = PROJECT_DIR / "results"
WINDOW_MINUTES = 5


def build_scenario(name, expected_suspicious, failure_minutes,
                   ip_mode="same", successful_logins=0):
    """Build one synthetic scenario with a predefined label."""
    start = datetime(2026, 10, 31, 9, 0, 0)
    events = []

    for index, minute in enumerate(failure_minutes):
        if ip_mode == "split":
            source_ip = (
                "192.0.2.40" if index % 2 == 0 else "192.0.2.41"
            )
        else:
            source_ip = "192.0.2.40"

        events.append({
            "timestamp": start + timedelta(minutes=minute),
            "username": "synthetic_user",
            "source_ip": source_ip,
            "status": "failure",
        })

    for index in range(successful_logins):
        events.append({
            "timestamp": start + timedelta(minutes=index),
            "username": "normal_user",
            "source_ip": "192.0.2.60",
            "status": "success",
        })

    events.sort(key=lambda event: event["timestamp"])

    return {
        "name": name,
        "expected_suspicious": expected_suspicious,
        "events": events,
    }


def create_scenarios():
    """Define labels before running any detection rules."""
    scenarios = []

    # 15 suspicious scenarios: at least five failures from one IP
    # occur within a five-minute window.
    for count in range(5, 10):
        for spacing in (1, 0.5, 0.75):
            minutes = [int(i * spacing) for i in range(count)]
            # Avoid duplicate timestamps caused by integer rounding.
            minutes = sorted(minutes)
            scenarios.append(build_scenario(
                f"suspicious_{len(scenarios) + 1:02}",
                True,
                minutes,
                successful_logins=2,
            ))

    # 15 benign scenarios: no IP reaches five failures within
    # any five-minute window.
    benign_specs = [
        ("benign_no_failures", [], "same"),
        ("benign_one_failure", [1], "same"),
        ("benign_two_failures", [1, 2], "same"),
        ("benign_three_failures", [0, 1, 2], "same"),
        ("benign_four_failures", [0, 1, 2, 3], "same"),
        ("benign_spread_1", [0, 2, 4, 6, 8], "same"),
        ("benign_spread_2", [0, 3, 6, 9, 12], "same"),
        ("benign_split_1", [0, 1, 2, 3, 4, 5], "split"),
        ("benign_split_2", [0, 1, 2, 3, 4, 5], "split"),
        ("benign_spread_3", [0, 2, 4, 7, 9], "same"),
        ("benign_four_late", [10, 11, 12, 13], "same"),
        ("benign_two_groups", [0, 1, 10, 11], "same"),
        ("benign_spread_4", [0, 3, 6, 9], "same"),
        ("benign_split_3", [0, 1, 2, 3], "split"),
        ("benign_spread_5", [0, 2, 5, 7], "same"),
    ]

    for name, minutes, ip_mode in benign_specs:
        scenarios.append(build_scenario(
            name,
            False,
            minutes,
            ip_mode=ip_mode,
            successful_logins=5,
        ))

    return scenarios


def calculate_metrics(tp, fp, tn, fn):
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0.0
    )
    fpr = fp / (fp + tn) if fp + tn else 0.0

    return precision, recall, f1, fpr


def main():
    scenarios = create_scenarios()
    scenario_results = []
    summary_results = []

    original_threshold = detector.THRESHOLD
    original_window = detector.WINDOW_MINUTES

    try:
        detector.WINDOW_MINUTES = WINDOW_MINUTES

        for threshold in (3, 5, 10):
            detector.THRESHOLD = threshold
            tp = fp = tn = fn = 0

            for scenario in scenarios:
                started = time.perf_counter()
                alerts = detector.detect_repeated_failures(
                    scenario["events"]
                )
                elapsed_ms = (time.perf_counter() - started) * 1000

                detected = len(alerts) > 0
                expected = scenario["expected_suspicious"]

                if expected and detected:
                    tp += 1
                    outcome = "TP"
                elif expected and not detected:
                    fn += 1
                    outcome = "FN"
                elif not expected and detected:
                    fp += 1
                    outcome = "FP"
                else:
                    tn += 1
                    outcome = "TN"

                scenario_results.append({
                    "threshold": threshold,
                    "scenario": scenario["name"],
                    "expected_suspicious": expected,
                    "detected": detected,
                    "outcome": outcome,
                    "event_count": len(scenario["events"]),
                    "processing_time_ms": round(elapsed_ms, 6),
                })

            precision, recall, f1, fpr = calculate_metrics(tp, fp, tn, fn)

            summary_results.append({
                "threshold": threshold,
                "window_minutes": WINDOW_MINUTES,
                "TP": tp,
                "FP": fp,
                "TN": tn,
                "FN": fn,
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1_score": round(f1, 4),
                "false_positive_rate": round(fpr, 4),
            })

    finally:
        detector.THRESHOLD = original_threshold
        detector.WINDOW_MINUTES = original_window

    RESULTS_DIR.mkdir(exist_ok=True)

    def save_csv(filename, rows):
        path = RESULTS_DIR / filename
        with path.open("w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
        print(f"Saved: {path}")

    save_csv("scenario_results.csv", scenario_results)
    save_csv("threshold_comparison.csv", summary_results)

    print("\n=== Threshold Comparison ===")
    for row in summary_results:
        print(
            f"Threshold={row['threshold']}: "
            f"TP={row['TP']} FP={row['FP']} "
            f"TN={row['TN']} FN={row['FN']} | "
            f"Precision={row['precision']:.3f} "
            f"Recall={row['recall']:.3f} "
            f"F1={row['f1_score']:.3f} "
            f"FPR={row['false_positive_rate']:.3f}"
        )

    print(f"\nScenarios evaluated per threshold: {len(scenarios)}")


if __name__ == "__main__":
    main()