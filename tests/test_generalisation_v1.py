import csv
import sys
from pathlib import Path
from datetime import datetime, timedelta
PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

import main as detector

RESULTS_DIR = PROJECT_DIR / "results"


def make_events(attempts):
    """Build synthetic events from (minute, username, IP, status)."""
    start = datetime(2026, 10, 31, 9, 0, 0)
    events = []

    for minute, username, source_ip, status in attempts:
        events.append({
            "timestamp": start + timedelta(minutes=minute),
            "username": username,
            "source_ip": source_ip,
            "status": status,
        })

    return sorted(events, key=lambda event: event["timestamp"])


def scenarios():
    """Labels represent predefined synthetic test patterns."""
    return [
        {
            "name": "rapid_repeated_failures",
            "expected_suspicious": True,
            "events": make_events([
                (0, "alice", "192.0.2.10", "failure"),
                (1, "alice", "192.0.2.10", "failure"),
                (2, "alice", "192.0.2.10", "failure"),
                (3, "alice", "192.0.2.10", "failure"),
                (4, "alice", "192.0.2.10", "failure"),
                (5, "alice", "192.0.2.10", "failure"),
            ]),
        },
        {
            "name": "slow_repeated_failures",
            "expected_suspicious": True,
            "events": make_events([
                (0, "alice", "192.0.2.11", "failure"),
                (10, "alice", "192.0.2.11", "failure"),
                (20, "alice", "192.0.2.11", "failure"),
                (30, "alice", "192.0.2.11", "failure"),
                (40, "alice", "192.0.2.11", "failure"),
                (50, "alice", "192.0.2.11", "failure"),
            ]),
        },
        {
            "name": "distributed_failures_same_account",
            "expected_suspicious": True,
            "events": make_events([
                (0, "alice", "192.0.2.20", "failure"),
                (1, "alice", "192.0.2.21", "failure"),
                (2, "alice", "192.0.2.22", "failure"),
                (3, "alice", "192.0.2.23", "failure"),
                (4, "alice", "192.0.2.24", "failure"),
                (5, "alice", "192.0.2.25", "failure"),
            ]),
        },
        {
            "name": "four_benign_failures",
            "expected_suspicious": False,
            "events": make_events([
                (0, "bob", "192.0.2.30", "failure"),
                (1, "bob", "192.0.2.30", "failure"),
                (2, "bob", "192.0.2.30", "failure"),
                (3, "bob", "192.0.2.30", "failure"),
            ]),
        },
        {
            "name": "successful_logins_only",
            "expected_suspicious": False,
            "events": make_events([
                (0, "bob", "192.0.2.31", "success"),
                (1, "alice", "192.0.2.32", "success"),
                (2, "carol", "192.0.2.33", "success"),
            ]),
        },
        {
            "name": "failures_split_between_ips",
            "expected_suspicious": False,
            "events": make_events([
                (0, "bob", "192.0.2.40", "failure"),
                (1, "bob", "192.0.2.41", "failure"),
                (2, "bob", "192.0.2.40", "failure"),
                (3, "bob", "192.0.2.41", "failure"),
            ]),
        },
    ]


def main():
    original_threshold = detector.THRESHOLD
    original_window = detector.WINDOW_MINUTES
    detector.THRESHOLD = 5
    detector.WINDOW_MINUTES = 5

    rows = []
    tp = fp = tn = fn = 0

    try:
        for case in scenarios():
            alerts = detector.detect_repeated_failures(case["events"])
            detected = bool(alerts)
            expected = case["expected_suspicious"]

            if expected and detected:
                outcome = "TP"
                tp += 1
            elif expected and not detected:
                outcome = "FN"
                fn += 1
            elif not expected and detected:
                outcome = "FP"
                fp += 1
            else:
                outcome = "TN"
                tn += 1

            rows.append({
                "scenario": case["name"],
                "expected_suspicious": expected,
                "detected": detected,
                "outcome": outcome,
            })
    finally:
        detector.THRESHOLD = original_threshold
        detector.WINDOW_MINUTES = original_window

    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0
    )
    fpr = fp / (fp + tn) if fp + tn else 0

    RESULTS_DIR.mkdir(exist_ok=True)
    output = RESULTS_DIR / "generalisation_results.csv"

    with output.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "scenario", "expected_suspicious", "detected", "outcome"
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    print("=== Generalisation Experiment ===")
    print(f"TP={tp}, FP={fp}, TN={tn}, FN={fn}")
    print(f"Precision: {precision:.3f}")
    print(f"Recall: {recall:.3f}")
    print(f"F1-score: {f1:.3f}")
    print(f"False-positive rate: {fpr:.3f}")
    print(f"Saved results to: {output}")

    print("\nScenario outcomes:")
    for row in rows:
        print(f"{row['scenario']}: {row['outcome']}")


if __name__ == "__main__":
    main()