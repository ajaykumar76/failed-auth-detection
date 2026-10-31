
import csv
import sys
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

import main as detector

RESULTS_DIR = PROJECT_DIR / "results"
THRESHOLD = 5
WINDOW_MINUTES = 5


def make_events(attempts):
    """Build events from (minute, username, source_ip, status)."""
    start = datetime(2026, 10, 31, 9, 0, 0)
    events = [
        {
            "timestamp": start + timedelta(minutes=minute),
            "username": username,
            "source_ip": source_ip,
            "status": status,
        }
        for minute, username, source_ip, status in attempts
    ]
    return sorted(events, key=lambda event: event["timestamp"])


def scenarios():
    """Expected labels are defined before detector execution."""
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
            ]),
        },
        {
            "name": "distributed_failures_same_account",
            "expected_suspicious": True,
            "events": make_events([
                (0, "alice", f"192.0.2.{20+i}", "failure")
                for i in range(5)
            ]),
        },
        {
            "name": "one_ip_multiple_accounts",
            "expected_suspicious": True,
            "events": make_events([
                (0, "alice", "192.0.2.30", "failure"),
                (1, "bob", "192.0.2.30", "failure"),
                (2, "carol", "192.0.2.30", "failure"),
                (3, "dave", "192.0.2.30", "failure"),
                (4, "erin", "192.0.2.30", "failure"),
            ]),
        },
        {
            "name": "five_failures_at_window_boundary",
            "expected_suspicious": True,
            "events": make_events([
                (0, "alice", "192.0.2.40", "failure"),
                (1, "alice", "192.0.2.40", "failure"),
                (2, "alice", "192.0.2.40", "failure"),
                (3, "alice", "192.0.2.40", "failure"),
                (5, "alice", "192.0.2.40", "failure"),
            ]),
        },
        {
            "name": "four_benign_failures",
            "expected_suspicious": False,
            "events": make_events([
                (0, "bob", "192.0.2.50", "failure"),
                (1, "bob", "192.0.2.50", "failure"),
                (2, "bob", "192.0.2.50", "failure"),
                (3, "bob", "192.0.2.50", "failure"),
            ]),
        },
        {
            "name": "successful_logins_only",
            "expected_suspicious": False,
            "events": make_events([
                (0, "bob", "192.0.2.51", "success"),
                (1, "alice", "192.0.2.52", "success"),
                (2, "carol", "192.0.2.53", "success"),
            ]),
        },
        {
            "name": "failures_split_between_ips",
            "expected_suspicious": False,
            "events": make_events([
                (0, "bob", "192.0.2.60", "failure"),
                (1, "bob", "192.0.2.61", "failure"),
                (2, "bob", "192.0.2.60", "failure"),
                (3, "bob", "192.0.2.61", "failure"),
            ]),
        },
        {
            "name": "failures_mixed_with_successes",
            "expected_suspicious": False,
            "events": make_events([
                (0, "bob", "192.0.2.70", "failure"),
                (1, "bob", "192.0.2.70", "success"),
                (2, "bob", "192.0.2.70", "failure"),
                (3, "bob", "192.0.2.70", "success"),
                (4, "bob", "192.0.2.70", "failure"),
                (5, "bob", "192.0.2.70", "failure"),
            ]),
        },
    ]


def baseline_detector(events):
    """Baseline: threshold failures from one IP in a rolling window."""
    failures_by_ip = defaultdict(deque)
    alerts = []
    window = timedelta(minutes=detector.WINDOW_MINUTES)

    for event in sorted(events, key=lambda item: item["timestamp"]):
        if event["status"] != "failure":
            continue

        source_ip = event["source_ip"]
        event_time = event["timestamp"]
        recent = failures_by_ip[source_ip]

        while recent and event_time - recent[0] > window:
            recent.popleft()

        recent.append(event_time)

        if len(recent) >= detector.THRESHOLD:
            alerts.append({"source_ip": source_ip})
            # Only detection/non-detection is evaluated.
            break

    return alerts


def outcome(expected, detected):
    if expected and detected:
        return "TP"
    if expected and not detected:
        return "FN"
    if not expected and detected:
        return "FP"
    return "TN"


def calculate_metrics(rows, detected_field):
    tp = fp = tn = fn = 0

    for row in rows:
        expected = row["expected_suspicious"]
        detected = row[detected_field]

        if expected and detected:
            tp += 1
        elif not expected and detected:
            fp += 1
        elif not expected and not detected:
            tn += 1
        else:
            fn += 1

    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0
    )
    fpr = fp / (fp + tn) if fp + tn else 0

    return {
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
    }


def write_csv(path, rows, fieldnames):
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main():
    original_threshold = detector.THRESHOLD
    original_window = detector.WINDOW_MINUTES

    detector.THRESHOLD = THRESHOLD
    detector.WINDOW_MINUTES = WINDOW_MINUTES

    scenario_rows = []
    comparison_rows = []

    try:
        for case in scenarios():
            expected = case["expected_suspicious"]
            events = case["events"]

            baseline_detected = bool(baseline_detector(events))
            enhanced_alerts = detector.detect_repeated_failures(events)
            enhanced_detected = bool(enhanced_alerts)

            baseline_outcome = outcome(expected, baseline_detected)
            enhanced_outcome = outcome(expected, enhanced_detected)

            scenario_rows.append({
                "scenario": case["name"],
                "expected_suspicious": expected,
                "baseline_detected": baseline_detected,
                "baseline_outcome": baseline_outcome,
            })

            comparison_rows.append({
                "scenario": case["name"],
                "expected_suspicious": expected,
                "baseline_detected": baseline_detected,
                "baseline_outcome": baseline_outcome,
                "enhanced_detected": enhanced_detected,
                "enhanced_outcome": enhanced_outcome,
            })
    finally:
        detector.THRESHOLD = original_threshold
        detector.WINDOW_MINUTES = original_window

    baseline_metrics = calculate_metrics(
        comparison_rows, "baseline_detected"
    )
    enhanced_metrics = calculate_metrics(
        comparison_rows, "enhanced_detected"
    )

    RESULTS_DIR.mkdir(exist_ok=True)

    write_csv(
        RESULTS_DIR / "generalisation_v2_scenarios.csv",
        scenario_rows,
        [
            "scenario",
            "expected_suspicious",
            "baseline_detected",
            "baseline_outcome",
        ],
    )

    write_csv(
        RESULTS_DIR / "generalisation_v2_comparison.csv",
        comparison_rows,
        [
            "scenario",
            "expected_suspicious",
            "baseline_detected",
            "baseline_outcome",
            "enhanced_detected",
            "enhanced_outcome",
        ],
    )

    metrics_rows = [
        {"detector": "baseline", **baseline_metrics},
        {"detector": "enhanced", **enhanced_metrics},
    ]

    write_csv(
        RESULTS_DIR / "generalisation_v2_metrics.csv",
        metrics_rows,
        [
            "detector", "TP", "FP", "TN", "FN", "precision",
            "recall", "f1_score", "false_positive_rate",
        ],
    )

    print("=== Expanded Synthetic Evaluation ===")
    print(f"Scenarios: {len(comparison_rows)}")

    for name, metrics in [
        ("Baseline", baseline_metrics),
        ("Enhanced", enhanced_metrics),
    ]:
        print(f"\n{name}")
        for key, value in metrics.items():
            print(f"{key}: {value}")

    print("\nScenario outcomes:")
    for row in comparison_rows:
        print(
            f"{row['scenario']}: "
            f"baseline={row['baseline_outcome']}, "
            f"enhanced={row['enhanced_outcome']}"
        )

    print("\nNew files saved in:", RESULTS_DIR)


if __name__ == "__main__":
    main()
