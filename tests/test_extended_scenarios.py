
import csv
import sys
from datetime import datetime, timedelta
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

import main as detector

RESULTS_DIR = PROJECT_DIR / "results"


def make_events(attempts):
    start = datetime(2026, 10, 31, 9, 0, 0)
    return sorted(
        [
            {
                "timestamp": start + timedelta(minutes=minute),
                "username": username,
                "source_ip": source_ip,
                "status": status,
            }
            for minute, username, source_ip, status in attempts
        ],
        key=lambda event: event["timestamp"],
    )


def get_scenarios():
    return [
        {
            "name": "six_failures_over_long_period",
            "expected_suspicious": True,
            "events": make_events([
                (0, "alice", "192.0.2.101", "failure"),
                (10, "alice", "192.0.2.101", "failure"),
                (20, "alice", "192.0.2.101", "failure"),
                (30, "alice", "192.0.2.101", "failure"),
                (40, "alice", "192.0.2.101", "failure"),
                (50, "alice", "192.0.2.101", "failure"),
            ]),
        },
        {
            "name": "one_ip_targets_five_accounts",
            "expected_suspicious": True,
            "events": make_events([
                (0, "alice", "192.0.2.102", "failure"),
                (1, "bob", "192.0.2.102", "failure"),
                (2, "carol", "192.0.2.102", "failure"),
                (3, "dave", "192.0.2.102", "failure"),
                (4, "erin", "192.0.2.102", "failure"),
            ]),
        },
        {
            "name": "multiple_ips_target_multiple_accounts",
            "expected_suspicious": True,
            "events": make_events([
                (0, "alice", "192.0.2.103", "failure"),
                (1, "bob", "192.0.2.104", "failure"),
                (2, "carol", "192.0.2.105", "failure"),
                (3, "dave", "192.0.2.106", "failure"),
                (4, "erin", "192.0.2.107", "failure"),
            ]),
        },
        {
            "name": "four_failures_then_success",
            "expected_suspicious": False,
            "events": make_events([
                (0, "alice", "192.0.2.108", "failure"),
                (1, "alice", "192.0.2.108", "failure"),
                (2, "alice", "192.0.2.108", "failure"),
                (3, "alice", "192.0.2.108", "failure"),
                (4, "alice", "192.0.2.108", "success"),
            ]),
        },
        {
            "name": "fifth_failure_outside_window",
            "expected_suspicious": False,
            "events": make_events([
                (0, "alice", "192.0.2.109", "failure"),
                (1, "alice", "192.0.2.109", "failure"),
                (2, "alice", "192.0.2.109", "failure"),
                (3, "alice", "192.0.2.109", "failure"),
                (6, "alice", "192.0.2.109", "failure"),
            ]),
        },
        {
            "name": "successful_logins_by_multiple_users",
            "expected_suspicious": False,
            "events": make_events([
                (0, "alice", "192.0.2.110", "success"),
                (1, "bob", "192.0.2.111", "success"),
                (2, "carol", "192.0.2.112", "success"),
                (3, "dave", "192.0.2.113", "success"),
                (4, "erin", "192.0.2.114", "success"),
            ]),
        },
    ]


def main():
    rows = []
    original_threshold = detector.THRESHOLD
    original_window = detector.WINDOW_MINUTES

    try:
        detector.THRESHOLD = 5
        detector.WINDOW_MINUTES = 5

        for scenario in get_scenarios():
            alerts = detector.detect_repeated_failures(scenario["events"])
            detected = bool(alerts)
            expected = scenario["expected_suspicious"]

            if expected and detected:
                outcome = "TP"
            elif expected and not detected:
                outcome = "FN"
            elif not expected and detected:
                outcome = "FP"
            else:
                outcome = "TN"

            rows.append({
                "scenario": scenario["name"],
                "expected_suspicious": expected,
                "detected": detected,
                "outcome": outcome,
                "alert_rules": "; ".join(
                    sorted({alert["rule"].split(":")[0] for alert in alerts})
                ),
            })

    finally:
        detector.THRESHOLD = original_threshold
        detector.WINDOW_MINUTES = original_window

    RESULTS_DIR.mkdir(exist_ok=True)
    output_file = RESULTS_DIR / "extended_scenarios.csv"

    with output_file.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "scenario",
                "expected_suspicious",
                "detected",
                "outcome",
                "alert_rules",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    tp = sum(row["outcome"] == "TP" for row in rows)
    fp = sum(row["outcome"] == "FP" for row in rows)
    tn = sum(row["outcome"] == "TN" for row in rows)
    fn = sum(row["outcome"] == "FN" for row in rows)

    print("=== Extended Synthetic Scenarios ===")
    print(f"Scenarios: {len(rows)}")
    print(f"TP={tp}, FP={fp}, TN={tn}, FN={fn}")

    for row in rows:
        print(
            f"{row['scenario']}: expected="
            f"{row['expected_suspicious']}, detected={row['detected']}, "
            f"outcome={row['outcome']}, rules={row['alert_rules'] or 'none'}"
        )

    print(f"\nSaved: {output_file}")


if __name__ == "__main__":
    main()
