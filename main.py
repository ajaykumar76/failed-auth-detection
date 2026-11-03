
import csv
from collections import deque, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent
LOG_FILE = PROJECT_DIR / "data" / "synthetic_auth_logs.csv"

THRESHOLD = 5
WINDOW_MINUTES = 5


def parse_logs():
    """Read, validate and normalise authentication log timestamps to UTC."""
    valid_events = []
    invalid_count = 0

    with LOG_FILE.open("r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        required = {"timestamp", "username", "source_ip", "status"}
        if not required.issubset(set(reader.fieldnames or [])):
            raise ValueError("CSV is missing required columns.")

        for row in reader:
            try:
                timestamp = datetime.fromisoformat(row["timestamp"])

                # Assume timestamps without an explicit timezone are UTC.
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=timezone.utc)
                else:
                    timestamp = timestamp.astimezone(timezone.utc)

                username = row["username"].strip()
                source_ip = row["source_ip"].strip()
                status = row["status"].strip().lower()

                if not username or not source_ip:
                    raise ValueError("Empty username or source IP.")

                if status not in {"success", "failure"}:
                    raise ValueError("Unknown authentication status.")

                valid_events.append({
                    "timestamp": timestamp,
                    "username": username,
                    "source_ip": source_ip,
                    "status": status,
                })

            except (ValueError, TypeError, KeyError):
                invalid_count += 1

    valid_events.sort(key=lambda event: event["timestamp"])
    return valid_events, invalid_count


def detect_repeated_failures(events):
    """Detect repeated failures by source IP or across IPs for one username."""
    failures_by_ip = defaultdict(deque)
    failures_by_username = defaultdict(deque)
    alerts = []

    window = timedelta(minutes=WINDOW_MINUTES)
    alerted_ip = set()
    alerted_username = set()

    for event in sorted(events, key=lambda event: event["timestamp"]):
        if event["status"] != "failure":
            continue

        source_ip = event["source_ip"]
        username = event["username"]
        event_time = event["timestamp"]

        # Rule 1: repeated failures from a single IP.
        recent_ip_failures = failures_by_ip[source_ip]

        while (
            recent_ip_failures
            and event_time - recent_ip_failures[0] > window
        ):
            recent_ip_failures.popleft()

        recent_ip_failures.append(event_time)

        if (
            len(recent_ip_failures) >= THRESHOLD
            and source_ip not in alerted_ip
        ):
            alerts.append({
                "source_ip": source_ip,
                "username": username,
                "timestamp": event_time,
                "failure_count": len(recent_ip_failures),
                "rule": (
                    f"Rule 1: {THRESHOLD} or more failures from one IP "
                    f"within {WINDOW_MINUTES} minutes"
                ),
            })
            alerted_ip.add(source_ip)

        # Rule 2: repeated failures against one username from multiple IPs.
        recent_user_failures = failures_by_username[username]

        while (
            recent_user_failures
            and event_time - recent_user_failures[0]["timestamp"] > window
        ):
            recent_user_failures.popleft()

        recent_user_failures.append({
            "timestamp": event_time,
            "source_ip": source_ip,
        })

        distinct_ips = {
            failure["source_ip"] for failure in recent_user_failures
        }

        if (
            len(recent_user_failures) >= THRESHOLD
            and len(distinct_ips) >= 2
            and username not in alerted_username
        ):
            alerts.append({
                "source_ip": ", ".join(sorted(distinct_ips)),
                "username": username,
                "timestamp": event_time,
                "failure_count": len(recent_user_failures),
                "rule": (
                    f"Rule 2: {THRESHOLD} or more failures against one "
                    f"username from at least 2 IPs within "
                    f"{WINDOW_MINUTES} minutes"
                ),
            })
            alerted_username.add(username)

    return alerts


if __name__ == "__main__":
    events, invalid_count = parse_logs()
    alerts = detect_repeated_failures(events)

    print(f"Valid events: {len(events)}")
    print(f"Invalid records skipped: {invalid_count}")
    print(f"Alerts detected: {len(alerts)}")

    for alert in alerts:
        print("-" * 40)
        print(f"Rule: {alert['rule']}")
        print(f"Username: {alert['username']}")
        print(f"Source IP: {alert['source_ip']}")
        print(f"Timestamp: {alert['timestamp']}")
        print(f"Failure count: {alert['failure_count']}")
