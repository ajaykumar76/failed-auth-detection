
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone


# Experimental Rule 3: Distributed multi-account failure detection
SPRAY_THRESHOLD = 5
SPRAY_WINDOW_MINUTES = 5
MIN_SPRAY_IPS = 2
MIN_SPRAY_USERNAMES = 5


# Experimental Rule 4: Long-window repeated failures
SLOW_THRESHOLD = 5
SLOW_WINDOW_MINUTES = 60
SLOW_MIN_SPAN_MINUTES = 30


def normalise_events(events):
    """Validate events and normalise timestamps to UTC."""
    normalised = []

    for event in events:
        if not isinstance(event, dict):
            raise ValueError("Each event must be a dictionary.")

        timestamp = event.get("timestamp")

        if not isinstance(timestamp, datetime):
            raise ValueError("Event timestamp must be a datetime object.")

        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("Event timestamp must be timezone-aware.")

        if event.get("status") not in {"success", "failure"}:
            raise ValueError("Invalid authentication status.")

        username = event.get("username")
        source_ip = event.get("source_ip")

        if not isinstance(username, str) or not username.strip():
            raise ValueError("Username must not be empty.")

        if not isinstance(source_ip, str) or not source_ip.strip():
            raise ValueError("Source IP must not be empty.")

        item = dict(event)
        item["timestamp"] = timestamp.astimezone(timezone.utc)
        normalised.append(item)

    return sorted(normalised, key=lambda item: item["timestamp"])


def detect_distributed_spraying(events):
    """
    Detect a heuristic pattern of failures across multiple IPs
    and multiple usernames within a short time window.

    This does not establish that the activity is password spraying.
    """
    events = normalise_events(events)
    recent_failures = deque()
    alerts = []

    window = timedelta(minutes=SPRAY_WINDOW_MINUTES)

    for event in events:
        if event["status"] != "failure":
            continue

        event_time = event["timestamp"]

        while (
            recent_failures
            and event_time - recent_failures[0]["timestamp"] > window
        ):
            recent_failures.popleft()

        recent_failures.append(event)

        distinct_ips = {
            item["source_ip"] for item in recent_failures
        }
        distinct_usernames = {
            item["username"] for item in recent_failures
        }

        if (
            len(recent_failures) >= SPRAY_THRESHOLD
            and len(distinct_ips) >= MIN_SPRAY_IPS
            and len(distinct_usernames) >= MIN_SPRAY_USERNAMES
        ):
            alerts.append({
                "rule": "Rule 3: Distributed multi-account failures",
                "timestamp": event_time,
                "failure_count": len(recent_failures),
                "distinct_ips": len(distinct_ips),
                "distinct_usernames": len(distinct_usernames),
            })
            break

    return alerts


def detect_low_and_slow_failures(events):
    """
    Detect repeated failures against one username from one IP
    within a 60-minute window and spanning at least 30 minutes.

    The span condition does not prove evenly spaced activity.
    """
    events = normalise_events(events)
    failures = defaultdict(deque)
    alerts = []

    window = timedelta(minutes=SLOW_WINDOW_MINUTES)
    minimum_span = timedelta(minutes=SLOW_MIN_SPAN_MINUTES)

    for event in events:
        if event["status"] != "failure":
            continue

        key = (event["username"], event["source_ip"])
        recent = failures[key]
        event_time = event["timestamp"]

        while recent and event_time - recent[0] > window:
            recent.popleft()

        recent.append(event_time)

        if (
            len(recent) >= SLOW_THRESHOLD
            and event_time - recent[0] >= minimum_span
        ):
            alerts.append({
                "rule": "Rule 4: Long-window repeated failures",
                "username": event["username"],
                "source_ip": event["source_ip"],
                "timestamp": event_time,
                "failure_count": len(recent),
                "window_minutes": SLOW_WINDOW_MINUTES,
                "minimum_span_minutes": SLOW_MIN_SPAN_MINUTES,
            })
            break

    return alerts


def detect_experimental(events):
    """Run both experimental detection rules."""
    events = normalise_events(events)

    return (
        detect_distributed_spraying(events)
        + detect_low_and_slow_failures(events)
    )
