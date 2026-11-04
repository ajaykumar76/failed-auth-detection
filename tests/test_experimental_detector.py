import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

from experimental_detector import (
    detect_distributed_spraying,
    detect_low_and_slow_failures,
    detect_experimental,
)


def make_events(attempts):
    start = datetime(2026, 11, 3, 9, 0, tzinfo=timezone.utc)

    return [
        {
            "timestamp": start + timedelta(minutes=minute),
            "username": username,
            "source_ip": source_ip,
            "status": status,
        }
        for minute, username, source_ip, status in attempts
    ]


class ExperimentalDetectorTests(unittest.TestCase):

    def test_invalid_event_status_is_rejected(self):
        events = make_events([
            (0, "alice", "192.0.2.1", "unknown"),
        ])

        with self.assertRaises(ValueError):
            detect_experimental(events)

    def test_distributed_spraying_detected(self):
        events = make_events([
            (0, "alice", "192.0.2.1", "failure"),
            (1, "bob", "192.0.2.2", "failure"),
            (2, "carol", "192.0.2.3", "failure"),
            (3, "dave", "192.0.2.4", "failure"),
            (4, "erin", "192.0.2.5", "failure"),
        ])

        alerts = detect_distributed_spraying(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["distinct_ips"], 5)
        self.assertEqual(alerts[0]["distinct_usernames"], 5)

    def test_four_distributed_failures_do_not_trigger(self):
        events = make_events([
            (0, "alice", "192.0.2.1", "failure"),
            (1, "bob", "192.0.2.2", "failure"),
            (2, "carol", "192.0.2.3", "failure"),
            (3, "dave", "192.0.2.4", "failure"),
        ])

        self.assertEqual(detect_distributed_spraying(events), [])

    def test_same_username_from_multiple_ips_does_not_trigger_spraying(self):
        events = make_events([
            (0, "alice", "192.0.2.1", "failure"),
            (1, "alice", "192.0.2.2", "failure"),
            (2, "alice", "192.0.2.3", "failure"),
            (3, "alice", "192.0.2.4", "failure"),
            (4, "alice", "192.0.2.5", "failure"),
        ])

        self.assertEqual(detect_distributed_spraying(events), [])

    def test_low_and_slow_failures_detected(self):
        events = make_events([
            (0, "alice", "192.0.2.10", "failure"),
            (10, "alice", "192.0.2.10", "failure"),
            (20, "alice", "192.0.2.10", "failure"),
            (30, "alice", "192.0.2.10", "failure"),
            (40, "alice", "192.0.2.10", "failure"),
        ])

        alerts = detect_low_and_slow_failures(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["failure_count"], 5)

    def test_failures_outside_slow_window_do_not_trigger(self):
        events = make_events([
            (0, "alice", "192.0.2.10", "failure"),
            (20, "alice", "192.0.2.10", "failure"),
            (40, "alice", "192.0.2.10", "failure"),
            (60, "alice", "192.0.2.10", "failure"),
            (61, "alice", "192.0.2.10", "failure"),
        ])

        self.assertEqual(detect_low_and_slow_failures(events), [])

    def test_sporadic_failures_outside_spray_window_do_not_trigger(self):
        events = make_events([
            (0, "alice", "192.0.2.1", "failure"),
            (2, "bob", "192.0.2.2", "failure"),
            (4, "carol", "192.0.2.3", "failure"),
            (6, "dave", "192.0.2.4", "failure"),
            (8, "erin", "192.0.2.5", "failure"),
        ])

        self.assertEqual(detect_distributed_spraying(events), [])

    def test_successful_logins_do_not_trigger(self):
        events = make_events([
            (0, "alice", "192.0.2.1", "success"),
            (1, "bob", "192.0.2.2", "success"),
            (2, "carol", "192.0.2.3", "success"),
            (3, "dave", "192.0.2.4", "success"),
            (4, "erin", "192.0.2.5", "success"),
        ])

        self.assertEqual(detect_experimental(events), [])

    def test_combined_detector_detects_both_patterns(self):
        spraying_events = [
            (0, "alice", "192.0.2.1", "failure"),
            (1, "bob", "192.0.2.2", "failure"),
            (2, "carol", "192.0.2.3", "failure"),
            (3, "dave", "192.0.2.4", "failure"),
            (4, "erin", "192.0.2.5", "failure"),
        ]

        slow_events = [
            (10, "frank", "192.0.2.10", "failure"),
            (20, "frank", "192.0.2.10", "failure"),
            (30, "frank", "192.0.2.10", "failure"),
            (40, "frank", "192.0.2.10", "failure"),
            (50, "frank", "192.0.2.10", "failure"),
        ]

        events = make_events(spraying_events + slow_events)
        alerts = detect_experimental(events)

        rules = {alert["rule"] for alert in alerts}

        self.assertIn(
            "Rule 3: Distributed multi-account failures",
            rules,
        )
        self.assertIn(
            "Rule 4: Long-window repeated failures",
            rules,
        )
    def test_low_and_slow_exact_30_minute_span_triggers(self):
        events = make_events([
            (0, "alice", "192.0.2.10", "failure"),
            (5, "alice", "192.0.2.10", "failure"),
            (10, "alice", "192.0.2.10", "failure"),
            (20, "alice", "192.0.2.10", "failure"),
            (30, "alice", "192.0.2.10", "failure"),
        ])

        alerts = detect_low_and_slow_failures(events)

        self.assertEqual(len(alerts), 1)

    def test_low_and_slow_29_minute_span_does_not_trigger(self):
        events = make_events([
            (0, "alice", "192.0.2.10", "failure"),
            (5, "alice", "192.0.2.10", "failure"),
            (10, "alice", "192.0.2.10", "failure"),
            (20, "alice", "192.0.2.10", "failure"),
            (29, "alice", "192.0.2.10", "failure"),
        ])

        alerts = detect_low_and_slow_failures(events)

        self.assertEqual(alerts, [])

    def test_four_rapid_failures_then_one_later_failure_triggers(self):
        events = make_events([
            (0, "alice", "192.0.2.10", "failure"),
            (0, "alice", "192.0.2.10", "failure"),
            (0, "alice", "192.0.2.10", "failure"),
            (1, "alice", "192.0.2.10", "failure"),
            (30, "alice", "192.0.2.10", "failure"),
        ])

        alerts = detect_low_and_slow_failures(events)

        self.assertEqual(len(alerts), 1)
