
import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

from main import detect_repeated_failures


class DetectionTests(unittest.TestCase):

    def make_events(self, statuses_and_minutes):
        start = datetime(2026, 10, 31, 9, 0, 0)
        events = []

        for status, minute in statuses_and_minutes:
            events.append({
                "timestamp": start + timedelta(minutes=minute),
                "username": "test_user",
                "source_ip": "192.0.2.25",
                "status": status,
            })

        return sorted(events, key=lambda event: event["timestamp"])

    def test_five_failures_trigger_alert(self):
        events = self.make_events([
            ("failure", 0), ("failure", 1), ("failure", 2),
            ("failure", 3), ("failure", 4),
        ])
        self.assertTrue(detect_repeated_failures(events))

    def test_four_failures_do_not_trigger_alert(self):
        events = self.make_events([
            ("failure", 0), ("failure", 1),
            ("failure", 2), ("failure", 3),
        ])
        self.assertEqual(len(detect_repeated_failures(events)), 0)

    def test_failures_outside_window_do_not_trigger_alert(self):
        events = self.make_events([
            ("failure", 0), ("failure", 1), ("failure", 2),
            ("failure", 3), ("failure", 6),
        ])
        self.assertEqual(len(detect_repeated_failures(events)), 0)

    def test_successes_do_not_count(self):
        events = self.make_events([
            ("failure", 0), ("success", 1), ("failure", 2),
            ("success", 3), ("failure", 4), ("failure", 5),
            ("success", 6),
        ])
        self.assertEqual(len(detect_repeated_failures(events)), 0)

    def test_failures_for_same_username_across_ips_trigger_alert(self):
        start = datetime(2026, 1, 1, 12, 0, 0)
        events = []

        for i in range(5):
            events.append({
                "timestamp": start + timedelta(minutes=i),
                "username": "alice",
                "source_ip": f"192.0.2.{10 + i}",
                "status": "failure",
            })

        alerts = detect_repeated_failures(events)
        self.assertTrue(any("Rule 2" in alert["rule"] for alert in alerts))

    def test_failure_exactly_five_minutes_apart_is_included(self):
        start = datetime(2026, 1, 1, 12, 0, 0)
        events = []

        for minute in [0, 1, 2, 3, 5]:
            events.append({
                "timestamp": start + timedelta(minutes=minute),
                "username": "alice",
                "source_ip": "192.0.2.10",
                "status": "failure",
            })

        alerts = detect_repeated_failures(events)
        self.assertTrue(any("Rule 1" in alert["rule"] for alert in alerts))

    def test_rule_two_emits_only_one_alert_per_username(self):
        start = datetime(2026, 1, 1, 12, 0, 0)
        attempts = [
            (0, "192.0.2.80"),
            (1, "192.0.2.81"),
            (2, "192.0.2.82"),
            (3, "192.0.2.80"),
            (4, "192.0.2.81"),
            (4, "192.0.2.82"),
            (4, "192.0.2.80"),
        ]

        events = []
        for minute, ip in attempts:
            events.append({
                "timestamp": start + timedelta(minutes=minute),
                "username": "alice",
                "source_ip": ip,
                "status": "failure",
            })

        alerts = detect_repeated_failures(events)
        rule_two_alerts = [
            alert for alert in alerts if "Rule 2" in alert["rule"]
        ]
        self.assertEqual(len(rule_two_alerts), 1)

    def test_unsorted_events_do_not_create_false_alert(self):
        start = datetime(2026, 1, 1, 12, 0, 0)

        events = []
        for minute in [10, 0, 1, 2, 3]:
            events.append({
                "timestamp": start + timedelta(minutes=minute),
                "username": "alice",
                "source_ip": "192.0.2.10",
                "status": "failure",
            })

        alerts = detect_repeated_failures(events)

        self.assertFalse(
            any("Rule 1" in alert["rule"] for alert in alerts),
            "Unsorted events must not create a false Rule 1 alert.",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)