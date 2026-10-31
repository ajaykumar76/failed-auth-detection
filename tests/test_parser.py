
import csv
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))

import main


class ParserTests(unittest.TestCase):

    def write_csv(self, path, rows, fieldnames=None):
        if fieldnames is None:
            fieldnames = [
                "timestamp", "username", "source_ip", "status"
            ]

        with path.open("w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

    def test_valid_record_is_parsed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "logs.csv"
            self.write_csv(path, [{
                "timestamp": "2026-10-31 09:00:00",
                "username": "user01",
                "source_ip": "192.0.2.10",
                "status": "success",
            }])

            with patch.object(main, "LOG_FILE", path):
                events, invalid = main.parse_logs()

            self.assertEqual(len(events), 1)
            self.assertEqual(invalid, 0)
            self.assertEqual(events[0]["status"], "success")

    def test_invalid_timestamp_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "logs.csv"
            self.write_csv(path, [{
                "timestamp": "not-a-timestamp",
                "username": "user01",
                "source_ip": "192.0.2.10",
                "status": "failure",
            }])

            with patch.object(main, "LOG_FILE", path):
                events, invalid = main.parse_logs()

            self.assertEqual(events, [])
            self.assertEqual(invalid, 1)

    def test_unknown_status_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "logs.csv"
            self.write_csv(path, [{
                "timestamp": "2026-10-31 09:00:00",
                "username": "user01",
                "source_ip": "192.0.2.10",
                "status": "unknown",
            }])

            with patch.object(main, "LOG_FILE", path):
                events, invalid = main.parse_logs()

            self.assertEqual(events, [])
            self.assertEqual(invalid, 1)

    def test_missing_required_column_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "logs.csv"
            self.write_csv(
                path,
                [{
                    "timestamp": "2026-10-31 09:00:00",
                    "username": "user01",
                    "source_ip": "192.0.2.10",
                }],
                fieldnames=["timestamp", "username", "source_ip"],
            )

            with patch.object(main, "LOG_FILE", path):
                with self.assertRaises(ValueError):
                    main.parse_logs()


if __name__ == "__main__":
    unittest.main(verbosity=2)