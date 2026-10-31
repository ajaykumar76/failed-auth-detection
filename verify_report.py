from pathlib import Path
import csv
import re
import subprocess
import sys

report_path = Path("results/experiment_report.md")
text = report_path.read_text(encoding="utf-8-sig")
lines = text.splitlines()

print("=== SECTION ORDER ===")
headings = [
    (i + 1, line.strip())
    for i, line in enumerate(lines)
    if re.match(r"^\s*\d+\\?\.\s+", line)
]
for line_no, heading in headings:
    print(f"{line_no}: {heading}")

numbers = [
    int(re.match(r"^\s*(\d+)", heading).group(1))
    for _, heading in headings
]
expected = list(range(1, 11))
print("Sections 1-10 in order:", numbers == expected)

print("\n=== TABLE CHECKS ===")
main_table = "| Metric | Baseline | Enhanced |" in text
threshold_table = "| Threshold | Detector | TP | FP | TN | FN | Precision | Recall | F1 score | False-positive rate |" in text
supplementary_table = "| Metric | Result |" in text
print("Main results table:", main_table)
print("Threshold sensitivity table:", threshold_table)
print("Section 10 metrics table:", supplementary_table)

with Path("results/threshold_sensitivity.csv").open(
    newline="", encoding="utf-8-sig"
) as f:
    threshold_rows = list(csv.DictReader(f))
print("Threshold CSV rows:", len(threshold_rows), "(expected 8)")

with Path("results/extended_scenarios.csv").open(
    newline="", encoding="utf-8-sig"
) as f:
    extended_rows = list(csv.DictReader(f))
print("Extended scenario CSV rows:", len(extended_rows), "(expected 6)")

print("\n=== UNIT TESTS ===")
result = subprocess.run(
    [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
    text=True
)
print("Unit tests passed:", result.returncode == 0)

checks = [
    numbers == expected,
    main_table,
    threshold_table,
    supplementary_table,
    len(threshold_rows) == 8,
    len(extended_rows) == 6,
    result.returncode == 0,
]
print("\nOVERALL:", "PASS" if all(checks) else "CHECK FAILED")
