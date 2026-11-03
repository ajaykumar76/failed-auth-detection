from pathlib import Path
import csv
import re
import subprocess
import sys
print("=== EXPERIMENT EXECUTION ===")
experiment_scripts = [
    "tests/test_generalisation.py",
    "tests/test_extended_scenarios.py",
    "tests/test_threshold_sensitivity.py",
]

experiment_results = []
for script in experiment_scripts:
    print(f"\nRunning {script}...")
    experiment = subprocess.run(
        [sys.executable, script],
        text=True
    )
    experiment_results.append(experiment.returncode == 0)
    print(f"{script} passed:", experiment.returncode == 0)
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

print("\n=== GENERALISATION V2 CHECKS ===")
with Path("results/generalisation_v2_metrics.csv").open(
    newline="", encoding="utf-8-sig"
) as f:
    generalisation_metrics = list(csv.DictReader(f))

with Path("results/generalisation_v2_comparison.csv").open(
    newline="", encoding="utf-8-sig"
) as f:
    comparison_rows = list(csv.DictReader(f))

with Path("results/generalisation_v2_scenarios.csv").open(
    newline="", encoding="utf-8-sig"
) as f:
    scenario_rows = list(csv.DictReader(f))

metric_by_detector = {row["detector"]: row for row in generalisation_metrics}
expected_metrics = {
    "baseline": {"TP": "3", "FP": "0", "TN": "4", "FN": "2",
                 "precision": "1.0", "recall": "0.6",
                 "f1_score": "0.75", "false_positive_rate": "0.0"},
    "enhanced": {"TP": "4", "FP": "0", "TN": "4", "FN": "1",
                 "precision": "1.0", "recall": "0.8",
                 "f1_score": "0.8889", "false_positive_rate": "0.0"},
}
metrics_match = (
    set(metric_by_detector) == set(expected_metrics)
    and all(
        all(metric_by_detector[name].get(key) == value
            for key, value in expected.items())
        for name, expected in expected_metrics.items()
    )
)

comparison_by_scenario = {row["scenario"]: row for row in comparison_rows}
scenario_by_name = {row["scenario"]: row for row in scenario_rows}
scenario_names_match = (
    len(comparison_rows) == 9
    and len(scenario_rows) == 9
    and set(comparison_by_scenario) == set(scenario_by_name)
)
baseline_outcomes_match = scenario_names_match and all(
    comparison_by_scenario[name]["baseline_detected"]
        == scenario_by_name[name]["baseline_detected"]
    and comparison_by_scenario[name]["baseline_outcome"]
        == scenario_by_name[name]["baseline_outcome"]
    for name in scenario_by_name
)

print("Metrics match expected results:", metrics_match)
print("Comparison CSV has 9 scenarios:", len(comparison_rows) == 9)
print("Scenario CSV has 9 scenarios:", len(scenario_rows) == 9)
print("Scenario names agree across CSVs:", scenario_names_match)
print("Baseline outcomes agree across CSVs:", baseline_outcomes_match)
print("\n=== UNIT TESTS ===")
result = subprocess.run(
    [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
    text=True
)
print("Unit tests passed:", result.returncode == 0)

checks = [
    all(experiment_results),
    numbers == expected,
    main_table,
    threshold_table,
    supplementary_table,
    len(threshold_rows) == 8,
    len(extended_rows) == 6,
    metrics_match,
    len(comparison_rows) == 9,
    len(scenario_rows) == 9,
    scenario_names_match,
    baseline_outcomes_match,
    result.returncode == 0,
]
print("\nOVERALL:", "PASS" if all(checks) else "CHECK FAILED")
sys.exit(0 if all(checks) else 1)
