# Synthetic Authentication Failure Detection

## Overview

This project implements and evaluates a rule-based detector for repeated authentication failures using synthetic log data. It includes two baseline detection rules and two additional experimental rules designed to explore different authentication-failure patterns.

The project compares detection outcomes across manually designed synthetic scenarios. It is an academic research prototype and has not been validated against production authentication logs.

## Detection Rules

### Baseline Rule 1: Repeated failures from one IP

Generate an alert when at least five failed authentication attempts from the same source IP occur within an inclusive rolling five-minute window.

### Baseline Rule 2: Failures against one username from multiple IPs

Generate an alert when at least five failed attempts against the same username occur within an inclusive rolling five-minute window and involve at least two distinct source IP addresses.

### Experimental Rule 3: Distributed multi-account failures

Generate an alert when at least five failed authentication attempts occur within an inclusive rolling five-minute window, involving at least two distinct source IP addresses and at least five distinct usernames.

This is a heuristic for distributed multi-account failure activity. It does not establish that the activity is password spraying or malicious.

### Experimental Rule 4: Long-window repeated failures

Generate an alert when at least five failed authentication attempts against the same username from the same source IP occur within a rolling 60-minute window, spanning at least 30 minutes between the first and latest failure.

The minimum time-span condition does not establish that failures are evenly spaced.

Successful authentication events are excluded from the failure counts.

## Technology

- Python 3
- CSV-based synthetic authentication logs
- Python standard library
- Unit tests and scenario-based evaluation

## Input Data

The synthetic authentication log CSV uses these required columns:

- `timestamp`
- `username`
- `source_ip`
- `status`

Timestamps are parsed using Python's ISO-format datetime parser. Invalid records are counted and excluded. The detector sorts events chronologically before evaluation.

## Running the Experiments

Run these commands from the project root directory.

Run the complete unit-test suite:

    python -m unittest discover -s tests -v

Run the original generalisation experiment:

    python tests/test_generalisation.py

Run the threshold-sensitivity experiment:

    python tests/test_threshold_sensitivity.py

Run the extended-scenario experiment:

    python tests/test_extended_scenarios.py

Run the experimental generalisation evaluation:

    python tests/test_experimental_generalisation.py

Run the experimental detector unit tests:

    python -m unittest discover -s tests -p "test_experimental_detector.py" -v

Verify the original research report:

    python verify_report.py

Run the detector directly with `python main.py`. It reads the synthetic authentication log, reports valid and skipped records, and prints any detected alerts. The experiment scripts run separate evaluations.

## Main Evaluation Results

The main evaluation uses nine manually designed synthetic scenarios.

| Metric | Baseline | Enhanced |
|---|---:|---:|
| True positives | 3 | 4 |
| False positives | 0 | 0 |
| True negatives | 4 | 4 |
| False negatives | 2 | 1 |
| Precision | 1.0000 | 1.0000 |
| Recall | 0.6000 | 0.8000 |
| F1 score | 0.7500 | 0.8889 |
| False-positive rate | 0.0000 | 0.0000 |

On this scenario set, the enhanced detector identifies one additional positive scenario and improves recall and F1 score without introducing an observed false positive.

These results describe only the selected synthetic scenarios. Four benign scenarios are insufficient to establish a reliable real-world false-positive rate.

## Experimental Generalisation Evaluation

The additional experimental rules were evaluated using six manually labelled synthetic scenarios: three suspicious and three benign.

| Metric | Original detector | Experimental detector | Combined detector |
|---|---:|---:|---:|
| True positives | 1 | 2 | 3 |
| False positives | 0 | 0 | 0 |
| True negatives | 3 | 3 | 3 |
| False negatives | 2 | 1 | 0 |
| Precision | 1.0000 | 1.0000 | 1.0000 |
| Recall | 0.3333 | 0.6667 | 1.0000 |
| F1 score | 0.5000 | 0.8000 | 1.0000 |
| False-positive rate | 0.0000 | 0.0000 | 0.0000 |

The combined detector uses the logical OR of the original and experimental detector outcomes.

The experimental rules identify two suspicious scenarios that the original detector misses. The combined detector identifies all three suspicious scenarios in this small test set.

These figures are derived from six synthetic scenarios with manually assigned expected labels. They do not demonstrate real-world accuracy, a reliable false-positive rate, or production effectiveness. The combined result is specific to this scenario set and requires validation using larger, independently labelled datasets.

## Threshold Sensitivity

The threshold experiment evaluates thresholds of three, four, five and six failures using a five-minute window.

- Thresholds of three and four produce more false positives in the tested scenarios.
- Threshold five provides the best balance in this particular dataset.
- Threshold six misses all five labelled suspicious scenarios in the experiment.

These results do not establish a universally optimal threshold. Different environments and attack patterns may require different settings.

## Extended Scenario Evaluation

The extended evaluation contains six additional synthetic scenarios:

- True positives: 1
- False positives: 0
- True negatives: 3
- False negatives: 2

The detector misses the scenarios involving six failures spread over a longer period and multiple IP addresses targeting multiple accounts. These misses demonstrate limitations in the current rules and scenario coverage.

## Project Outputs

The `results` directory contains experiment metrics, scenario results, threshold-sensitivity results and research reports.

- `results/experiment_report.md` - Original research experiment report.
- `results/experimental_detection_report.md` - Evaluation of the two additional experimental detection rules.
- `results/experimental_generalisation.csv` - Scenario-level results for the experimental generalisation evaluation.

The `tests` directory contains unit tests and scripts for running the experiments. The `data` directory contains the synthetic authentication log dataset.

## Limitations

- All authentication records and scenarios are synthetic; no production authentication logs were used.
- Expected scenario labels were assigned manually and were not independently validated.
- The experiments use small, deliberately designed datasets and do not establish real-world detection effectiveness.
- Experimental Rule 3 identifies a heuristic pattern of distributed multi-account failures. It cannot establish attacker intent or confirm password spraying.
- Rule 3 does not group events by application, service or tenant. Unrelated authentication activity could therefore contribute to the same detection window.
- Experimental Rule 4 requires failures to span at least 30 minutes, but this does not guarantee evenly spaced activity.
- The experimental rules stop after their first qualifying alert within a batch, so later independent patterns may not produce additional alerts.
- The combined detector uses a logical OR of the original and experimental outcomes; it is not an independently trained or validated detection model.
- The rules may miss attacks that fall outside their configured thresholds or time windows.
- Passing unit tests verifies specified behaviours, not real-world security effectiveness.
- No production deployment, operational performance measurement or independent real-world validation has been performed.

## Future Work

Potential improvements include testing on larger and more diverse datasets, evaluating additional benign and suspicious behaviours, measuring performance on independently labelled data, and investigating configurable thresholds and time windows.

## Research Integrity

This project is a simulated research prototype for learning and evaluation. Its results should not be interpreted as evidence of production security effectiveness.
