# Synthetic Authentication Failure Detection

## Overview

This project implements and evaluates a rule-based detector for repeated authentication failures using synthetic log data. It compares a baseline detection rule with an enhanced rule designed to identify failures distributed across multiple source IP addresses.

This is an academic research prototype. It has not been validated against production authentication logs.

## Detection Rules

### Rule 1: Repeated failures from one IP

Generate an alert when at least five failed authentication attempts from the same source IP occur within an inclusive rolling five-minute window.

### Rule 2: Failures against one username from multiple IPs

Generate an alert when at least five failed attempts against the same username occur within an inclusive rolling five-minute window and involve at least two distinct source IP addresses.

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

Run the unit tests:

    python -m unittest discover -s tests -v

Run the generalisation experiment:

    python tests/test_generalisation.py

Run the threshold-sensitivity experiment:

    python tests/test_threshold_sensitivity.py

Run the extended-scenario experiment:

    python tests/test_extended_scenarios.py

Verify the research report:

    python verify_report.py

The `main.py` file currently defines the parsing and detection functions but does not provide a standalone command-line entry point. Use the experiment scripts above to run the evaluations.

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

The `results` directory contains experiment metrics, scenario results, threshold-sensitivity results and the research report.

The report is located at `results/experiment_report.md`.

The `tests` directory contains unit tests and scripts for running the experiments. The `data` directory contains the synthetic authentication log dataset.

## Limitations

- All authentication records and scenarios are synthetic.
- Expected scenario labels were assigned manually.
- The experiments use a small, deliberately designed dataset.
- Passing unit tests verifies specified behaviours, not real-world detection effectiveness.
- The rules may miss attacks that fall outside the configured threshold or time window.
- False-positive and false-negative rates may differ substantially in real environments.
- No production deployment or independent real-world validation has been performed.

## Future Work

Potential improvements include testing on larger and more diverse datasets, evaluating additional benign and suspicious behaviours, measuring performance on independently labelled data, and investigating configurable thresholds and time windows.

## Research Integrity

This project is a simulated research prototype for learning and evaluation. Its results should not be interpreted as evidence of production security effectiveness.
