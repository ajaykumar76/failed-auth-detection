Expanded Synthetic Evaluation Report

1. Objective

This study investigates whether adding a multi-source-IP detection rule improves the identification of repeated failed-authentication patterns compared with a baseline rule that detects repeated failures from a single source IP.

**Research question:** To what extent does the enhanced detector improve precision, recall, and F1 score compared with the baseline detector on a manually designed synthetic dataset?

The baseline detects repeated failures from a single source IP address. The enhanced detector retains this rule and adds a rule for repeated failures against the same username from multiple source IP addresses.
2. Detection Rules
Baseline detector

Triggers when at least five failed authentication attempts from one source IP occur within a rolling five-minute window.

Enhanced detector

Includes the baseline IP-based rule.

Adds detection of at least five failed authentication attempts against the same username from at least two distinct source IP addresses within a rolling five-minute window.

The five-minute boundary is inclusive.

3. Evaluation Method

Nine manually designed synthetic scenarios were evaluated. The scenarios represent suspicious and benign authentication patterns, including rapid repeated failures, slower failures, distributed attempts against one account, successful logins, and activity at the detection-window boundary.

The baseline and enhanced detectors were evaluated against manually assigned expected outcomes. Both detectors were assessed using the same scenario set to enable a direct comparison. The expected outcomes were defined by the scenario design rather than independently labelled real-world data.

Results were classified as true positives (TP), false positives (FP), true negatives (TN), and false negatives (FN). Precision, recall, F1 score, and false-positive rate were calculated from these counts. Because the evaluation contains only nine synthetic scenarios, the metrics are descriptive of this test set and should not be interpreted as estimates of real-world performance.

4. Results

| Metric | Baseline | Enhanced |
|-|-:|-:|
|True positives (TP)|3|4|
|False positives (FP)|0|0|
|True negatives (TN)|4|4|
|False negatives (FN)|2|1|
|Precision|1.0000|1.0000|
|Recall|0.6000|0.8000|
|F1 score|0.7500|0.8889|
|False-positive rate|0.0000|0.0000|

5. Interpretation

On this nine-scenario synthetic evaluation, the enhanced detector identified one additional suspicious scenario: repeated failed authentication attempts against the same username from multiple source IP addresses.

Recall increased from 0.60 to 0.80, an absolute increase of 0.20 (20 percentage points). The F1 score increased from 0.75 to approximately 0.8889.

Both detectors recorded zero false positives in this dataset. However, only four scenarios were benign, so this result is insufficient to establish a reliably low false-positive rate in real environments.

The slow repeated-failure scenario was missed by both detectors because it did not satisfy the configured five-minute detection window.

6. Limitations

The evaluation contains only nine manually designed synthetic scenarios.

The expected outcomes were assigned manually rather than derived from independently labelled operational data.

The scenarios do not represent the full range of real authentication behaviour.

No claims can be made about production effectiveness, real-world generalisation, or operational false-positive rates.

The results depend on the chosen thresholds, window length, and scenario design.

7. Reproducibility

The experiments use manually designed synthetic authentication scenarios. Results are reproducible by running the scripts below from the project root directory, provided the source code and dependencies remain unchanged.

### Main generalisation evaluation

Script: `tests/test_generalisation.py`

Command:

    python tests/test_generalisation.py

Reported outputs:
- `results/generalisation_v2_scenarios.csv`
- `results/generalisation_v2_comparison.csv`
- `results/generalisation_v2_metrics.csv`

### Threshold sensitivity experiment

Script: `tests/test_threshold_sensitivity.py`

Command:

    python tests/test_threshold_sensitivity.py

Output: `results/threshold_sensitivity.csv`

The experiment evaluates thresholds of 3, 4, 5, and 6 failures while holding the rolling window at five minutes.

### Extended synthetic scenario evaluation

Script: `tests/test_extended_scenarios.py`

Command:

    python tests/test_extended_scenarios.py

Output: `results/extended_scenarios.csv`

8. Next Evaluation Steps

Expand the scenario set with additional benign and suspicious patterns.

Test threshold variations and different time windows.

Include repeated attempts spread across longer periods to examine the current detector's limitations.

Verify expected outcomes and metric calculations independently.

Document all changes and preserve the results from each experiment run for comparison.

9. Threshold Sensitivity Experiment

Objective

A follow-up experiment examined how changing the failed-authentication threshold affected baseline and enhanced detector performance. The rolling time window was held constant at five minutes, and the threshold was varied across 3, 4, 5, and 6 failures.

Results

| Threshold | Detector | TP | FP | TN | FN | Precision | Recall | F1 score | False-positive rate |
|-:|-|-:|-:|-:|-:|-:|-:|-:|-:|
|3|baseline|3|2|2|2|0.6|0.6|0.6|0.5|
|3|enhanced|4|3|1|1|0.5714|0.8|0.6667|0.75|
|4|baseline|3|2|2|2|0.6|0.6|0.6|0.5|
|4|enhanced|4|3|1|1|0.5714|0.8|0.6667|0.75|
|5|baseline|3|0|4|2|1.0|0.6|0.75|0.0|
|5|enhanced|4|0|4|1|1.0|0.8|0.8889|0.0|
|6|baseline|0|0|4|5|0|0.0|0|0.0|
|6|enhanced|0|0|4|5|0|0.0|0|0.0|

Discussion

On this synthetic dataset, thresholds of 3 and 4 produced more false positives than threshold 5 without improving recall. At threshold 6, neither detector identified any of the five labelled suspicious scenarios. Threshold 5 therefore provided the strongest observed F1 score for both detectors in this particular evaluation.

The enhanced detector identified one additional suspicious scenario at thresholds 3 to 5, but at thresholds 3 and 4 it also generated one additional false positive compared with the baseline.

Limitations

The evaluation contains only nine manually designed scenarios. The results are sensitive to the selected scenario patterns and manually assigned expected labels. Threshold 5 must not be presented as an optimal operational threshold for real authentication systems. A larger and more diverse dataset, independent validation of scenario labels, and additional testing would be needed to support broader conclusions.

The threshold sensitivity output is stored in results/threshold\_sensitivity.csv. The experiment script is tests/test\_threshold\_sensitivity.py.

Conclusion

The enhanced rule-based detector performed better than the baseline on the current manually designed synthetic dataset, primarily by detecting a distributed failed-authentication scenario that the baseline missed. Further testing with a larger, more diverse, and independently validated dataset is required before drawing broader conclusions.

10. Extended Synthetic Scenario Evaluation

Objective

A supplementary evaluation examined six additional synthetic authentication scenarios to investigate detection behaviour beyond the original nine scenarios.

Results

| Metric | Result |
|-|-:|
|Scenarios|6|
|True positives (TP)|1|
|False positives (FP)|0|
|True negatives (TN)|3|
|False negatives (FN)|2|

The detector identified the scenario involving five accounts targeted from one source IP. It did not alert on six failures spread over a longer period or on failures distributed across multiple IP addresses and multiple accounts.

The remaining three scenarios were correctly classified as benign (true negatives), consistent with their manually assigned labels.

Interpretation

These results illustrate the limitations of the two implemented rules. The detector focuses on repeated failures from one IP or repeated failures against one username from multiple IPs within a rolling five-minute window. It does not implement general detection for low-frequency attempts spread over longer periods or distributed activity involving multiple accounts.

The two false negatives should be interpreted in the context of the defined detection scope and the manually assigned scenario labels. They do not, by themselves, establish an implementation defect.

Limitations

The six scenarios were manually designed and labelled. Their results are supplementary and should not be treated as independent real-world validation. Because the scenarios were added after the initial evaluation, the results should be reported separately rather than merged into the original nine-scenario metrics without a documented evaluation protocol.

Reproducibility

Run the supplementary evaluation using:

python tests/test\_extended\_scenarios.py

The output is saved to results/extended\_scenarios.csv.

The unit tests were also executed using python -m unittest discover -s tests -v; all 17 tests passed in the reported run.
