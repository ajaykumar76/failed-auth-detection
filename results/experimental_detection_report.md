Experimental Evaluation of Additional Failed Authentication Detection Rules



1\. Objective



This experiment evaluates two additional rule-based detection heuristics designed to identify failed-authentication patterns that were not detected by the original prototype in selected synthetic scenarios.



The experimental rules are implemented separately in experimental_detector.py. The original detector in main.py remains unchanged.



The evaluation compares three configurations:



Original detector.



Experimental detector.



Combined detector, where an event scenario is considered detected if either detector generates an alert.



The purpose is to investigate whether the additional rules improve detection coverage within the defined synthetic scenarios.



2\. Experimental Detection Rules



2.1 Rule 3: Distributed Multi-Account Failures



This rule identifies a pattern of failed authentication attempts involving multiple source IP addresses and multiple usernames within a short time window.



Parameter



Value



Minimum failures



5



Time window



5 minutes



Minimum distinct IP addresses



2



Minimum distinct usernames



5



The rule generates an alert when all four conditions are satisfied.



This is a heuristic for distributed multi-account failure activity. It does not establish that password spraying occurred because the prototype does not analyse attempted passwords or establish attacker intent.



2.2 Rule 4: Long-Window Repeated Failures



This rule identifies repeated failures against the same username from the same source IP over a longer period.



Parameter



Value



Minimum failures



5



Time window



60 minutes



Minimum time between first and last failure



30 minutes



The rule generates an alert when at least five failures occur for the same username and source IP within the rolling 60-minute window, with the first and last failures separated by at least 30 minutes.



The minimum-span condition does not require evenly spaced attempts. Consequently, this rule should be interpreted as a long-window repeated-failure heuristic rather than proof of low-and-slow attack behaviour.



3\. Evaluation Methodology



The evaluation uses six synthetic scenarios defined in tests/test_extended_scenarios.py.



Each scenario contains authentication events with:



Timestamp.



Username.



Source IP address.



Authentication status.



The events use UTC-aware timestamps and are generated from a fixed starting timestamp.



The evaluation script, tests/test_experimental_generalisation.py, executes the original and experimental detectors against the same scenarios.



The combined detector is evaluated using a logical OR condition: a scenario is considered detected if either the original or experimental detector produces an alert.



Each result is classified as:



True Positive (TP): suspicious scenario correctly detected.



False Positive (FP): benign scenario incorrectly detected.



True Negative (TN): benign scenario correctly left undetected.



False Negative (FN): suspicious scenario not detected.



The script records scenario-level outcomes and writes them to results/experimental_generalisation.csv.



The original detector's threshold and time-window settings are temporarily set to five failures and five minutes during evaluation. The original values are restored in a finally block.



4\. Synthetic Scenario Design



Scenario



Expected classification



Test objective



Six failures over a long period



Suspicious



Evaluate repeated failures over an extended period



One IP targets five accounts



Suspicious



Evaluate multiple-account failures from one IP



Multiple IPs target multiple accounts



Suspicious



Evaluate distributed failures across accounts



Four failures followed by success



Benign



Evaluate behaviour below the original threshold



Fifth failure outside the window



Benign



Evaluate failures outside the five-minute window



Successful logins by multiple users



Benign



Ensure successful authentication alone does not trigger alerts



These scenarios are controlled synthetic examples. They do not represent a statistically representative sample of real authentication activity.



5\. Experimental Results



5.1 Confusion Matrix Counts



Detector



TP



FP



TN



FN



Original detector



1



0



3



2



Experimental detector



2



0



3



1



Combined detector



3



0



3



0



5.2 Scenario-Level Comparison



Scenario



Original



Experimental



Combined



Six failures over a long period



FN



TP



TP



One IP targets five accounts



TP



FN



TP



Multiple IPs target multiple accounts



FN



TP



TP



Four failures then success



TN



TN



TN



Fifth failure outside window



TN



TN



TN



Successful logins by multiple users



TN



TN



TN



5.3 Derived Performance Measures



The following measures are calculated from the confusion-matrix counts:



Precision = TP / (TP + FP)



Recall = TP / (TP + FN)



F1-score = 2 × (Precision × Recall) / (Precision + Recall)



False-positive rate = FP / (FP + TN)



Detector



Precision



Recall



F1-score



False-positive rate



Original detector



1.000



0.333



0.500



0.000



Experimental detector



1.000



0.667



0.800



0.000



Combined detector



1.000



1.000



1.000



0.000



These are descriptive results for the six scenarios only. They must not be interpreted as estimates of performance in real networks.



6\. Results Analysis



The original detector correctly identifies one of the three suspicious scenarios. It misses the long-period repeated-failure scenario and the distributed multi-account scenario.



The experimental detector identifies both of these missed patterns:



Rule 4 detects the long-period repeated-failure scenario.



Rule 3 detects the distributed multi-account scenario.



However, the experimental detector does not detect the scenario in which one IP targets five accounts. The original detector identifies this pattern, demonstrating that the experimental rules do not replace the original detection rules.



The combined detector identifies all three suspicious scenarios and correctly leaves all three benign scenarios undetected in this test set.



The results indicate improved detection coverage within the defined synthetic scenarios when the experimental rules are used alongside the original detector.



7\. Limitations and Threats to Validity



Several limitations affect the interpretation of these results.



Small scenario set: Only six synthetic scenarios were evaluated. This is insufficient to establish reliable real-world performance.



Synthetic data: The scenarios are manually constructed and do not reproduce the full complexity of operational authentication logs.



Expected labels: Suspicious and benign labels are assigned by the scenario definitions. They are not independently validated against real incident records.



Limited attack diversity: The scenarios do not cover all possible authentication attacks, evasion techniques, distributed environments or legitimate operational anomalies.



Rule 3 attribution: Multiple IP addresses and usernames within a short period do not necessarily indicate malicious activity. The rule does not inspect attempted passwords, application context or user intent.



Rule 4 timing limitation: The minimum-span condition checks the interval between the first and last failures. It does not enforce evenly distributed attempts.



Missing contextual information: The event schema does not include application, tenant, device, geographic or session context. This may cause unrelated authentication activity to be grouped together.



No operational performance evaluation: Processing latency, throughput, memory consumption and performance on large log datasets have not been established by this experiment.



No statistical confidence assessment: The small number of scenarios does not support meaningful claims about generalisation or statistical reliability.



8\. Reproducibility



The experiment can be reproduced from the project directory using:



python tests/test_experimental_generalisation.py



The script generates:



results/experimental_generalisation.csv



The experimental unit tests can be executed using:



python -m unittest discover -s tests -p "test_experimental_detector.py" -v



The complete test suite can be executed using:



python -m unittest discover -s tests -v



The recorded full test-suite result was 29 passing tests.



9\. Conclusion



The experiment investigated two additional rule-based heuristics for failed-authentication detection.



Within the six manually constructed synthetic scenarios, the experimental rules detected two suspicious patterns missed by the original detector. The combined detector correctly classified all six scenarios.



These results provide preliminary evidence that additional detection heuristics can improve coverage of selected authentication-failure patterns.



However, the limited synthetic evaluation does not establish real-world detection accuracy, operational effectiveness or generalisation to production environments.



Further evaluation using larger and more diverse datasets, independently validated labels, additional benign scenarios and operational performance measurements is necessary before making broader claims about the prototype's effectiveness.
