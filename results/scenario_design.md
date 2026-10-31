&#x20;Synthetic Authentication Detection — Scenario Design



&#x20;Purpose



This document defines the nine synthetic scenarios used to compare a baseline failed-authentication detector with an enhanced detector. Expected labels are specified independently of detector outputs.



Detection configuration



\- Failure threshold: 5 events

\- Rolling time window: 5 minutes

\- Baseline rule: repeated failures from a single source IP

\- Enhanced rules: repeated failures from a single source IP and repeated failures against one username from multiple source IPs

\- Data source: manually constructed synthetic authentication events

\- Real authentication logs: not used



Scenario definitions



| ID | Scenario | Expected label | Rationale |

|---|---|---|---|

| S01 | Rapid repeated failures | Suspicious | Five failures from one IP occur within five minutes. |

| S02 | Slow repeated failures | Suspicious | Repeated failures occur over a longer period; tests a known limitation of the five-minute window. |

| S03 | Distributed failures against one account | Suspicious | Five source IPs attempt to authenticate as the same username within five minutes. |

| S04 | One IP targeting multiple accounts | Suspicious | Five usernames receive failed attempts from one IP within five minutes. |

| S05 | Failures at the window boundary | Suspicious | Five failures occur at minutes 0, 1, 2, 3, and 5, testing inclusive window-boundary behavior. |

| S06 | Four failures | Benign for this test | Fewer than five failures occur from one IP within the window. This is a test assumption, not proof that the activity is harmless. |

| S07 | Successful logins only | Benign for this test | No failed authentication events occur. |

| S08 | Failures split between two IPs | Benign for this test | Four failures are distributed across two IPs, with no username receiving five failures. |

| S09 | Failures mixed with successful logins | Benign for this test | Four failures and two successful events occur; the configured threshold is not reached. |



Evaluation method



For each scenario, the expected label is compared with the detector's binary output.



\- True positive (TP): suspicious scenario detected.

\- False positive (FP): scenario labelled benign is detected.

\- True negative (TN): scenario labelled benign is not detected.

\- False negative (FN): suspicious scenario is not detected.



Precision, recall, F1 score, and false-positive rate are calculated from these counts.



Limitations



1\. The scenario set is small and manually designed.

2\. Expected labels are researcher-defined test assumptions, not independently validated incident labels.

3\. The scenarios do not represent the full diversity of production authentication traffic.

4\. A zero false-positive count on these scenarios does not establish a zero real-world false-positive rate.

5\. Results support a comparison on this specific synthetic test set only; they do not establish production readiness.



Reproducibility



The scenario-generation and evaluation logic is implemented in `tests/test\_generalisation.py`. The corresponding scenario-level outcomes and metric summaries are saved under `results/`.



