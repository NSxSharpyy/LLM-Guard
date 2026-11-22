# Day 14 — Attack Batch Dashboard Acceptance Report

**Evaluation date:** 22 November 2026
**Owner:** Member 6 — DevOps, SIEM Logging and SOC Dashboard

## 1. Objective

Display real-time security metrics from a controlled 1,000-attack batch evaluation through the SOC dashboard.

## 2. Implementation

- Integrated the updated LLM-Guard proxy prompt-injection guard.
- Created an isolated synthetic evaluation runner.
- Generated 1,000 attack prompts across four prompt-guard categories.
- Generated 100 benign control prompts.
- Added a separate batch-progress JSON reader.
- Integrated batch progress into the Streamlit dashboard.
- Preserved the frozen nine-field SIEM event schema.
- Kept batch results separate from ordinary SOC telemetry.

## 3. Synthetic evaluation results

| Metric | Result |
|---|---:|
| Attack requests | 1,000 |
| Attack requests blocked | 1,000 |
| Correct prompt-guard rule matches | 1,000 |
| Missed attacks | 0 |
| Wrong-rule blocks | 0 |
| Benign controls | 100 |
| Benign false positives | 0 |
| Request errors | 0 |
| Attack detection rate | 100% |
| Correct rule-match rate | 100% |
| Benign false-positive rate | 0% |
| Average HTTP response latency | 2.289 ms |
| P95 HTTP response latency | 3.773 ms |
| Throughput | 46.02 requests/second |

## 4. Category results

| Category | Tested | Correctly blocked |
|---|---:|---:|
| PI-001 Instruction Override | 250 | 250 |
| PI-002 Jailbreak Persona | 250 | 250 |
| PI-003 System Prompt Leak | 250 | 250 |
| PI-004 Delimiter Injection | 250 | 250 |

## 5. SIEM correlation

| Validation | Result |
|---|---:|
| Evaluation records | 1,100 |
| SIEM events | 1,100 |
| Matched unique trace IDs | 1,100 |
| Missing trace IDs | 0 |
| Duplicate trace IDs | 0 |
| Schema errors | 0 |
| Action/rule mismatches | 0 |
| Extra unmatched events | 0 |

SIEM actions: 1,000 BLOCK and 100 ALLOW.

## 6. Dashboard

The Day 14 panel displays:

- Batch identity, source and execution status
- Completion progress
- Attack detection and correct rule-match rates
- Benign false-positive rate
- Evaluation errors
- Throughput and HTTP response latency
- Category-level results

The panel reads a separate progress file and refreshes within the existing two-second Streamlit fragment.

## 7. Limitations

This evaluation used a synthetic corpus generated from variations of the four existing prompt-guard regex categories. The prompts are not independent real-world attack samples.

The M5 Red Team Simulator branch inspected during integration contained only a README and LICENSE. Therefore, this report does not claim that M5's actual payload dataset was tested.

The measured HTTP latency is end-to-end client-observed request latency. It should not be interpreted as isolated firewall-engine latency.

## 8. Acceptance status

**Synthetic Day 14 evaluation: PASS**

**Dashboard integration: PASS**

**SIEM trace correlation: PASS**

**M5 real payload integration: PENDING**

The synthetic evaluation must remain clearly labelled as synthetic until the actual M5 simulator and payload corpus are supplied and validated.
