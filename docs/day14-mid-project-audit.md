
# Day 14 — Mid-Project Audit

## 1. Objective

Day 14 evaluates the performance and security effectiveness of the DLP engine at the midpoint of the project.

The audit covers three areas:

1. PII masking latency using `DLPEngine.redact()`.
2. Streaming unmasking overhead using `StreamUnmasker.feed()`.
3. Zero-PII upstream verification using the Day 13 audit framework.

## 2. Masking Performance

### Methodology

- Used 10 realistic prompts: 6 containing validated PII entity types and 4 clean prompts.
- Warmed up the engine once for each prompt.
- Executed 10 measurement cycles.
- Collected 100 timed calls to `DLPEngine.redact()`.
- Used `time.perf_counter()` for latency measurement.

### Results

| Metric | Result |
|---|---:|
| Total measured calls | 100 |
| Mean latency | 5.52 ms |
| p95 latency | 10.50 ms |
| Maximum latency | 19.80 ms |
| Minimum latency | 0.015 ms |
| Mean latency threshold | 15 ms |
| Result | PASS |

The measured mean latency of 5.52 ms is below the 15 ms threshold.

The maximum latency was 19.80 ms. This is an observed individual outlier; the acceptance criterion is based on mean latency.

## 3. Streaming Unmasking Performance

### Methodology

- Used the existing Redis-backed `StreamUnmasker`.
- Stored test placeholder mappings in Redis DB 15.
- Split a response into five-character chunks to exercise placeholder boundaries.
- Executed 20 streaming passes.
- Measured every `StreamUnmasker.feed()` call.
- Verified that the reconstructed response exactly matched the expected unmasked response.
- Removed the temporary Redis session after measurement.

### Results

| Metric | Result |
|---|---:|
| Streaming passes | 20 |
| Chunks per pass | 22 |
| Total feed calls | 440 |
| Chunk size | 5 characters |
| Mean feed latency | 1.20 ms |
| p95 feed latency | 1.87 ms |
| Maximum feed latency | 14.26 ms |
| Mean latency threshold | 5 ms |
| Output reconstruction | PASS |
| Result | PASS |

The measured mean feed latency of 1.20 ms is below the 5 ms threshold.

The reconstructed response matched the expected output across all 20 passes.

The maximum individual feed latency was 14.26 ms. The acceptance criterion is based on mean feed latency.

## 4. Zero-PII Upstream Verification

### Methodology

A fresh Day 13 audit was executed using the existing mock proxy and mock LLM services.

The audit processed 500 synthetic PII payloads and examined the upstream records for raw sensitive values.

The audit also executed a negative control by intentionally sending a raw email address directly to the mock LLM. The detector successfully identified this intentional leak.

### Results

| Metric | Result |
|---|---:|
| Expected payloads | 500 |
| Successful proxy requests | 500 |
| Matched upstream records | 500 |
| Raw PII leaks | 0 |
| Missing records | 0 |
| Duplicate records | 0 |
| Unexpected records | 0 |
| Request failures | 0 |
| Entity mismatches | 0 |
| Log errors | 0 |
| Raw PII leak rate | 0.00% |
| Negative leak-detection test | PASS |
| Overall zero-PII audit | PASS |

The positive audit confirmed zero raw PII leaks across all 500 payloads.

The negative control successfully detected an intentionally introduced email leak, confirming that the audit mechanism can identify an actual leak.

## 5. Acceptance Criteria

| Requirement | Threshold | Measured | Status |
|---|---:|---:|---|
| Masking mean latency | Below 15 ms | 5.52 ms | PASS |
| Streaming mean latency | Below 5 ms | 1.20 ms | PASS |
| Raw PII leakage | Zero | Zero | PASS |

## 6. Generated Evidence

The audit generated the following files:

- `scripts/mid_project_audit.py` — Day 14 measurement and verification script.
- `logs/mid_project_audit_report.json` — consolidated Day 14 results.
- `logs/day14_zero_pii_audit_report.json` — fresh underlying zero-PII audit report.

The consolidated report records the benchmark measurements, thresholds, validation checks, and overall result.

## 7. Conclusion

The Day 14 mid-project audit passed all three acceptance criteria.

The DLP engine achieved a mean masking latency of 5.52 ms, while streaming unmasking achieved a mean feed latency of 1.20 ms.

The fresh upstream audit processed 500 payloads with zero raw PII leaks. The negative control also successfully detected an intentionally introduced leak.

**Overall Day 14 Result: PASS**

These measurements establish the current performance and security baseline for the next phase of the project.
