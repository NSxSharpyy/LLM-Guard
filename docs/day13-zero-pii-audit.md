# Day 13 — Zero-PII Upstream Verification Audit

## Objective

Verify that sensitive values detected and masked by the DLP pipeline
do not reach the upstream mock LLM in their original form.

The audit sends deterministic synthetic PII payloads through the
existing Day 7 mock proxy and inspects the actual prompts received by
the mock LLM.

This is an integration test of upstream leakage prevention. It is not
a claim that the entire application has zero-PII storage.

## Scope

The audit covers nine entity types:

- EMAIL_ADDRESS
- PHONE_NUMBER
- CREDIT_CARD
- US_SSN
- AADHAAR_CARD
- PAN_CARD
- AWS_ACCESS_KEY
- AWS_SECRET_KEY
- JWT_TOKEN

A total of 500 synthetic payloads were generated.

| Entity type | Payload count |
|---|---:|
| EMAIL_ADDRESS | 56 |
| PHONE_NUMBER | 56 |
| CREDIT_CARD | 56 |
| US_SSN | 56 |
| AADHAAR_CARD | 56 |
| PAN_CARD | 55 |
| AWS_ACCESS_KEY | 55 |
| AWS_SECRET_KEY | 55 |
| JWT_TOKEN | 55 |
| **Total** | **500** |

The payloads are generated for local testing and must not be treated
as real user records or production credentials.

## Methodology

1. Generate 500 deterministic synthetic payloads.
2. Validate that each expected entity is detected by the DLP engine.
3. Send every payload through the mock proxy.
4. Capture the exact prompts appended to the mock LLM received-request
   log.
5. Correlate requests and upstream records using unique audit markers.
6. Compare upstream prompts against the raw synthetic values.
7. Record missing, duplicate, unexpected, malformed, and failed
   requests.
8. Execute a negative test that deliberately sends a raw synthetic
   value directly to the mock LLM, bypassing the masking proxy.
9. Confirm that the audit detects this intentionally exposed value.

## Results

| Metric | Result |
|---|---:|
| Expected payloads | 500 |
| Successful proxy requests | 500 |
| New upstream records | 500 |
| Matched upstream records | 500 |
| Missing records | 0 |
| Duplicate records | 0 |
| Unexpected records | 0 |
| Raw PII leaks in positive audit | 0 |
| Request failures | 0 |
| Entity mismatches | 0 |
| Malformed log records | 0 |

### Positive audit

**PASS**

All 500 requests were successfully processed. Every request was
matched to an upstream record, and no tested raw PII value was found
in the captured upstream prompts.

### Negative leak-detection test

**PASS**

A raw synthetic email value was deliberately sent directly to the
mock LLM, bypassing the DLP proxy. The audit found the corresponding
log record and detected the exposed value.

This demonstrates that the audit's leak-detection mechanism can
identify an intentionally introduced upstream leak.

## Evidence

Machine-readable report:

`logs/zero_pii_audit_report.json`

Synthetic input dataset:

`data/pii_audit_payloads.json`

Audit implementation:

- `scripts/generate_pii_payloads.py`
- `scripts/zero_pii_audit.py`
- `tests/test_day13_audit.py`

The report records counts, audit outcomes, and a SHA-256 hash for the
negative-test value. It does not need to contain the raw test values.

## Validation

- Day 13 audit unit tests: 9 passed.
- Focused regression tests: 129 passed.
- Full project test suite: 258 passed, 10 skipped.
- Python compilation check: passed.
- `git diff --check`: passed.
- Live upstream audit: passed.

A third-party spaCy/Click deprecation warning was observed during
pytest. It did not cause test failures.

## Limitations

- The audit uses a local mock proxy and mock LLM, not a production
  external LLM provider.
- The dataset is synthetic and finite; the result does not prove
  detection of every possible PII format or encoding.
- The audit verifies upstream prompt contents, not every possible
  application log, memory area, database, or storage location.
- Original sensitive values remain in Redis mapping values in
  plaintext in the current implementation. HMAC-protected lookup
  identifiers do not encrypt those values.

Therefore, the result supports the claim that the tested pipeline
prevented raw PII from reaching the mock LLM during this audit. It
does not establish complete zero-PII storage or production-wide
security.

## Conclusion

The Day 13 zero-PII upstream verification audit passed all 500
positive test cases, detected the intentionally introduced negative
test leak, and reported zero raw PII leaks in the positive audit.

**Day 13 upstream leakage verification: PASS.**
