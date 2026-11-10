# LLM-Guard DLP — Day 2: Baseline PII Redaction

## 1. Objective

Implement a baseline PII detection and redaction engine using
Microsoft Presidio Analyzer and Presidio Anonymizer.

The engine detects supported sensitive entities and replaces
them with static placeholder tags.

## 2. Implementation

File: `dlp/dlp_engine.py`

The implementation contains:

- DLPEngine class
- Presidio AnalyzerEngine initialization
- Presidio AnonymizerEngine initialization
- Entity-specific replacement operators
- Detection metadata collection
- Empty-input handling

## 3. Supported Entities

| Entity | Description | Status |
|---|---|---|
| EMAIL_ADDRESS | Email addresses | Implemented and tested |
| PHONE_NUMBER | Telephone numbers | Implemented and tested |

PERSON is available through the installed Presidio analyzer
but is intentionally excluded from the Day 2 redaction scope.

## 4. Redaction Strategy

The engine uses Presidio to identify sensitive information.

Detected entities are passed to the anonymizer.

Static replacement tags are used:

- EMAIL_ADDRESS -> `<REDACTED_EMAIL_ADDRESS>`
- PHONE_NUMBER -> `<REDACTED_PHONE_NUMBER>`

The engine also returns detection metadata containing:

- Entity type
- Start position
- End position
- Confidence score
- Original detected value

## 5. Phone Number Validation

The following formats were tested:

| Input | Detection | Confidence |
|---|---|---|
| 212-555-0147 | Yes | 0.4 |
| 415-555-0199 | Yes | 0.4 |
| +1 212-555-0147 | Yes | 0.4 |
| +91 9876543210 | Yes | 0.4 |
| 9876543210 | Yes | 0.4 |
| 555-0147 | No | Not applicable |

All five recognized examples were successfully redacted.

The seven-digit example was not detected by the current
Presidio recognizer configuration.

Confidence scores are recorded for analysis. No additional
confidence threshold is applied by DLPEngine.

## 6. Combined PII Validation

Test input:

"My name is John Smith. Email john@example.com.
Call +91 9876543210."

Expected Day 2 behavior:

- Email address detected and redacted.
- Phone number detected and redacted.
- Person name preserved because PERSON is outside Day 2 scope.

## 7. Unit Tests

Test file: `tests/test_day2_redaction.py`

Fourteen Day 2 tests cover:

1. Email detection and redaction.
2. Phone detection and redaction.
3. Multiple PII redaction.
4. Empty input.
5. Ordinary text preservation.
6. Seven-digit number behavior.
7. PERSON exclusion from Day 2.
8. Entity metadata validation.
9. Original input preservation.
10. Multiple common email formats.
11. Invoice numbers and prices are not redacted.
12. Exact preservation of surrounding text.
13. Input containing only PII.
14. Idempotent redaction of already-masked text.

### Day 2 test result

Command: `python -m pytest -v tests/test_day2_redaction.py`

Result: **14 passed, 0 failed.**

One non-blocking spaCy deprecation warning was reported.

## 8. Manual Batch Validation

Four synthetic inputs were tested:

| Input scenario | Expected entities | Result |
|---|---:|---|
| Email only | 1 | PASS |
| Phone only | 1 | PASS |
| Ordinary text | 0 | PASS |
| Email and phone together | 2 | PASS |

All four examples produced the expected masked text and entity counts.

## 9. Known Limitations

- Seven-digit local phone numbers such as `555-0147`
  are not detected in the tested configuration.
- Standard ten-digit and international phone examples
  were detected and redacted.
- PERSON detection is outside the Day 2 redaction scope.
- Phone detection confidence was 0.4 for the tested examples.
- Obfuscated email and phone formats are not covered by
  the current baseline.
- Custom sensitive entities are planned for Day 3 and later.

## 10. Full Regression Results

Command:

`python -m pytest -v`

| Test suite | Passed | Failed |
|---|---:|---:|
| Day 1 | 7 | 0 |
| Day 2 | 14 | 0 |
| Total | 21 | 0 |

Execution time: 6.95 seconds.

One non-blocking spaCy deprecation warning was reported.

## 11. Conclusion

The baseline PII redaction engine is implemented.

Email and phone-number detection and redaction have been
validated through individual tests, combined-input tests,
additional precision tests, and a four-case synthetic
manual batch.

All 14 Day 2 tests and all 7 Day 1 regression tests passed.
The complete project regression suite passed with 21 tests
and zero failures.

The seven-digit phone-number detection limitation is
documented for future hardening.
