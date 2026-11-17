# Day 10 — Complex Text & Edge Case Findings

## Objective

Validate DLP detection and masking against complex text formats, including Markdown, multiline JSON, escaped strings, international phone numbers, and secret-token boundaries.

## Test Results

Command:

`python -m pytest tests/test_day10_edge_cases.py -v`

Result: **17 passed, 0 failed**

One third-party spaCy/Click deprecation warning was reported.

## Scenarios Tested

| Scenario | Result |
|---|---|
| AWS access key inside Markdown code block | PASS |
| Email inside inline Markdown code | PASS |
| Email and credit card inside multiline JSON | PASS |
| AWS secret key inside JSON | PASS |
| JWT inside JSON with trailing content | PASS |
| Email inside escaped quoted string | PASS |
| Email inside string containing escaped newline | PASS |
| International phone number formats (5 formats) | PASS |
| Combined Markdown, JSON, PII and secret prompt | PASS |
| AWS secret key beginning or ending with `/` or `+` | PASS |

## Observations

1. Sensitive values were masked without removing surrounding Markdown syntax.
2. JSON quotation marks and surrounding structure were preserved in the tested cases.
3. Escaped quote and newline sequences remained intact.
4. All five tested international phone formats were detected.
5. AWS access keys, AWS secret keys and JWTs were replaced with semantic placeholders.
6. The JWT test confirmed that trailing JSON content was not swallowed by the replacement.
7. AWS secret keys with `/` and `+` at token boundaries were correctly detected after the regex correction.

## Known Limitation

The seven-digit phone number `555-0147` remains unmasked in the mixed-prompt test.

This is a previously known limitation from Day 2. It remains outside the successful detection scope of the current tests and requires separate investigation.

## Implementation Changes

Fixed an AWS secret-key regex boundary defect in
`dlp/custom_recognizers.py`.

### Problem

The original regex used `\b` boundaries:

`\\b[A-Za-z0-9/+=]{40}\\b`

Python word boundaries do not correctly handle all permitted AWS secret characters, particularly `/` and `+`, at the beginning or end of a token.

### Correction

Replaced the word boundaries with negative lookbehind and lookahead:

`(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])`

### Verification

Four synthetic boundary cases were added:

- Secret beginning with `/`
- Secret ending with `/`
- Secret beginning with `+`
- Secret ending with `+`

All four boundary tests pass.

## Full Regression Validation

Command:

`python -m pytest`

Result: **174 passed, 10 skipped, 0 failed**

Redis was running and responding successfully during this validation.

## Conclusion

The Day 10 suite passed all 17 tests.

The AWS secret-key boundary defect was identified, corrected,
and verified. Markdown, JSON, escaped strings, international
phone numbers, JWTs, and AWS secrets passed their tested scenarios.

The seven-digit phone number `555-0147` remains a known limitation.
