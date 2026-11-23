# Day 15 — Output Response DLP Scanning

## 1. Objective

Day 15 introduces an output response scanner that checks final LLM responses for unexpected personally identifiable information (PII) and secrets.

The scanner acts as a detection backstop after the normal response unmasking process. It distinguishes values already associated with the current user's session from other detected sensitive values.

The implementation covers three areas:

1. Detecting PII and secrets in final LLM responses.
2. Excluding exact sensitive values already stored in the current session's vault mapping.
3. Integrating output scanning into `DLPInterceptor` as an explicit opt-in operation.

## 2. Implementation

### OutputScanner

Implemented `dlp/output_scanner.py` with the `OutputScanner` class.

The scanner:

- Uses the existing `DLPEngine` with `include_original_value=True`.
- Scans the supplied final response using existing entity recognizers.
- Retrieves the current session's mappings through `vault.get_mapping(session_id)`.
- Compares detected original values against the values stored in that session's vault.
- Excludes exact matches from the findings.
- Reports detected values that are not present in the session's vault mapping.

### Scan Result

The scanner returns a tuple:

```python
is_clean, findings
```

Each finding contains:

| Field | Description |
|---|---|
| `entity_type` | Detected PII or secret category |
| `value_sample` | A shortened sample of the detected value |
| `score` | Detection confidence score |

The complete sensitive value is not included in the finding.

## 3. Interceptor Integration

Integrated the scanner into `dlp/interceptor.py`.

Added:

```python
scan_output(final_response, session_id)
```

This method:

1. Validates the session ID.
2. Passes the final response to `OutputScanner`.
3. Returns the scanner's clean status and findings.

Output scanning is explicitly opt-in. It does not automatically run during `unmask()` and does not modify, redact, or block the response.

The intended workflow is:

1. Receive the LLM response.
2. Restore legitimate placeholders using the session vault.
3. Call `scan_output()` on the final response when output scanning is required.
4. Inspect the returned findings and apply any application-level handling policy.

## 4. Detection Behaviour

| Scenario | Expected behaviour |
|---|---|
| Known session email restored into the response | Not flagged |
| Unexpected email address | Flagged |
| Unexpected phone number | Flagged |
| Unexpected credit card number | Flagged |
| Unexpected AWS access key | Flagged |
| Multiple unexpected sensitive values | Each detected value is reported |
| Response containing no detected PII | Clean |
| Empty response | Clean |
| Sensitive value from another session | Not treated as a known value for the current session |

The scanner compares exact detected values against the current session's vault mapping.

## 5. Testing and Validation

Created `tests/test_day15_output_scanner.py`.

The test suite contains 14 tests covering:

- Known session values.
- Unexpected email addresses.
- Unexpected phone numbers.
- Unexpected credit card numbers.
- Unexpected AWS access keys.
- Multiple detected sensitive values.
- Empty vault behaviour.
- Responses without PII.
- Empty responses.
- Sensitive-value sample protection.
- Session isolation.
- Invalid response input.
- Invalid session input.
- Redaction, unmasking, and output-scanning integration.

### Day 15 Test Results

| Validation | Result |
|---|---|
| Day 15 automated tests | 14 passed |
| Python compilation | PASS |
| Interceptor initialization | PASS |
| Output scanner initialization | PASS |
| Redis health check | PASS |
| Known session value verification | PASS |
| Unexpected PII detection | PASS |

The manual verification confirmed that a known session email was excluded from findings, while an unexpected email address was detected.

## 6. Security Considerations and Limitations

The output scanner is a detection mechanism, not a complete data-leak prevention guarantee.

Important limitations:

- A detected value outside the current session's vault is not proof that the value originated from LLM training data. It may have come from another source.
- Matching is based on exact values. Modified, reformatted, or transformed versions may not match the vault entry.
- A coincidental reuse of a known value may be excluded because the scanner cannot establish the value's origin.
- Session expiry or removal of vault mappings can affect whether previously restored values are recognized.
- Detection depends on the existing recognizers and may produce false positives or false negatives.
- The scanner does not automatically block or modify a response. Applications must decide how to handle findings.

## 7. Generated Evidence

The Day 15 implementation and validation files are:

- `dlp/output_scanner.py` — output response scanning implementation.
- `dlp/interceptor.py` — explicit output-scanning integration.
- `tests/test_day15_output_scanner.py` — automated test suite.
- `docs/day15-output-scanning.md` — implementation and validation documentation.

## 8. Conclusion

Day 15 successfully introduces an opt-in output response scanner integrated with the existing DLP interceptor.

The scanner identifies sensitive values in final responses while excluding exact values already associated with the current session's vault mapping. Findings contain shortened value samples rather than complete sensitive values.

All 14 Day 15 automated tests passed, and manual verification confirmed both known-value exclusion and unexpected PII detection.

**Day 15 Implementation and Unit Test Result: PASS**

Full project regression testing and final repository review remain separate validation steps.
