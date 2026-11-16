# Day 8 — NER Latency Profiling and Regex Pre-filter

## 1. Objective

The objective of Day 8 was to reduce unnecessary Presidio NER analysis
for prompts that do not contain indicators of PII or secrets.

A lightweight regex pre-filter was introduced before the Presidio
analysis stage in `DLPEngine.redact()`.

## 2. Implementation

Created:

- `dlp/pre_filter.py`

Modified:

- `dlp/dlp_engine.py`

The function `might_contain_pii(text)` checks for:

- Numeric characters
- Email-style `@` indicators
- AWS access key prefixes (`AKIA`, `ASIA`)
- JWT prefixes (`eyJ`)
- Key-related symbols (`+`, `/`, `=`)
- AWS or secret-related context words, which allow contextual AWS secret candidates to reach the recognizer

When no indicators are found, the engine skips Presidio analysis.
When an indicator is found, the existing Presidio detection pipeline
runs with all eight supported entity types.

## 3. Baseline latency

The following measurements were recorded before pre-filter integration.

| Scenario | Input size | Mean latency | Median latency |
|---|---:|---:|---:|
| Short clean | 50 characters | 6.018 ms | 5.910 ms |
| Short with PII | 50 characters | 9.501 ms | 9.585 ms |

Only the short baseline measurements are available in the recorded
baseline output. No medium or large baseline values are claimed here.

## 4. Optimized latency

Measurements recorded after pre-filter integration:

| Scenario | Input size | Mean latency | Median latency |
|---|---:|---:|---:|
| Short clean | 50 characters | 0.010 ms | 0.008 ms |
| Short with PII | 50 characters | 6.153 ms | 5.646 ms |
| Medium clean | 500 characters | 0.050 ms | 0.048 ms |
| Medium with PII | 500 characters | 9.236 ms | 9.827 ms |
| Large clean | 5,000 characters | 0.964 ms | 0.960 ms |
| Large with PII | 5,000 characters | 14.515 ms | 14.304 ms |

The profiling script used 20 runs per scenario.

Benchmark input design:
- Clean inputs use repeated "A" characters.
- PII-bearing inputs contain an email address.
- These controlled samples are useful for comparing the pre-filter
  overhead, but do not represent all real-world prompt patterns.

## 5. Observations

- Clean prompts avoid the Presidio analysis call.
- Short clean-text mean latency decreased from 6.018 ms to 0.010 ms
  in the recorded measurements (approximately 99.83% lower).
- Short PII-text mean latency decreased from 9.501 ms to 6.153 ms
  in the recorded measurements (approximately 35.24% lower).
- PII-bearing prompts still use the full detection pipeline.
- Larger PII-bearing prompts can exceed 12 ms. The 12 ms target is
  therefore not claimed for every input size.

These are machine-specific measurements, not universal performance
guarantees. Benchmark timings can vary with system load and environment.

## 6. AWS secret edge case

The AWS secret recognizer requires nearby context containing both
`aws` and `secret`.

A 40-character secret consisting entirely of letters may contain no
digits or key-related symbols. The pre-filter therefore also checks
AWS/secret-related context words.

For example:

`aws secret AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`

This allows contextual AWS secret candidates to reach Presidio.

A secret-like string without the required AWS and secret context is
not guaranteed to be detected by this recognizer. This is a known
limitation of the recognizer's contextual detection design.

## 7. Validation

Dedicated Day 8 tests:

`python -m pytest -v tests/test_day8_prefilter_and_latency.py`

Result:

`21 passed`

Full regression suite:

`python -m pytest -v`

Result:

`126 passed, 10 skipped, 0 failed`

Additional validation:

- `git diff --check` — passed
- `python -m compileall -q dlp scripts tests` — passed
- Expected five Day 8 files identified by `git status`

The skipped tests and spaCy/Click deprecation warning are recorded
separately from test failures.

That regression result was recorded before adding the dedicated Day 8 test file.

## 8. Conclusion

The regex pre-filter reduces unnecessary Presidio work for clean
prompts while allowing known PII and secret indicators to reach the
existing detection pipeline.

The Day 8 implementation passed dedicated tests, full regression
testing, Python compilation, and whitespace validation. Final review
is complete.
