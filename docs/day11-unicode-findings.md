# Day 11: Unicode & International Character Findings

## Objective
Verify UTF-8 and Unicode safety across accented Latin characters, emoji, ZWJ sequences, CJK, Arabic, Hindi, and Marathi text.

## Testing Results

- Accented Latin: PASS
- Japanese/CJK: PASS
- Arabic RTL: PASS
- Emoji and ZWJ sequences: PASS
- Hindi: PASS
- Marathi: PASS
- Embedded email masking: PASS
- Embedded phone masking: PASS
- Unicode span preservation: PASS
- Placeholder numbering: PASS
- Unicode pre-filter behavior: PASS

## Regression Results

- Unicode tests: 22 passed
- Full regression: 196 passed
- Skipped: 10
- Failures: 0

## Design Decision: Fail Closed

The DLPEngine does not catch analyzer exceptions or return the original
text as a successful redaction result.

A dedicated regression test simulates an analyzer failure and verifies
that the exception propagates instead of allowing unmasked text to be
returned.

This verifies fail-closed behavior at the engine level. The calling
application must also reject the request rather than forward the
original unmasked input.

## Known Scope Limitation

The English-only spaCy NER model does not guarantee detection of Hindi or Marathi PERSON names. This is an accepted limitation.

Regex-based PII detection, including emails and supported phone patterns, should continue working regardless of surrounding language.

## Conclusion

Unicode stress testing passed across the tested scripts and emoji sequences. No Unicode-specific production code changes were required based on the observed test results.
