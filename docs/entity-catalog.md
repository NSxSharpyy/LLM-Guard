# LLM-Guard DLP — Entity Catalog

## 1. Standard Presidio Entities

These entities are available through the installed Presidio
Analyzer.

| Entity | Description | Status |
|---|---|---|
| EMAIL_ADDRESS | Email addresses | Day 2 implemented and tested |
| PHONE_NUMBER | Telephone numbers | Day 2 implemented and tested |
| PERSON | Individual names | Day 1 analyzer verified; Day 2 excluded |
| CREDIT_CARD | Credit card numbers | Day 1 spot-tested |
| US_SSN | US Social Security Numbers | Day 1 spot-tested; value-dependent |

## 2. Day 2 Redaction Scope

The DLPEngine currently supports:

- EMAIL_ADDRESS
- PHONE_NUMBER

These entities are detected using Presidio Analyzer and
replaced using Presidio Anonymizer.

Replacement placeholders:

- `<REDACTED_EMAIL_ADDRESS>`
- `<REDACTED_PHONE_NUMBER>`

## 3. Planned Custom Entities — Day 3

These entities will require custom recognizers or additional
detection logic.

| Entity | Description | Planned implementation |
|---|---|---|
| IN_AADHAAR | Indian Aadhaar numbers | Custom recognizer |
| IN_PAN | Indian PAN identifiers | Custom recognizer |
| AWS_ACCESS_KEY | AWS access key identifiers | Custom recognizer |
| AWS_SECRET_KEY | AWS secret access keys | Custom recognizer |
| JWT | JSON Web Tokens | Custom recognizer |

## 4. Planned Custom Entities — Day 16

| Entity | Description |
|---|---|
| INTERNAL_IPV4 | Internal IPv4 addresses |
| DATABASE_CONNECTION_STRING | Database connection strings |
| PRIVATE_KEY | Private SSH/RSA keys |

## 5. Future Detection Capability

| Entity | Description |
|---|---|
| PASSWORD | Passwords detected using contextual detection logic |

## 6. Detection Strategy

LLM-Guard uses Presidio's built-in recognizers for standard
PII detection and custom recognizers for additional sensitive
information.

Detected entities are passed to the anonymization layer
to replace sensitive values with appropriate placeholders.

The supported entity list in DLPEngine controls which entities
are actively analyzed and redacted.

## 7. Validation History

### Day 1

- Presidio Analyzer initialization
- Email detection
- Phone detection
- PERSON detection
- US SSN detection
- Credit-card detection
- PERSON anonymization
- EMAIL_ADDRESS anonymization
- Empty-input handling
- Ordinary-text handling

### Day 2

- Email detection and redaction
- Phone detection and redaction
- Combined PII detection and redaction
- Empty-input handling
- Ordinary-text preservation
- Seven-digit phone-number edge case
- PERSON exclusion from the Day 2 redaction scope
- Detection metadata validation

See `docs/day2-baseline-redaction.md` for detailed results.
