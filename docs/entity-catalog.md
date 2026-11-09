# LLM-Guard DLP — Entity Catalog

## 1. Standard Presidio Entities

These entities are supported by the installed Presidio Analyzer.

| Entity | Description | Status |
|---|---|---|
| EMAIL_ADDRESS | Email addresses | Verified |
| PHONE_NUMBER | Telephone numbers | Verified |
| PERSON | Individual names | Verified |
| CREDIT_CARD | Credit card numbers | Spot-tested |
| US_SSN | US Social Security Numbers | Built-in recognizer with validation; spot-tested, detection is value-dependent |

## 2. Planned Custom Entities — Day 3

These entities will require custom recognizers or additional detection logic.

| Entity | Description | Planned implementation |
|---|---|---|
| IN_AADHAAR | Indian Aadhaar numbers | Custom recognizer |
| IN_PAN | Indian PAN identifiers | Custom recognizer |
| AWS_ACCESS_KEY | AWS access key identifiers | Custom recognizer |
| AWS_SECRET_KEY | AWS secret access keys | Custom recognizer |
| JWT | JSON Web Tokens | Custom recognizer |

## 3. Planned Custom Entities — Day 16

| Entity | Description |
|---|---|
| INTERNAL_IPV4 | Internal IPv4 addresses |
| DATABASE_CONNECTION_STRING | Database connection strings |
| PRIVATE_KEY | Private SSH/RSA keys |

## 4. Future Detection Capability

| Entity | Description |
|---|---|
| PASSWORD | Passwords detected using contextual detection logic |

## 5. Detection Strategy

LLM-Guard will use Presidio's built-in recognizers for standard
PII detection and custom recognizers for additional sensitive
information.

Detected entities will be passed to the anonymization layer
to replace sensitive values with appropriate placeholders.

## 6. Current Validation

The following have been tested during Day 1:

- Email detection
- Phone number detection
- Person detection
- US SSN detection
- Credit card detection
- PERSON anonymization
- EMAIL_ADDRESS anonymization

Custom entity detection will be implemented and validated
during the corresponding project development stages.
