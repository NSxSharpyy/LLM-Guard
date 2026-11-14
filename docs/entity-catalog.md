# LLM-Guard DLP — Entity Catalog

## 1. Standard Presidio Entities

These entities are available through the installed Presidio Analyzer.

| Entity | Description | Status |
|---|---|---|
| EMAIL_ADDRESS | Email addresses | Day 2 implemented and tested |
| PHONE_NUMBER | Telephone numbers | Day 2 implemented and tested |
| PERSON | Individual names | Day 1 analyzer verified; excluded from active redaction scope |
| CREDIT_CARD | Credit card numbers | Day 1 spot-tested |
| US_SSN | US Social Security Numbers | Day 1 spot-tested; value-dependent |

## 2. Active Redaction Scope

The `DLPEngine` currently supports seven entity types from standard Presidio and custom recognizers.

### Standard entities

- `EMAIL_ADDRESS`
- `PHONE_NUMBER`

### Custom entities

- `AADHAAR_CARD`
- `PAN_CARD`
- `AWS_ACCESS_KEY`
- `AWS_SECRET_KEY`
- `JWT_TOKEN`

Detected entities are processed using Presidio Analyzer and replaced using Presidio Anonymizer.

Replacement placeholders:

| Entity | Replacement |
|---|---|
| EMAIL_ADDRESS | `<REDACTED_EMAIL_ADDRESS>` |
| PHONE_NUMBER | `<REDACTED_PHONE_NUMBER>` |
| AADHAAR_CARD | `<REDACTED_AADHAAR_CARD>` |
| PAN_CARD | `<REDACTED_PAN_CARD>` |
| AWS_ACCESS_KEY | `<REDACTED_AWS_ACCESS_KEY>` |
| AWS_SECRET_KEY | `<REDACTED_AWS_SECRET_KEY>` |
| JWT_TOKEN | `<REDACTED_JWT_TOKEN>` |

## 3. Custom Entities — Day 3 Implementation

The following custom recognizers have been implemented in `dlp/custom_recognizers.py` and registered with the Presidio Analyzer.

| Entity | Description | Detection strategy |
|---|---|---|
| AADHAAR_CARD | Indian Aadhaar number format | 12-digit pattern with optional spaces or hyphens and Verhoeff checksum validation |
| PAN_CARD | Indian Permanent Account Number | Five uppercase letters, four digits, and one uppercase letter |
| AWS_ACCESS_KEY | AWS access key identifier | `AKIA` or `ASIA` prefix followed by 16 uppercase alphanumeric characters |
| AWS_SECRET_KEY | AWS secret access key | 40-character base64-like pattern with contextual detection |
| JWT_TOKEN | JSON Web Token | Three dot-separated segments with a base64url-like header beginning with `eyJ` |

### 3.1 Aadhaar validation

A custom Verhoeff checksum implementation is provided in `dlp/verhoeff.py`.

The Aadhaar recognizer:

- Identifies 12-digit candidates.
- Supports optional spaces and hyphens.
- Normalizes the candidate before checksum validation.
- Rejects candidates that fail Verhoeff validation.

**Limitation:** Passing the format and checksum checks does not establish that an Aadhaar number was issued or belongs to a particular person.

### 3.2 PAN validation

The PAN recognizer checks the expected structural format:

`[A-Z]{5}[0-9]{4}[A-Z]`

This is a format-based check, not verification against an official PAN database.

### 3.3 AWS credential detection

The AWS access-key recognizer identifies access-key identifiers with the supported `AKIA` and `ASIA` prefixes.

The AWS secret-key recognizer uses a 40-character base64-like pattern and contextual terms such as `aws`, `secret`, and `aws_secret_access_key`.

Its base recognition score is intentionally low (0.3). The pattern alone is not sufficient to establish that a matched string is an actual AWS secret. False positives are possible.

### 3.4 JWT detection

The JWT recognizer checks for three dot-separated segments and a header beginning with `eyJ`.

This is structural detection; it does not verify the token signature, issuer, expiration, or validity.

### 3.5 Compliance and security rationale

The custom entity catalog supports the identification of sensitive personal data and credentials that may be exposed through LLM prompts.

| Entity | Compliance / security rationale |
|---|---|
| AADHAAR_CARD | Supports identification and protection of Aadhaar-related personal data under applicable Indian data-protection requirements, including the DPDP Act. |
| PAN_CARD | Supports identification and protection of Indian tax-identification information as personal data. |
| AWS_ACCESS_KEY | Supports cloud credential protection and secrets-management controls. |
| AWS_SECRET_KEY | Supports protection of cloud authentication secrets and prevention of accidental credential disclosure. |
| JWT_TOKEN | Supports protection of authentication tokens and prevention of accidental session or credential leakage. |

**Important limitation:** These recognizers provide detection and redaction capabilities. Their implementation alone does not establish legal or regulatory compliance. Detection accuracy also depends on the patterns, context, and input format.

## 4. Planned Custom Entities — Day 16

| Entity | Description | Status |
|---|---|---|
| INTERNAL_IPV4 | Internal IPv4 addresses | Planned |
| DATABASE_CONNECTION_STRING | Database connection strings | Planned |
| PRIVATE_KEY | Private SSH/RSA keys | Planned |

## 5. Future Detection Capability

| Entity | Description | Status |
|---|---|---|
| PASSWORD | Passwords detected using contextual detection logic | Planned |

## 6. Detection Strategy

LLM-Guard uses Presidio's built-in recognizers for standard PII detection and custom recognizers for additional sensitive information.

The custom recognizers are registered with the Presidio Analyzer during `DLPEngine` initialization.

The processing flow is:

1. Receive input text.
2. Analyze the text against the supported entity list.
3. Apply custom validation where required, including Aadhaar checksum validation.
4. Pass detected entities to the Presidio Anonymizer.
5. Replace sensitive values with entity-specific placeholders.
6. Return the redacted text and detection metadata.

The supported entity list in `DLPEngine` controls which entities are actively analyzed and redacted.

Detection metadata includes:

- Entity type
- Start position
- End position
- Confidence score
- Original detected value (only when `include_original_value=True`)

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
- Original input preservation
- Multiple email format detection
- Invoice number and price false-positive checks
- Redaction idempotency

See `docs/day2-baseline-redaction.md` for detailed results.

### Day 3

- Verhoeff checksum validation
- Rejection of invalid Aadhaar checksums
- Aadhaar detection with spaces
- PAN format detection
- Rejection of malformed PAN values
- AWS access-key detection (`AKIA`)
- AWS temporary access-key detection (`ASIA`)
- Rejection of access-key candidates without supported prefixes
- AWS secret-key detection with context
- JWT structural detection
- Rejection of ordinary dotted text as JWT
- Registration of all five custom recognizers
- Verification of all seven supported entity types
- Multiple custom entity detection and redaction
- Day 2 email and phone regression testing
- Ordinary-text false-positive testing

**Day 3 automated tests:** 19 passed.

**Full regression suite:** Passed after correcting the Day 3 phone regression test to use the valid Day 2 phone-number example.

### Metadata privacy

By default, entity metadata does not include the original detected value.
It contains the entity type, start offset, end offset, and confidence score.

Original values can be included explicitly by initializing the engine with
`DLPEngine(include_original_value=True)`. This should only be used when
there is a clear requirement and the resulting metadata is handled securely.
