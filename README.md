# LLM-Guard DLP

**A Data Loss Prevention system for detecting and protecting sensitive information in Large Language Model (LLM) workflows.**

## Project Overview

LLM-Guard DLP identifies sensitive information before it is exposed to Large Language Models or external services.

The project uses Microsoft Presidio, custom recognizers, deterministic semantic placeholders, and session-scoped reversible vaults to protect sensitive information while preserving the context of LLM prompts and responses.

The system supports both in-memory and Redis-backed vault storage.

## Current Implementation — Days 1-13

### Day 1 – Environment Setup and PII Detection
- Microsoft Presidio integration.
- spaCy English NLP model.
- Initial PII detection and validation.

### Day 2 – PII Redaction
- Sensitive entity detection.
- Baseline redaction pipeline.
- Regression testing.

### Day 3 – Custom Recognizers
- Aadhaar card detection with Verhoeff checksum validation.
- PAN card detection.
- AWS access key detection.
- AWS secret key detection.
- JWT token detection.
- Custom recognizer integration.

### Day 4 – Deterministic Placeholder Masking
- Semantic placeholders such as `<EMAIL_1>` and `<PHONE_1>`.
- Repeated sensitive values reuse their placeholders within a masking operation.
- Independent numbering for different entity types.
- Overlap resolution.

### Day 5 – Session-Scoped Reversible Vault
- In-memory placeholder-to-original-value storage.
- Independent mappings for each session.
- Thread-safe storage and retrieval.
- Reversible text restoration.
- Session cleanup.
- Cross-session isolation.

### Day 6 – DLPInterceptor
- Single public entry point for the DLP module.
- Integration of DLPEngine, PlaceholderManager, and Vault.
- Session-level placeholder numbering across multiple calls.
- Reuse of placeholders for previously detected values.
- Protection against placeholder collisions.
- Original-value metadata removed from returned detection results.
- Session isolation and cleanup.

### Day 8 – Regex Pre-filter and Latency Profiling
- Regex-based pre-filter for identifying prompts that may contain sensitive information.
- Fast-path handling for prompts that do not match configured sensitive-information patterns.
- Integration with the DLP processing workflow.
- Baseline latency profiling across different prompt scenarios.
- Performance measurement using mean, median, minimum, and maximum execution times.

### Day 9 – Redis-Backed Session-Scoped Reversible Vault
- Redis-backed placeholder-to-original-value storage.
- Independent mappings for each session.
- Configurable mapping expiration using TTL.
- Automatic expiration of stored mappings.
- Session-specific mapping retrieval.
- Reversible text restoration.
- Session cleanup and existence checking.
- Session counting.
- Placeholder and original-value input validation.
- Redis connectivity verification.
- Dedicated Redis integration tests.

### Day 10 – Unicode and Detection Improvements
- Improved handling of Unicode text during sensitive-information detection.
- Added regression tests for Unicode-related detection scenarios.
- Validated compatibility with the existing redaction pipeline.

### Day 11 – Unicode Processing and Validation
- Improved Unicode-aware processing.
- Added additional regression coverage for Unicode edge cases.
- Validated compatibility with existing recognizers and placeholder handling.

### Day 12 – Streaming Response Unmasking
- Implemented a streaming unmasking engine.
- Added ring-buffer handling for incomplete placeholder fragments.
- Handles placeholders split across multiple response chunks.
- Buffers incomplete placeholder tags until they can be safely processed.
- Prevents incomplete placeholder fragments from being released to clients.
- Supports session-scoped restoration through the vault.

### Day 13 – Zero-PII Audit and Cross-Worker Placeholder Allocation
- Removed process-local session mapping storage from DLPInterceptor.
- Implemented shared placeholder allocation through Redis.
- Added atomic Redis Lua-based placeholder allocation.
- Added HMAC-SHA256-based reverse-lookup key generation.
- Prevented placeholder collisions between independent workers.
- Added indexed Redis key tracking for session cleanup.
- Implemented atomic session cleanup using Redis Lua.
- Added regression tests for cross-worker allocation and cleanup.
- Improved AWS secret and JWT/JWE recognizer coverage.

## Technology Stack

- Python 3.11
- Microsoft Presidio Analyzer 2.2.355
- Microsoft Presidio Anonymizer 2.2.355
- spaCy 3.7.5
- pytest 8.3.2
- Redis 5.0.8
- Redis Server

## Installation

Clone the repository:

```bash
git clone -b dlp-engine https://github.com/NSxSharpyy/LLM-Guard.git llm-guard-dlp
cd llm-guard-dlp
```

Create and activate a virtual environment:

```bash
python3.11 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Download the English spaCy model:

```bash
python -m spacy download en_core_web_sm
```

### Redis Server Setup

Install Redis Server on Kali Linux or Debian-based systems:

```bash
sudo apt update
sudo apt install redis-server
```

Start the Redis service:

```bash
sudo systemctl enable --now redis-server
```

Verify Redis availability:

```bash
redis-cli ping
```

Expected output:

```text
PONG
```

### HMAC Secret Configuration

The Redis-backed DLPInterceptor requires a shared HMAC secret
for cross-worker placeholder allocation.

Configure the secret before starting the application:

```bash
export DLP_HMAC_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
```

Verify that the variable is configured without displaying its value:

```bash
python -c 'import os; print("HMAC configured:", bool(os.getenv("DLP_HMAC_SECRET")))'
```

Important:
- All application workers must use the same HMAC secret.
- Generate the secret once and store it securely.
- Do not generate a different secret for each worker.
- Use a secrets manager in production.
- Never commit the secret to Git or expose it in logs.
- Configure the same secret whenever the application restarts.
- Do not regenerate the secret during application restarts.
- Changing the secret can prevent existing reverse-lookup keys from being found.
- Secret rotation should be performed using a planned migration procedure.

## Setup Verification

```bash
python scripts/verify_setup.py
```

## Running Tests

Run the complete regression suite:

```bash
python -m pytest -v
```

Run Day 9 Redis Vault tests independently:

```bash
python -m pytest tests/test_day9_redis_vault.py -v
```

Compile the project:

```bash
python -m compileall -q dlp tests examples
```

## Basic Usage

The public DLPInterceptor interface supports masking and reversible restoration:

```python
from dlp import DLPInterceptor

dlp = DLPInterceptor()
session_id = "conversation-123"

try:
    masked_prompt, entities = dlp.redact(
        "Contact john@example.com",
        session_id
    )

    # Only masked_prompt should be sent to the LLM.
    print("Masked prompt:", masked_prompt)

    llm_response = "Please contact <EMAIL_1>."

    final_response = dlp.unmask(
        llm_response,
        session_id
    )

    print("Final response:", final_response)

finally:
    dlp.end_session(session_id)
```

### RedisVault Usage

RedisVault provides Redis-backed storage as an alternative to the in-memory Vault.

```python
from dlp.redis_vault import RedisVault

vault = RedisVault(
    host="localhost",
    port=6379,
    db=0,
    ttl_seconds=900
)

session_id = "conversation-123"

if vault.ping():
    vault.store(session_id, {
        "<EMAIL_1>": "john@example.com"
    })

    masked_text = "Contact <EMAIL_1>"

    restored_text = vault.unmask_text(
        masked_text,
        session_id
    )

    print(restored_text)

    vault.clear_session(session_id)
```

The default mapping TTL is 900 seconds (15 minutes). It can be configured when creating the RedisVault instance.

**RedisVault compatibility note:**

- `store()` is retained for backward compatibility and legacy mapping-storage workflows.
- `DLPInterceptor` uses `allocate_placeholders()` for atomic, cross-worker placeholder allocation.
- Do not mix `store()` and `allocate_placeholders()` within the same session. They do not share synchronized placeholder counters and reverse mappings, which can cause placeholder collisions.
- Use one allocation method consistently for each session.

See [docs/integration-guide.md](docs/integration-guide.md) for the complete integration workflow and security considerations.

## Project Structure

```text
llm-guard-dlp/
├── dlp/
│   ├── __init__.py
│   ├── custom_recognizers.py
│   ├── dlp_engine.py
│   ├── interceptor.py
│   ├── placeholder_manager.py
│   ├── pre_filter.py
│   ├── redis_vault.py
│   ├── vault.py
│   └── verhoeff.py
├── docs/
│   ├── day2-baseline-redaction.md
│   ├── day8-latency-report.md
│   ├── entity-catalog.md
│   └── integration-guide.md
├── examples/
│   └── usage_example.py
├── scripts/
│   ├── distributed_retrieval_demo.py
│   ├── profile_latency.py
│   └── verify_setup.py
├── tests/
│   ├── test_day1_setup.py
│   ├── test_day2_redaction.py
│   ├── test_day3_custom_recognizers.py
│   ├── test_day4_placeholders.py
│   ├── test_day5_vault.py
│   ├── test_day6_interceptor.py
│   └── test_day9_redis_vault.py
├── requirements.txt
├── README.md
└── .gitignore
```

## Security and Retention Considerations

- Sensitive values are replaced with semantic placeholders before being forwarded to an LLM.
- The in-memory Vault provides session-scoped, thread-safe mapping storage.
- RedisVault provides shared Redis-backed mapping storage.
- DLPInterceptor uses Redis-backed placeholder allocation to maintain consistent placeholder numbering across independent workers.
- Redis Lua scripts provide atomic placeholder allocation and indexed session cleanup.
- HMAC-SHA256 generates reverse-lookup key identifiers without exposing original values in Redis key names.
- All application workers must use the same securely configured DLP_HMAC_SECRET.
- Redis mappings expire according to their configured TTL.
- Session mappings can be explicitly removed using session cleanup.
- Session IDs must be securely generated and protected by the integrating application.
- The vault does not independently authenticate users.

### Important PII Storage Limitation

The current implementation does not provide complete zero-PII storage.

Although HMAC protects reverse-lookup key names, original sensitive values are still stored in Redis mapping values in plaintext.

Therefore:
- HMAC does not encrypt Redis mapping values.
- Redis access must be restricted to trusted application components.
- Production deployments should evaluate Redis TLS, authentication, encryption at rest, backups, and persistence settings.
- Redis credentials and HMAC secrets must be protected.
- Sensitive values and detection metadata must not be forwarded to external LLM services.
- Additional security work is required before claiming complete zero-PII protection.


## Development Roadmap

### Completed
- Environment setup and PII detection.
- Baseline PII redaction.
- Custom sensitive-information recognizers.
- Deterministic semantic placeholder masking.
- Session-scoped reversible in-memory vault.
- DLPInterceptor public interface.
- Regex pre-filter and baseline latency profiling.
- Redis-backed session-scoped reversible vault.
- Configurable mapping TTL and automatic expiration.
- Redis integration and regression testing.
- Unicode processing and regression validation.
- Streaming response unmasking.
- Cross-worker placeholder allocation.
- HMAC-based reverse-lookup key generation.
- Atomic Redis session cleanup.
- Cross-worker collision regression testing.
- JWT/JWE detection regression testing.

### Upcoming
- Further LLM prompt inspection and integration.
- Sensitive information leakage prevention.
- Additional security validation.
- Performance optimization and benchmarking.
- Encryption of sensitive values stored in Redis.
- Further zero-PII architecture improvements.
- Redis deployment hardening and security validation.
- Additional concurrent-worker and failure-recovery testing.
- Further LLM prompt and response integration.

## Project Status

**Day 13 upstream leakage verification completed.
Further security hardening and documentation review remain ongoing.**

Latest full regression validation:

- 258 tests passed.
- 10 tests skipped.
- 0 test failures.
- Python compilation successful.
- Day 13 live upstream audit: 500/500 requests matched.
- Zero raw PII leaks detected in the positive audit.
- Negative leak-detection test passed.
- Redis integration and cross-worker regression tests passed.
- Unicode and streaming-related regression tests validated.
- One third-party spaCy/Click deprecation warning.

The Day 13 result verifies upstream prompt masking against the local
mock LLM. It does not establish complete zero-PII storage.

Original sensitive values remain in Redis mapping values in plaintext.
Production hardening and encryption of stored values remain outstanding.

See [Day 13 Zero-PII Upstream Verification Audit](docs/day13-zero-pii-audit.md)
for methodology, results, evidence, and limitations.
