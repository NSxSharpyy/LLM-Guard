# LLM-Guard DLP

**A Data Loss Prevention system for detecting and protecting sensitive information in Large Language Model (LLM) workflows.**

## Project Overview

LLM-Guard DLP identifies sensitive information before it is exposed to Large Language Models or external services.

The project uses Microsoft Presidio, custom recognizers, deterministic semantic placeholders, and session-scoped reversible vaults to protect sensitive information while preserving the context of LLM prompts and responses.

The system supports both in-memory and Redis-backed vault storage.

## Current Implementation — Days 1–6, 8–9

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
- RedisVault provides Redis-backed mapping storage with configurable automatic expiration.
- Redis mappings expire according to their configured TTL.
- Session IDs must be securely generated and protected by the integrating application.
- The vault does not independently authenticate users.
- Session mappings can be explicitly removed using session cleanup.
- The application must not forward original sensitive values or sensitive detection metadata to the LLM.
- Redis should be protected with appropriate authentication, network restrictions, and transport security in production environments.
- Redis persistence, backups, and server-side retention policies must be configured according to the application's security requirements.

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

### Upcoming
- Further LLM prompt inspection and integration.
- Sensitive information leakage prevention.
- Additional security validation.
- Performance optimization and benchmarking.

## Project Status

**Days 1–6, 8–9: Implementation and functional validation completed.**

Latest full regression validation:

- 157 tests passed.
- 10 tests skipped.
- 0 test failures.
- Python compilation successful.
- Redis connectivity verified.
- 31 Day 9 Redis Vault tests passed.
- Redis TTL expiration verified.
- Session isolation and cleanup verified.
- Cross-process mapping retrieval verified.
- Redis-backed DLPInterceptor integration verified.
- One third-party spaCy/Click deprecation warning.
