# LLM-Guard DLP

**A Data Loss Prevention system for detecting and protecting sensitive information in Large Language Model (LLM) workflows.**

## Project Overview

LLM-Guard DLP identifies sensitive information before it is exposed to Large Language Models or external services.

The project uses Microsoft Presidio, custom recognizers, deterministic semantic placeholders, and a session-scoped reversible vault to protect sensitive information while preserving the context of LLM prompts and responses.

## Current Implementation — Days 1–6

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

## Technology Stack

- Python 3.11
- Microsoft Presidio Analyzer
- Microsoft Presidio Anonymizer
- spaCy 3.7.5
- pytest 8.3.2

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

## Setup Verification

```bash
python scripts/verify_setup.py
```

## Running Tests

Run the complete regression suite:

```bash
python -m pytest -v
```

Compile the project:

```bash
python -m compileall -q dlp tests examples
```

## Basic Usage

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
│   ├── vault.py
│   └── verhoeff.py
├── docs/
│   ├── day2-baseline-redaction.md
│   ├── entity-catalog.md
│   └── integration-guide.md
├── examples/
│   └── usage_example.py
├── scripts/
│   └── verify_setup.py
├── tests/
│   ├── test_day1_setup.py
│   ├── test_day2_redaction.py
│   ├── test_day3_custom_recognizers.py
│   ├── test_day4_placeholders.py
│   ├── test_day5_vault.py
│   └── test_day6_interceptor.py
├── requirements.txt
├── README.md
└── .gitignore
```

## Security and Retention Considerations

- The vault is in-memory and session-scoped.
- Session IDs must be securely generated and protected by the integrating application.
- The vault does not independently authenticate users.
- Session mappings are removed through `end_session()`.
- The application must not forward original sensitive values or sensitive detection metadata to the LLM.
- The current implementation does not provide persistent storage or automatic session expiration.
- Redis-backed storage with automatic expiration is planned for a future development stage.

## Development Roadmap

Completed:
- Environment setup and PII detection.
- Baseline PII redaction.
- Custom sensitive-information recognizers.
- Deterministic semantic placeholder masking.
- Session-scoped reversible vault.
- DLPInterceptor public interface.

Upcoming:
- LLM prompt inspection and integration.
- Sensitive information leakage prevention.
- Additional security validation.
- Redis-backed vault with automatic expiration.

## Project Status

Days 1–6: Implementation and functional validation completed.

Latest validation:
- 101 tests passed.
- Python compilation successful.
- Public package import successful.
- Usage example successful.
- Session isolation and cleanup verified.
- Reordered placeholder handling verified.
- One third-party spaCy/Click deprecation warning.
EOF
