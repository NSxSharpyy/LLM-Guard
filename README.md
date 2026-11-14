# LLM-Guard DLP

**A Data Loss Prevention system for detecting and protecting sensitive information in Large Language Model (LLM) workflows.**

## Project Overview

LLM-Guard DLP is designed to identify sensitive information before it is exposed to Large Language Models or external services.
The system uses Microsoft Presidio for Personally Identifiable Information (PII) detection and anonymization, along with custom recognizers and deterministic placeholders to protect sensitive information in LLM workflows.


## Current Implementation — Days 1–5

The project currently implements the following capabilities:

### Day 1 – Environment Setup and PII Detection
- Microsoft Presidio Analyzer integration.
- Presidio Anonymizer integration.
- spaCy English NLP model.
- Initial PII detection and validation.

### Day 2 – PII Redaction
- Sensitive entity redaction.
- Anonymization validation.
- Regression testing.

### Day 3 – Custom Recognizers
- Custom sensitive-information recognizers.
- Integration with the detection pipeline.
- Recognizer validation tests.

### Day 4 – Deterministic Placeholder Masking
- Semantic placeholders such as `<EMAIL_1>` and `<PHONE_1>`.
- Deterministic placeholder assignment.
- Reversible mapping support.

### Day 5 – Session-Scoped Reversible Vault
- In-memory placeholder-to-original-value storage.
- Independent mappings for each session.
- Thread-safe storage and retrieval.
- Session cleanup.
- Protection against cross-session data access.
- Concurrent session access testing.

### Validation

The complete regression suite currently reports:

- 80 tests passed.
- Python compilation successful.
- One third-party spaCy/Click deprecation warning.

## Technology Stack

- Python 3.11
- Microsoft Presidio Analyzer
- Microsoft Presidio Anonymizer
- spaCy 3.7.5
- pytest 8.3.2

## Installation

Clone the repository:

```bash
git clone -b dlp-engine https://github.com/NSxSharpyy/LLM-Guard.git
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

## Running Setup Verification

```bash
python scripts/verify_setup.py
```

## Running Tests

Run the complete test suite:

```bash
python -m pytest -v
```

## Project Structure

```text
llm-guard-dlp/
├── dlp/
│   ├── __init__.py
│   ├── custom_recognizers.py
│   ├── dlp_engine.py
│   ├── placeholder_manager.py
│   ├── vault.py
│   └── verhoeff.py
├── docs/
│   └── entity-catalog.md
├── scripts/
│   └── verify_setup.py
├── tests/
│   ├── test_day1_setup.py
│   ├── test_day2_redaction.py
│   ├── test_day3_custom_recognizers.py
│   ├── test_day4_placeholders.py
│   └── test_day5_vault.py
├── requirements.txt
├── README.md
└── .gitignore
```

## Vault Security and Retention Notes

- The vault isolates mappings by session ID but does not authenticate users. Session IDs must be securely generated and protected by the application.
- The current vault uses in-memory storage and does not have automatic expiration.
- `clear_session()` provides manual session cleanup.
- Future monitoring should count unknown-session unmask attempts without logging sensitive text.
- Redis-backed storage with a 15-minute TTL is planned for Day 9.

## Development Roadmap

Completed:
- Environment setup and PII detection.
- PII redaction.
- Custom sensitive-information recognizers.
- Deterministic semantic placeholder masking.
- Session-scoped reversible vault.

Upcoming:
- LLM prompt inspection.
- Sensitive information leakage prevention.
- Security validation and testing.
- Redis-backed vault with automatic expiration.

## Project Status

Days 1–5: Implementation and validation completed.

Latest validation:
- 80 tests passed.
- Python compilation successful.
- Session-isolation security check passed.
- One third-party spaCy/Click deprecation warning.
