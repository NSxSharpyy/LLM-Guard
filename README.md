# LLM-Guard DLP

**A Data Loss Prevention system for detecting and protecting sensitive information in Large Language Model (LLM) workflows.**

## Project Overview

LLM-Guard DLP is designed to identify sensitive information before it is exposed to Large Language Models or external services.

The system uses Microsoft Presidio for Personally Identifiable Information (PII) detection and anonymization, with plans to introduce custom recognizers for additional sensitive information.

## Current Implementation — Day 1

The initial setup includes:

- Presidio Analyzer for sensitive entity detection.
- Presidio Anonymizer for replacing detected sensitive information.
- spaCy English NLP model.
- Basic PII detection and validation tests.

### Verified Detection Capabilities

| Entity | Description |
|---|---|
| EMAIL_ADDRESS | Email addresses |
| PHONE_NUMBER | Telephone numbers |
| PERSON | Individual names |
| US_SSN | US Social Security Numbers (detection is value-dependent; see entity catalog) |
| CREDIT_CARD | Credit card numbers |

### Anonymization

Detected information can be replaced with entity-based placeholders.

Example:

**Original:**
`My name is John Smith and my email is john.smith@example.com`

**Anonymized:**
`My name is <PERSON> and my email is <EMAIL_ADDRESS>`

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
├── docs/
│   └── entity-catalog.md
├── scripts/
│   └── verify_setup.py
├── tests/
│   └── test_day1_setup.py
├── requirements.txt
├── README.md
└── .gitignore
```

## Development Roadmap

The project will progressively introduce:

- Custom PII and credential recognizers.
- Advanced detection and anonymization.
- LLM prompt inspection.
- Sensitive information leakage prevention.
- Security validation and testing.

## Project Status

Day 1: Environment setup, Presidio integration, initial detection, anonymization verification and entity catalog.

Further functionality will be implemented and validated in subsequent development stages.
