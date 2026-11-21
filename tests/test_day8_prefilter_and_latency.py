"""
Day 8: Regex pre-filter and latency tests.

Tests:
- Clean text is identified without PII indicators.
- All supported entity types pass through the pre-filter.
- AWS secret context is preserved, including letter-only secrets.
- Clean text bypasses Presidio.
- PII-bearing text invokes Presidio.
- Clean-text processing remains below the 12 ms target.
"""

import time

import pytest

from dlp.dlp_engine import DLPEngine, SUPPORTED_ENTITIES
from dlp.pre_filter import might_contain_pii


JWT = (
    "eyJhbGciOiJIUzI1NiJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
)

PII_SAMPLES = [
    ("email", "Contact john.doe@company.com"),
    ("phone", "Call +1 415-555-0132"),
    ("credit card", "Card: 4111 1111 1111 1111"),
    ("Aadhaar", "My Aadhaar number is 234123412346"),
    ("PAN", "PAN: ABCDE1234F"),
    ("AWS access key", "Key: AKIAIOSFODNN7EXAMPLE"),
    (
        "AWS secret key",
        "aws_secret_access_key = "
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    ),
    ("JWT", f"Authorization: Bearer {JWT}"),
]


@pytest.fixture
def engine():
    return DLPEngine()


def test_clean_text_has_no_pii_indicators():
    assert might_contain_pii(
        "The weather is pleasant today."
    ) is False


@pytest.mark.parametrize(
    ("entity_name", "sample"),
    PII_SAMPLES,
    ids=[sample[0] for sample in PII_SAMPLES],
)
def test_supported_pii_samples_pass_prefilter(entity_name, sample):
    assert might_contain_pii(sample) is True, (
        f"The pre-filter rejected a valid {entity_name} test sample."
    )


def test_letter_only_aws_secret_with_context_passes_prefilter():
    sample = "aws secret " + ("A" * 40)

    assert might_contain_pii(sample) is True


def test_clean_text_bypasses_presidio(engine, monkeypatch):
    def unexpected_analyzer_call(*args, **kwargs):
        pytest.fail("Presidio should not run for clean text.")

    monkeypatch.setattr(
        engine.analyzer,
        "analyze",
        unexpected_analyzer_call,
    )

    masked, entities = engine.redact(
        "The weather is pleasant today."
    )

    assert masked == "The weather is pleasant today."
    assert entities == []


@pytest.mark.parametrize(
    ("entity_name", "sample"),
    PII_SAMPLES,
    ids=[sample[0] for sample in PII_SAMPLES],
)
def test_pii_samples_invoke_presidio(
    engine,
    monkeypatch,
    entity_name,
    sample,
):
    original_analyze = engine.analyzer.analyze
    calls = []

    def tracked_analyze(*args, **kwargs):
        calls.append(True)
        return original_analyze(*args, **kwargs)

    monkeypatch.setattr(
        engine.analyzer,
        "analyze",
        tracked_analyze,
    )

    engine.redact(sample)

    assert calls, (
        f"Presidio was not invoked for the {entity_name} sample."
    )


def test_supported_entity_catalog_is_unchanged():
    expected = {
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "CREDIT_CARD",
        "AADHAAR_CARD",
        "PAN_CARD",
        "AWS_ACCESS_KEY",
        "AWS_SECRET_KEY",
        "JWT_TOKEN",
        "US_SSN",
    }

    assert set(SUPPORTED_ENTITIES) == expected


def test_clean_text_average_latency_under_12_ms(engine):
    sample = "The weather is pleasant today."

    # Warm up before measuring.
    for _ in range(10):
        engine.redact(sample)

    iterations = 500
    start = time.perf_counter()

    for _ in range(iterations):
        engine.redact(sample)

    elapsed_ms = (time.perf_counter() - start) * 1000
    average_ms = elapsed_ms / iterations

    print(f"\nAverage clean-text latency: {average_ms:.4f} ms")

    assert average_ms < 12.0
