"""
Day 3 tests: Custom Presidio PatternRecognizers.

Tests:
- Verhoeff checksum validation
- Aadhaar detection and precision
- PAN detection
- AWS Access Key detection
- AWS Secret Key detection
- JWT detection
- Registry integration
- Day 2 regression
"""

import pytest

from dlp.dlp_engine import DLPEngine, SUPPORTED_ENTITIES
from dlp.verhoeff import validate as verhoeff_validate


@pytest.fixture(scope="module")
def engine():
    return DLPEngine()


# ============================================================
# VERHOEFF ALGORITHM
# ============================================================

def test_verhoeff_accepts_known_valid_number():
    assert verhoeff_validate("234123412346") is True


def test_verhoeff_rejects_invalid_checksum():
    assert verhoeff_validate("234123412340") is False


def test_verhoeff_rejects_non_digit_input():
    assert verhoeff_validate("23412341234X") is False


def test_verhoeff_rejects_empty_string():
    assert verhoeff_validate("") is False


# ============================================================
# AADHAAR DETECTION
# ============================================================

def test_redacts_valid_aadhaar_number(engine):
    masked, entities = engine.redact(
        "My Aadhaar number is 234123412346."
    )

    assert "<REDACTED_AADHAAR_CARD>" in masked
    assert any(
        e["entity_type"] == "AADHAAR_CARD"
        for e in entities
    )


def test_rejects_invalid_aadhaar_checksum(engine):
    masked, entities = engine.redact(
        "Order number: 111111111112."
    )

    aadhaar_hits = [
        e for e in entities
        if e["entity_type"] == "AADHAAR_CARD"
    ]

    assert len(aadhaar_hits) == 0
    assert "111111111112" in masked


def test_detects_spaced_aadhaar_format(engine):
    masked, entities = engine.redact(
        "Aadhaar: 2341 2341 2346"
    )

    assert any(
        e["entity_type"] == "AADHAAR_CARD"
        for e in entities
    )


# ============================================================
# PAN CARD DETECTION
# ============================================================

def test_redacts_valid_pan_format(engine):
    masked, entities = engine.redact("PAN: ABCDE1234F")

    assert "<REDACTED_PAN_CARD>" in masked
    assert any(
        e["entity_type"] == "PAN_CARD"
        for e in entities
    )


def test_rejects_malformed_pan(engine):
    masked, entities = engine.redact(
        "Code: ABCDE12345F"
    )

    pan_hits = [
        e for e in entities
        if e["entity_type"] == "PAN_CARD"
    ]

    assert len(pan_hits) == 0

def test_rejects_unrelated_40_character_string(engine):
    text = "Reference value: ABCDEFGHIJKLMNOPQRSTUVWXYZ12345678901234"

    _, entities = engine.redact(text)

    aws_secret_hits = [
        entity for entity in entities
        if entity["entity_type"] == "AWS_SECRET_KEY"
    ]

    assert aws_secret_hits == []

# ============================================================
# AWS ACCESS KEY DETECTION
# ============================================================

def test_redacts_aws_access_key(engine):
    masked, entities = engine.redact(
        "Key: AKIAIOSFODNN7EXAMPLE"
    )

    assert "<REDACTED_AWS_ACCESS_KEY>" in masked
    assert any(
        e["entity_type"] == "AWS_ACCESS_KEY"
        for e in entities
    )


def test_redacts_aws_temporary_access_key(engine):
    masked, entities = engine.redact(
        "Key: ASIAIOSFODNN7EXAMPLE"
    )

    assert any(
        e["entity_type"] == "AWS_ACCESS_KEY"
        for e in entities
    )


def test_rejects_string_without_aws_prefix(engine):
    masked, entities = engine.redact(
        "Code: XXXXIOSFODNN7EXAMPLEA"
    )

    aws_hits = [
        e for e in entities
        if e["entity_type"] == "AWS_ACCESS_KEY"
    ]

    assert len(aws_hits) == 0


# ============================================================
# AWS SECRET KEY DETECTION
# ============================================================

def test_redacts_aws_secret_key_with_context(engine):
    masked, entities = engine.redact(
        "aws_secret_access_key = "
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    )

    assert "<REDACTED_AWS_SECRET_KEY>" in masked
    assert any(
        e["entity_type"] == "AWS_SECRET_KEY"
        for e in entities
    )


# ============================================================
# JWT DETECTION
# ============================================================

def test_redacts_jwt_token(engine):
    jwt = (
        "eyJhbGciOiJIUzI1NiJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    )

    masked, entities = engine.redact(
        f"Authorization: Bearer {jwt}"
    )

    assert "<REDACTED_JWT_TOKEN>" in masked
    assert jwt not in masked
    assert any(
        e["entity_type"] == "JWT_TOKEN"
        for e in entities
    )


def test_rejects_plain_text_with_dots(engine):
    masked, entities = engine.redact(
        "The file is named report.v2.final.docx"
    )

    jwt_hits = [
        e for e in entities
        if e["entity_type"] == "JWT_TOKEN"
    ]

    assert len(jwt_hits) == 0


# ============================================================
# REGISTRY AND INTEGRATION
# ============================================================

def test_all_seven_entities_are_supported(engine):
    expected = {
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "AADHAAR_CARD",
        "PAN_CARD",
        "AWS_ACCESS_KEY",
        "AWS_SECRET_KEY",
        "JWT_TOKEN",
    }

    assert set(SUPPORTED_ENTITIES) == expected


def test_redacts_multiple_custom_entities(engine):
    text = (
        "Aadhaar 234123412346, "
        "PAN ABCDE1234F, "
        "and key AKIAIOSFODNN7EXAMPLE."
    )

    masked, entities = engine.redact(text)

    entity_types = {
        e["entity_type"] for e in entities
    }

    assert "AADHAAR_CARD" in entity_types
    assert "PAN_CARD" in entity_types
    assert "AWS_ACCESS_KEY" in entity_types

    assert "<REDACTED_AADHAAR_CARD>" in masked
    assert "<REDACTED_PAN_CARD>" in masked
    assert "<REDACTED_AWS_ACCESS_KEY>" in masked


def test_day2_email_and_phone_still_work(engine):
    masked, entities = engine.redact(
        "Email me at john@acme.com or call +91 9876543210."
    )

    assert "<REDACTED_EMAIL_ADDRESS>" in masked
    assert "<REDACTED_PHONE_NUMBER>" in masked

    entity_types = {entity["entity_type"] for entity in entities}

    assert "EMAIL_ADDRESS" in entity_types
    assert "PHONE_NUMBER" in entity_types

def test_plain_text_produces_no_false_positives(engine):
    text = "The weather is nice today, nothing special."

    masked, entities = engine.redact(text)

    assert masked == text
    assert entities == []
