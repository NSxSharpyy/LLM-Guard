import pytest

from dlp.dlp_engine import DLPEngine


@pytest.fixture(scope="module")
def engine():
    return DLPEngine()


def test_email_detection_and_redaction(engine):
    text = "Contact me at john.smith@example.com"

    masked, entities = engine.redact(text)

    assert "<REDACTED_EMAIL_ADDRESS>" in masked
    assert "john.smith@example.com" not in masked
    assert any(e["entity_type"] == "EMAIL_ADDRESS" for e in entities)


def test_phone_detection_and_redaction(engine):
    text = "Call me at +91 9876543210"

    masked, entities = engine.redact(text)

    assert "<REDACTED_PHONE_NUMBER>" in masked
    assert "+91 9876543210" not in masked
    assert any(e["entity_type"] == "PHONE_NUMBER" for e in entities)


def test_multiple_pii_redaction(engine):
    text = (
        "My name is John Smith. "
        "Email john@example.com. "
        "Call +91 9876543210."
    )

    masked, entities = engine.redact(text)

    entity_types = {e["entity_type"] for e in entities}

    assert "EMAIL_ADDRESS" in entity_types
    assert "PHONE_NUMBER" in entity_types

    assert "<REDACTED_EMAIL_ADDRESS>" in masked
    assert "<REDACTED_PHONE_NUMBER>" in masked

    assert "john@example.com" not in masked
    assert "+91 9876543210" not in masked


def test_empty_input(engine):
    masked, entities = engine.redact("")

    assert masked == ""
    assert entities == []


def test_ordinary_text_unchanged(engine):
    text = "The weather is pleasant outside."

    masked, entities = engine.redact(text)

    assert masked == text
    assert entities == []


def test_seven_digit_number_not_detected(engine):
    text = "Call me at 555-0147"

    masked, entities = engine.redact(text)

    assert masked == text
    assert entities == []


def test_person_not_in_day2_scope(engine):
    text = "My name is John Smith."

    masked, entities = engine.redact(text)

    assert masked == text
    assert entities == []


def test_entity_metadata_is_valid(engine):
    text = "Email john@example.com or call +91 9876543210."

    masked, entities = engine.redact(text)

    assert len(entities) == 2

    for entity in entities:
        assert entity["entity_type"] in [
            "EMAIL_ADDRESS",
            "PHONE_NUMBER"
        ]

        assert entity["start"] < entity["end"]
        assert entity["original_value"] == text[
            entity["start"]:entity["end"]
        ]

        assert 0 <= entity["score"] <= 1


def test_engine_does_not_modify_original_input(engine):
    text = "Email john@example.com"

    original = text
    engine.redact(text)

    assert text == original


def test_detects_email_in_various_formats(engine):
    """Check common email formats and variations."""
    samples = [
        "user@example.com",
        "first.last@company.co.uk",
        "user+tag@example.org",
        "name123@sub.domain.com",
    ]

    for email in samples:
        masked, entities = engine.redact(f"My email is {email}.")
        assert email not in masked, f"Failed to redact: {email}"
        assert any(
            entity["entity_type"] == "EMAIL_ADDRESS"
            for entity in entities
        )


def test_does_not_redact_invoice_numbers_or_prices(engine):
    """Ordinary prices and short order numbers should remain unchanged."""
    text = "The invoice total is $4500 for order #1234."

    masked, entities = engine.redact(text)

    assert masked == text
    assert entities == []


def test_preserves_surrounding_text_exactly(engine):
    """Only the email address should be replaced."""
    text = "Please email support@acme.com before Friday."

    masked, entities = engine.redact(text)

    assert masked == "Please email <REDACTED_EMAIL_ADDRESS> before Friday."
    assert len(entities) == 1


def test_handles_text_containing_only_pii(engine):
    """A string containing only an email should be fully redacted."""
    masked, entities = engine.redact("john@acme.com")

    assert masked == "<REDACTED_EMAIL_ADDRESS>"
    assert len(entities) == 1
    assert entities[0]["entity_type"] == "EMAIL_ADDRESS"


def test_redaction_is_idempotent(engine):
    """Already-redacted text should not be changed a second time."""
    masked_once, _ = engine.redact("Contact me at john@acme.com")
    masked_twice, entities_twice = engine.redact(masked_once)

    assert masked_twice == masked_once
    assert entities_twice == []
