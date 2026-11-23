
import pytest

from dlp import DLPInterceptor


@pytest.fixture
def interceptor(monkeypatch):
    """Create an interceptor using the isolated test Redis database."""

    # Configure a test-only HMAC secret.
    monkeypatch.setenv(
        "DLP_HMAC_SECRET",
        "day15-test-secret-0123456789abcdef",
    )

    instance = DLPInterceptor(redis_db=15)

    instance._vault._redis.flushdb()

    yield instance

    instance._vault._redis.flushdb()


def test_known_session_email_is_not_flagged(interceptor):
    session = "day15-known-email"

    interceptor._vault.store(
        session,
        {"<EMAIL_1>": "alice@example.com"},
    )

    clean, findings = interceptor.scan_output(
        "Your registered email is alice@example.com",
        session,
    )

    assert clean is True
    assert findings == []


def test_unexpected_email_is_flagged(interceptor):
    session = "day15-unexpected-email"

    clean, findings = interceptor.scan_output(
        "Contact stranger@example.com",
        session,
    )

    assert clean is False
    assert len(findings) == 1
    assert findings[0]["entity_type"] == "EMAIL_ADDRESS"


def test_unexpected_phone_number_is_flagged(interceptor):
    session = "day15-unexpected-phone"

    clean, findings = interceptor.scan_output(
        "Call +1-415-555-2671",
        session,
    )

    assert clean is False
    assert any(
        item["entity_type"] == "PHONE_NUMBER"
        for item in findings
    )


def test_unexpected_credit_card_is_flagged(interceptor):
    session = "day15-credit-card"

    clean, findings = interceptor.scan_output(
        "Card number: 4111 1111 1111 1111",
        session,
    )

    assert clean is False
    assert any(
        item["entity_type"] == "CREDIT_CARD"
        for item in findings
    )


def test_unexpected_aws_access_key_is_flagged(interceptor):
    session = "day15-aws-key"

    clean, findings = interceptor.scan_output(
        "AWS key: AKIAIOSFODNN7EXAMPLE",
        session,
    )

    assert clean is False
    assert any(
        item["entity_type"] == "AWS_ACCESS_KEY"
        for item in findings
    )


def test_multiple_unexpected_pii_entities_are_flagged(interceptor):
    session = "day15-multiple-pii"

    response = (
        "Email: stranger@example.com. "
        "Phone: +1-415-555-2671"
    )

    clean, findings = interceptor.scan_output(
        response,
        session,
    )

    detected_types = {
        item["entity_type"]
        for item in findings
    }

    assert clean is False
    assert "EMAIL_ADDRESS" in detected_types
    assert "PHONE_NUMBER" in detected_types


def test_empty_vault_detects_unexpected_email(interceptor):
    session = "day15-empty-vault"

    clean, findings = interceptor.scan_output(
        "Contact unknown@example.com",
        session,
    )

    assert clean is False
    assert findings


def test_response_without_pii_is_clean(interceptor):
    session = "day15-no-pii"

    clean, findings = interceptor.scan_output(
        "The deployment completed successfully.",
        session,
    )

    assert clean is True
    assert findings == []


def test_empty_response_is_clean(interceptor):
    session = "day15-empty-response"

    clean, findings = interceptor.scan_output(
        "",
        session,
    )

    assert clean is True
    assert findings == []


def test_findings_do_not_expose_complete_email(interceptor):
    session = "day15-privacy"

    sensitive_email = "confidential@example.com"

    clean, findings = interceptor.scan_output(
        f"Contact {sensitive_email}",
        session,
    )

    assert clean is False
    assert sensitive_email not in str(findings)
    assert findings[0]["value_sample"] == "conf..."


def test_session_values_are_isolated(interceptor):
    session_a = "day15-session-a"
    session_b = "day15-session-b"

    interceptor._vault.store(
        session_a,
        {"<EMAIL_1>": "alice@example.com"},
    )

    clean, findings = interceptor.scan_output(
        "Contact alice@example.com",
        session_b,
    )

    assert clean is False
    assert findings


def test_scan_output_rejects_non_string_response(interceptor):
    with pytest.raises(TypeError):
        interceptor.scan_output(
            None,
            "day15-invalid-response",
        )


def test_scan_output_rejects_invalid_session(interceptor):
    with pytest.raises(ValueError):
        interceptor.scan_output(
            "Contact alice@example.com",
            "invalid session",
        )


def test_redact_unmask_and_scan_output_integration(interceptor):
    session = "day15-full-integration"

    masked, entities = interceptor.redact(
        "Contact alice@example.com",
        session,
    )

    assert masked == "Contact <EMAIL_1>"
    assert len(entities) == 1

    final_response = interceptor.unmask(
        masked,
        session,
    )

    assert final_response == "Contact alice@example.com"

    clean, findings = interceptor.scan_output(
        final_response,
        session,
    )

    assert clean is True
    assert findings == []

def test_expected_and_unexpected_emails_in_same_response(interceptor):
    session = "day15-mixed-response"

    interceptor._vault.store(
        session,
        {"<EMAIL_1>": "john.doe@company.com"},
    )

    response = (
        "Your email john.doe@company.com is confirmed. "
        "For support, contact unexpected@mystery.net."
    )

    clean, findings = interceptor.scan_output(response, session)

    assert clean is False
    assert len(findings) == 1
    assert findings[0]["entity_type"] == "EMAIL_ADDRESS"
    assert findings[0]["value_sample"] == "unex..."
