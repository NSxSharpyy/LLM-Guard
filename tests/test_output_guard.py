import pytest
from src.security.output_guard import inspect_and_sanitize_output


def test_output_guard_redacts_leaks() -> None:
    leaky_output = "Here is your key sk-proj-fakeapikey1234567890 and contact support@company.com"
    verdict = inspect_and_sanitize_output(leaky_output)

    assert verdict.flagged is True
    assert verdict.rule_id == "DLP-OUT-002-EMAIL"  # Last matching rule
    assert "sk-proj-fakeapikey1234567890" not in verdict.sanitized_text
    assert "support@company.com" not in verdict.sanitized_text
    assert "[REDACTED_API_KEY]" in verdict.sanitized_text
    assert "[REDACTED_EMAIL]" in verdict.sanitized_text


def test_clean_output_passes() -> None:
    clean = "Hello! How can I assist you today with your code structure?"
    verdict = inspect_and_sanitize_output(clean)

    assert verdict.flagged is False
    assert verdict.rule_id == "PASS-ALL-CHECKS"
    assert verdict.sanitized_text == clean
