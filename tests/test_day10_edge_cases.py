
"""Day 10 stress tests: markdown, JSON, escaped strings,
international phone numbers and regex boundaries."""

import pytest

from dlp.dlp_engine import DLPEngine


@pytest.fixture(scope="module")
def engine():
    return DLPEngine()


# ---------- Markdown code blocks ----------

def test_aws_key_inside_markdown_code_block(engine):
    text = '```python\naws_key = "AKIAIOSFODNN7EXAMPLE"\n```'

    masked, entities = engine.redact(text)

    assert "AKIAIOSFODNN7EXAMPLE" not in masked
    assert "<AWS_KEY_1>" in masked
    assert "```python" in masked
    assert "```" in masked.rstrip()


def test_email_inside_inline_code_span(engine):
    text = "Use `john.doe@company.com` as the test account."

    masked, entities = engine.redact(text)

    assert "john.doe@company.com" not in masked
    assert "<EMAIL_1>" in masked
    assert masked.startswith("Use `")
    assert masked.endswith("` as the test account.")


# ---------- Multi-line JSON ----------

def test_email_and_card_inside_multiline_json(engine):
    text = '''{
  "name": "John Doe",
  "email": "john.doe@company.com",
  "card": "4532015112830366"
}'''

    masked, entities = engine.redact(text)

    assert "john.doe@company.com" not in masked
    assert "4532015112830366" not in masked
    assert masked.count('"') == text.count('"')
    assert '"name": "John Doe"' in masked
    assert masked.strip().startswith("{")
    assert masked.strip().endswith("}")


def test_json_with_aws_secret_key_field(engine):
    text = (
        '{"aws_secret_access_key": '
        '"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}'
    )

    masked, entities = engine.redact(text)

    assert "wJalrXUtnFEMI" not in masked
    assert "<AWS_SECRET_1>" in masked
    assert masked.startswith('{"aws_secret_access_key": "')
    assert masked.endswith('"}')

@pytest.mark.parametrize("secret", [
    "/" + "A" * 39,
    "A" * 39 + "/",
    "+" + "A" * 39,
    "A" * 39 + "+",
])
def test_aws_secret_key_special_character_boundaries(engine, secret):
    text = f'aws_secret_access_key = "{secret}"'

    masked, entities = engine.redact(text)

    assert secret not in masked
    assert "<AWS_SECRET_1>" in masked

def test_json_trailing_comma_not_swallowed_by_jwt_regex(engine):
    jwt = (
        "eyJhbGciOiJIUzI1NiJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    )

    text = f'{{"token": "{jwt}", "status": "active"}}'

    masked, entities = engine.redact(text)

    assert jwt not in masked
    assert "<JWT_1>" in masked
    assert '", "status": "active"}' in masked


# ---------- Escaped strings ----------

def test_email_inside_escaped_quoted_string(engine):
    text = 'She said \\"email john.doe@company.com\\" to him.'

    masked, entities = engine.redact(text)

    assert "john.doe@company.com" not in masked
    assert '\\"' in masked


def test_email_inside_python_string_with_escaped_newline(engine):
    text = 'message = "Contact john.doe@company.com\\nfor details"'

    masked, entities = engine.redact(text)

    assert "john.doe@company.com" not in masked
    assert "\\n" in masked


# ---------- International phone numbers ----------

@pytest.mark.parametrize("phone", [
    "+44 20 7946 0958",
    "+91-98765-43210",
    "+1 (415) 555-0199",
    "+61 2 9374 4000",
    "+49 30 123456",
])
def test_international_phone_formats_detected(engine, phone):
    text = f"Call me at {phone} anytime."

    masked, entities = engine.redact(text)

    phone_hits = [
        entity for entity in entities
        if entity["entity_type"] == "PHONE_NUMBER"
    ]

    assert phone_hits, f"Failed to detect international phone: {phone}"
    assert phone not in masked


# ---------- Combined realistic input ----------

def test_realistic_mixed_messy_prompt(engine):
    text = '''Here's the config:
```json
{
  "contact_email": "john.doe@company.com",
  "support_phone": "+44 20 7946 0958",
  "api_key": "AKIAIOSFODNN7EXAMPLE"
}
```
Let me know if you need anything else, you can also reach me at 555-0147.'''

    masked, entities = engine.redact(text)

    assert "john.doe@company.com" not in masked
    assert "+44 20 7946 0958" not in masked
    assert "AKIAIOSFODNN7EXAMPLE" not in masked

    assert "```json" in masked

    # Known Day 2 limitation: seven-digit phone detection.
    # Keep this visible until separately investigated.
    assert "555-0147" in masked
