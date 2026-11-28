
import pytest

from dlp.multimodal_handler import (
    MultiModalHandler,
    MultiModalInput,
    MultiModalInputError,
)


class FakeInterceptor:
    """Predictable interceptor for isolated unit tests."""

    def __init__(self):
        self.calls = []
        self.placeholders = {}

    def redact(self, text, session_id, role=None):
        self.calls.append((text, session_id))

        entities = []
        masked_text = text

        sensitive_value = "alice@example.com"

        if sensitive_value in text:
            placeholder = self.placeholders.setdefault(
                sensitive_value,
                "<EMAIL_1>",
            )

            masked_text = text.replace(
                sensitive_value,
                placeholder,
            )

            entities.append({
                "entity_type": "EMAIL_ADDRESS",
                "masked": True,
                "placeholder": placeholder,
            })

        return masked_text, entities


@pytest.fixture
def fake_interceptor():
    return FakeInterceptor()


@pytest.fixture
def handler(fake_interceptor):
    return MultiModalHandler(fake_interceptor)


# ---------------------------------------------------------
# 1. INPUT VALIDATION TESTS
# ---------------------------------------------------------

def test_valid_minimal_input():
    MultiModalHandler.validate_input({
        "text": "Hello",
    })


def test_valid_input_with_attachments():
    MultiModalHandler.validate_input({
        "text": "Review this file",
        "attachments": [
            {
                "filename": "report.pdf",
                "extracted_text": "Document content",
            }
        ],
    })


def test_valid_attachment_metadata():
    MultiModalHandler.validate_input({
        "text": "Review this file",
        "attachments": [
            {
                "filename": "report.pdf",
                "extracted_text": "Document content",
                "mime_type": "application/pdf",
                "size_bytes": 2048,
            }
        ],
    })


@pytest.mark.parametrize(
    "raw_input",
    [
        None,
        "not a dictionary",
        [],
    ],
)
def test_rejects_non_dictionary_input(raw_input):
    with pytest.raises(MultiModalInputError):
        MultiModalHandler.validate_input(raw_input)


def test_rejects_missing_text():
    with pytest.raises(MultiModalInputError):
        MultiModalHandler.validate_input({})


def test_rejects_unexpected_top_level_key():
    with pytest.raises(MultiModalInputError):
        MultiModalHandler.validate_input({
            "text": "Hello",
            "metadata": {},
        })


@pytest.mark.parametrize(
    "text",
    [
        None,
        123,
        [],
    ],
)
def test_rejects_non_string_text(text):
    with pytest.raises(MultiModalInputError):
        MultiModalHandler.validate_input({
            "text": text,
        })


@pytest.mark.parametrize(
    "attachments",
    [
        None,
        "not a list",
        {},
    ],
)
def test_rejects_non_list_attachments(attachments):
    with pytest.raises(MultiModalInputError):
        MultiModalHandler.validate_input({
            "text": "Hello",
            "attachments": attachments,
        })


def test_rejects_non_dictionary_attachment():
    with pytest.raises(MultiModalInputError):
        MultiModalHandler.validate_input({
            "text": "Hello",
            "attachments": ["report.pdf"],
        })


def test_rejects_missing_filename():
    with pytest.raises(MultiModalInputError):
        MultiModalHandler.validate_input({
            "text": "Hello",
            "attachments": [
                {"extracted_text": "Document content"}
            ],
        })


def test_rejects_missing_extracted_text():
    with pytest.raises(MultiModalInputError):
        MultiModalHandler.validate_input({
            "text": "Hello",
            "attachments": [
                {"filename": "report.pdf"}
            ],
        })


def test_rejects_non_string_filename():
    with pytest.raises(MultiModalInputError):
        MultiModalHandler.validate_input({
            "text": "Hello",
            "attachments": [
                {
                    "filename": 123,
                    "extracted_text": "Content",
                }
            ],
        })


def test_rejects_non_string_extracted_text():
    with pytest.raises(MultiModalInputError):
        MultiModalHandler.validate_input({
            "text": "Hello",
            "attachments": [
                {
                    "filename": "report.pdf",
                    "extracted_text": 123,
                }
            ],
        })


def test_rejects_unexpected_attachment_field():
    with pytest.raises(MultiModalInputError):
        MultiModalHandler.validate_input({
            "text": "Hello",
            "attachments": [
                {
                    "filename": "report.pdf",
                    "extracted_text": "Content",
                    "notes": "Unscanned content",
                }
            ],
        })


def test_rejects_invalid_mime_type():
    with pytest.raises(MultiModalInputError):
        MultiModalHandler.validate_input({
            "text": "Hello",
            "attachments": [
                {
                    "filename": "report.pdf",
                    "extracted_text": "Content",
                    "mime_type": 123,
                }
            ],
        })


@pytest.mark.parametrize(
    "size_bytes",
    [
        -1,
        1.5,
        True,
        "2048",
    ],
)
def test_rejects_invalid_attachment_size(size_bytes):
    with pytest.raises(MultiModalInputError):
        MultiModalHandler.validate_input({
            "text": "Hello",
            "attachments": [
                {
                    "filename": "report.pdf",
                    "extracted_text": "Content",
                    "size_bytes": size_bytes,
                }
            ],
        })


# ---------------------------------------------------------
# 2. MULTIMODAL INPUT REPRESENTATION TESTS
# ---------------------------------------------------------

def test_multimodal_input_representation(handler):
    raw_input = {
        "text": "Hello",
        "attachments": [
            {
                "filename": "report.pdf",
                "extracted_text": "Document content",
            }
        ],
    }

    result = MultiModalInput.from_dict(raw_input)

    assert result.text == "Hello"
    assert isinstance(result.attachments, tuple)
    assert result.attachments[0]["filename"] == "report.pdf"


# ---------------------------------------------------------
# 3. HANDLER PROCESSING TESTS
# ---------------------------------------------------------

def test_process_main_text(handler, fake_interceptor):
    result = handler.process(
        {"text": "Contact alice@example.com"},
        "day20-unit-session",
    )

    assert result["masked_text"] == "Contact <EMAIL_1>"
    assert result["attachments"] == []
    assert result["total_entities_found"] == 1
    assert result["entity_types_found"] == ["EMAIL_ADDRESS"]


def test_process_attachment_and_preserve_metadata(handler):
    result = handler.process(
        {
            "text": "Review this document",
            "attachments": [
                {
                    "filename": "report.pdf",
                    "extracted_text": "Contact alice@example.com",
                    "mime_type": "application/pdf",
                    "size_bytes": 2048,
                }
            ],
        },
        "day20-unit-session",
    )

    attachment = result["attachments"][0]

    assert attachment["filename"] == "report.pdf"
    assert attachment["mime_type"] == "application/pdf"
    assert attachment["size_bytes"] == 2048
    assert attachment["masked_text"] == "Contact <EMAIL_1>"
    assert "extracted_text" not in attachment


def test_process_multiple_attachments(handler):
    result = handler.process(
        {
            "text": "Review these files",
            "attachments": [
                {
                    "filename": "one.txt",
                    "extracted_text": "Contact alice@example.com",
                },
                {
                    "filename": "two.txt",
                    "extracted_text": "No sensitive data",
                },
            ],
        },
        "day20-unit-session",
    )

    assert len(result["attachments"]) == 2
    assert result["attachments"][0]["masked_text"] == (
        "Contact <EMAIL_1>"
    )
    assert result["attachments"][1]["masked_text"] == (
        "No sensitive data"
    )


def test_repeated_email_reuses_placeholder(handler):
    result = handler.process(
        {
            "text": "Contact alice@example.com",
            "attachments": [
                {
                    "filename": "contact.txt",
                    "extracted_text": "Email alice@example.com",
                }
            ],
        },
        "day20-unit-session",
    )

    assert "<EMAIL_1>" in result["masked_text"]
    assert result["attachments"][0]["masked_text"] == (
        "Email <EMAIL_1>"
    )


def test_entity_count_and_types_are_aggregated(handler):
    result = handler.process(
        {
            "text": "Contact alice@example.com",
            "attachments": [
                {
                    "filename": "one.txt",
                    "extracted_text": "Email alice@example.com",
                },
                {
                    "filename": "two.txt",
                    "extracted_text": "No sensitive data",
                },
            ],
        },
        "day20-unit-session",
    )

    assert result["total_entities_found"] == 2
    assert result["entity_types_found"] == ["EMAIL_ADDRESS"]


def test_clean_input_returns_zero_entities(handler):
    result = handler.process(
        {
            "text": "Hello there",
            "attachments": [
                {
                    "filename": "clean.txt",
                    "extracted_text": "Nothing sensitive here",
                }
            ],
        },
        "day20-unit-session",
    )

    assert result["total_entities_found"] == 0
    assert result["entity_types_found"] == []


def test_no_attachments_is_supported(handler):
    result = handler.process(
        {"text": "Hello"},
        "day20-unit-session",
    )

    assert result["masked_text"] == "Hello"
    assert result["attachments"] == []


def test_same_session_id_is_used_for_every_content(
    handler,
    fake_interceptor,
):
    handler.process(
        {
            "text": "Main text",
            "attachments": [
                {
                    "filename": "one.txt",
                    "extracted_text": "Attachment one",
                },
                {
                    "filename": "two.txt",
                    "extracted_text": "Attachment two",
                },
            ],
        },
        "day20-shared-session",
    )

    assert len(fake_interceptor.calls) == 3
    assert all(
        session_id == "day20-shared-session"
        for _, session_id in fake_interceptor.calls
    )


def test_original_input_is_not_modified(handler):
    raw_input = {
        "text": "Contact alice@example.com",
        "attachments": [
            {
                "filename": "report.txt",
                "extracted_text": "Contact alice@example.com",
            }
        ],
    }

    original_attachment_text = raw_input["attachments"][0][
        "extracted_text"
    ]

    handler.process(raw_input, "day20-unit-session")

    assert raw_input["attachments"][0]["extracted_text"] == (
        original_attachment_text
    )


# ---------------------------------------------------------
# 4. REAL REDIS INTEGRATION TEST
# ---------------------------------------------------------

def test_real_interceptor_reuses_and_restores_placeholder():
    from dlp.interceptor import DLPInterceptor

    session_id = "day20-integration-session"

    interceptor = DLPInterceptor(
        redis_host="127.0.0.1",
        redis_port=6380,
        redis_db=13,
    )

    interceptor.end_session(session_id)

    try:
        handler = MultiModalHandler(interceptor)

        result = handler.process(
            {
                "text": "Contact alice@example.com",
                "attachments": [
                    {
                        "filename": "contact.txt",
                        "extracted_text": "Email alice@example.com",
                    }
                ],
            },
            session_id,
        )

        main_placeholder = "<EMAIL_1>"

        assert main_placeholder in result["masked_text"]
        assert main_placeholder in result["attachments"][0]["masked_text"]
        assert result["total_entities_found"] == 2

        restored_main = interceptor.unmask(
            result["masked_text"],
            session_id,
        )

        restored_attachment = interceptor.unmask(
            result["attachments"][0]["masked_text"],
            session_id,
        )

        assert restored_main == "Contact alice@example.com"
        assert restored_attachment == "Email alice@example.com"

    finally:
        interceptor.end_session(session_id)
