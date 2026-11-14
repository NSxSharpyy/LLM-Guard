
import pytest

from dlp import DLPInterceptor


@pytest.fixture
def interceptor():
    return DLPInterceptor()


def test_basic_masking_and_restoration(interceptor):
    session = "basic-session"

    masked, entities = interceptor.redact(
        "Contact john@example.com",
        session,
    )

    assert masked == "Contact <EMAIL_1>"
    assert interceptor.unmask(masked, session) == (
        "Contact john@example.com"
    )
    assert len(entities) == 1


def test_multiple_emails_in_one_session(interceptor):
    session = "multiple-session"

    masked, _ = interceptor.redact(
        "Contact john@example.com and jane@example.com",
        session,
    )

    assert masked == "Contact <EMAIL_1> and <EMAIL_2>"


def test_repeated_value_reuses_placeholder(interceptor):
    session = "repeated-session"

    first, _ = interceptor.redact(
        "Contact john@example.com",
        session,
    )

    second, _ = interceptor.redact(
        "Email john@example.com again",
        session,
    )

    assert "<EMAIL_1>" in first
    assert "<EMAIL_1>" in second
    assert "<EMAIL_2>" not in second


def test_different_values_do_not_collide(interceptor):
    session = "collision-session"

    first, _ = interceptor.redact(
        "Contact john@example.com",
        session,
    )

    second, _ = interceptor.redact(
        "Contact jane@example.com",
        session,
    )

    assert "<EMAIL_1>" in first
    assert "<EMAIL_2>" in second

    assert interceptor.unmask(first, session) == (
        "Contact john@example.com"
    )

    assert interceptor.unmask(second, session) == (
        "Contact jane@example.com"
    )


def test_sessions_are_isolated(interceptor):
    session_a = "session-A"
    session_b = "session-B"

    masked_a, _ = interceptor.redact(
        "Contact john@example.com",
        session_a,
    )

    masked_b, _ = interceptor.redact(
        "Contact jane@example.com",
        session_b,
    )

    assert masked_a == "Contact <EMAIL_1>"
    assert masked_b == "Contact <EMAIL_1>"

    assert interceptor.unmask(masked_a, session_a) == (
        "Contact john@example.com"
    )

    assert interceptor.unmask(masked_b, session_b) == (
        "Contact jane@example.com"
    )


def test_session_cleanup(interceptor):
    session = "cleanup-session"

    masked, _ = interceptor.redact(
        "Contact john@example.com",
        session,
    )

    assert interceptor.active_session_count() == 1

    interceptor.end_session(session)

    assert interceptor.active_session_count() == 0

    assert interceptor.unmask(masked, session) == masked


def test_original_values_not_exposed_in_metadata(interceptor):
    _, entities = interceptor.redact(
        "Contact john@example.com",
        "metadata-session",
    )

    assert entities

    for entity in entities:
        assert "original_value" not in entity
        assert "placeholder" in entity
        assert "entity_type" in entity


def test_reordered_values_restore_correctly(interceptor):
    session = "reorder-session"

    interceptor.redact(
        "John john@example.com and Jane jane@example.com",
        session,
    )

    second, _ = interceptor.redact(
        "Jane jane@example.com and John john@example.com",
        session,
    )

    assert second == "Jane <EMAIL_2> and John <EMAIL_1>"

    restored = interceptor.unmask(second, session)

    assert restored == (
        "Jane jane@example.com and John john@example.com"
    )


@pytest.mark.parametrize("invalid_session", ["", " ", None, 123])
def test_redact_rejects_invalid_session_ids(
    interceptor,
    invalid_session,
):
    with pytest.raises(ValueError):
        interceptor.redact("Contact john@example.com", invalid_session)


@pytest.mark.parametrize("invalid_session", ["", " ", None, 123])
def test_unmask_rejects_invalid_session_ids(
    interceptor,
    invalid_session,
):
    with pytest.raises(ValueError):
        interceptor.unmask("<EMAIL_1>", invalid_session)


@pytest.mark.parametrize("invalid_session", ["", " ", None, 123])
def test_end_session_rejects_invalid_session_ids(
    interceptor,
    invalid_session,
):
    with pytest.raises(ValueError):
        interceptor.end_session(invalid_session)


def test_empty_text(interceptor):
    masked, entities = interceptor.redact("", "empty-session")

    assert masked == ""
    assert entities == []
