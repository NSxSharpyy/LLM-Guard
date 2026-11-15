
import pytest

from dlp import DLPInterceptor
from concurrent.futures import ThreadPoolExecutor

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


def test_concurrent_redaction_same_session(interceptor):
    session = "concurrent-session"

    def redact_email(_):
        return interceptor.redact(
            "Contact john@example.com",
            session,
        )[0]

    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(redact_email, range(20)))

    assert all(result == "Contact <EMAIL_1>" for result in results)

    assert interceptor.unmask(
        "Contact <EMAIL_1>",
        session,
    ) == "Contact john@example.com"


def test_detection_exception_does_not_create_session(
    interceptor,
    monkeypatch,
):
    session = "detection-error-session"

    def raise_error(*args, **kwargs):
        raise RuntimeError("Simulated detection failure")

    monkeypatch.setattr(
        interceptor._engine,
        "redact",
        raise_error,
    )

    with pytest.raises(RuntimeError):
        interceptor.redact(
            "Contact john@example.com",
            session,
        )

    assert interceptor.active_session_count() == 0
    assert session not in interceptor._session_managers



def test_placeholder_exception_does_not_leave_partial_session(
    interceptor,
    monkeypatch,
):
    from dlp.placeholder_manager import PlaceholderManager

    session = "placeholder-error-session"

    # Simulate an entity returned by the detection engine.
    def fake_engine_redact(text):
        return text, [
            {
                "entity_type": "EMAIL_ADDRESS",
                "start": 8,
                "end": 24,
                "original_value": "john@example.com",
            }
        ]

    monkeypatch.setattr(
        interceptor._engine,
        "redact",
        fake_engine_redact,
    )

    # Raise specifically during interceptor placeholder generation.
    original_method = PlaceholderManager.get_placeholder

    def raise_after_generation(self, entity_type, original_value):
        original_method(self, entity_type, original_value)
        raise RuntimeError("Simulated placeholder failure")

    monkeypatch.setattr(
        PlaceholderManager,
        "get_placeholder",
        raise_after_generation,
    )

    with pytest.raises(RuntimeError):
        interceptor.redact("Contact john@example.com", session)

    assert interceptor.active_session_count() == 0
    assert session not in interceptor._session_managers

def test_placeholder_exception_preserves_existing_session(
    interceptor,
    monkeypatch,
):
    from dlp.placeholder_manager import PlaceholderManager

    session = "existing-session-error"

    # First redaction succeeds and creates EMAIL_1.
    masked_text, _ = interceptor.redact(
        "Contact john@example.com",
        session,
    )

    assert masked_text == "Contact <EMAIL_1>"

    # Simulate a second redaction for a different email.
    def fake_engine_redact(text):
        return text, [
            {
                "entity_type": "EMAIL_ADDRESS",
                "start": 8,
                "end": 24,
                "original_value": "jane@example.com",
            }
        ]

    monkeypatch.setattr(
        interceptor._engine,
        "redact",
        fake_engine_redact,
    )

    # Raise during the interceptor's placeholder generation.
    original_method = PlaceholderManager.get_placeholder

    def raise_after_generation(self, entity_type, original_value):
        original_method(self, entity_type, original_value)
        raise RuntimeError("Simulated placeholder failure")

    monkeypatch.setattr(
        PlaceholderManager,
        "get_placeholder",
        raise_after_generation,
    )

    with pytest.raises(RuntimeError):
        interceptor.redact(
            "Contact jane@example.com",
            session,
        )

    # The original session state must remain intact.
    assert interceptor._vault.get_mapping(session) == {
        "<EMAIL_1>": "john@example.com"
    }

    assert interceptor.unmask(
        "Contact <EMAIL_1>",
        session,
    ) == "Contact john@example.com"

    assert interceptor._session_managers[session].value_mapping == {
        ("EMAIL_ADDRESS", "john@example.com"): "<EMAIL_1>"
    }
