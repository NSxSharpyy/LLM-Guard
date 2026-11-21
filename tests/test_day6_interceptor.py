
import pytest

from dlp import DLPInterceptor
from concurrent.futures import ThreadPoolExecutor

@pytest.fixture
def interceptor():
    instance = DLPInterceptor(redis_db=15)

    instance._vault._redis.flushdb()

    yield instance

    instance._vault._redis.flushdb()


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

    assert interceptor.has_session(session) is False
    assert interceptor.active_session_count() == 0


def test_allocation_exception_does_not_leave_partial_session(
    interceptor,
    monkeypatch,
):
    session = "allocation-error-session"

    def fake_engine_redact(text):
        return text, [
            {
                "entity_type": "EMAIL_ADDRESS",
                "start": 8,
                "end": 24,
                "original_value": "john@example.com",
            }
        ]

    def raise_allocation_error(session_id, entities):
        raise RuntimeError("Simulated Redis allocation failure")

    monkeypatch.setattr(
        interceptor._engine,
        "redact",
        fake_engine_redact,
    )

    monkeypatch.setattr(
        interceptor._vault,
        "allocate_placeholders",
        raise_allocation_error,
    )

    with pytest.raises(RuntimeError):
        interceptor.redact(
            "Contact john@example.com",
            session,
        )

    assert interceptor.has_session(session) is False
    assert interceptor.active_session_count() == 0


def test_allocation_exception_preserves_existing_session(
    interceptor,
    monkeypatch,
):
    session = "existing-session-error"

    # First redaction succeeds and creates EMAIL_1.
    masked_text, _ = interceptor.redact(
        "Contact john@example.com",
        session,
    )

    assert masked_text == "Contact <EMAIL_1>"

    original_mapping = interceptor._vault.get_mapping(session)

    assert original_mapping == {
        "<EMAIL_1>": "john@example.com"
    }

    def fake_engine_redact(text):
        return text, [
            {
                "entity_type": "EMAIL_ADDRESS",
                "start": 8,
                "end": 24,
                "original_value": "jane@example.com",
            }
        ]

    def raise_allocation_error(session_id, entities):
        raise RuntimeError("Simulated Redis allocation failure")

    monkeypatch.setattr(
        interceptor._engine,
        "redact",
        fake_engine_redact,
    )

    monkeypatch.setattr(
        interceptor._vault,
        "allocate_placeholders",
        raise_allocation_error,
    )

    with pytest.raises(RuntimeError):
        interceptor.redact(
            "Contact jane@example.com",
            session,
        )

    # Existing Redis mappings must remain unchanged.
    assert interceptor._vault.get_mapping(session) == original_mapping

    assert interceptor.unmask(
        "Contact <EMAIL_1>",
        session,
    ) == "Contact john@example.com"

def test_independent_interceptors_do_not_collide(interceptor):
    session = "cross-worker-session"

    worker_a = interceptor
    worker_b = DLPInterceptor(redis_db=15)

    first, _ = worker_a.redact(
        "Contact alice@example.com",
        session,
    )

    second, _ = worker_b.redact(
        "Contact bob@example.com",
        session,
    )

    third, _ = worker_b.redact(
        "Again alice@example.com",
        session,
    )

    assert first == "Contact <EMAIL_1>"
    assert second == "Contact <EMAIL_2>"
    assert third == "Again <EMAIL_1>"

    assert worker_a.unmask(first, session) == (
        "Contact alice@example.com"
    )

    assert worker_b.unmask(second, session) == (
        "Contact bob@example.com"
    )

    assert worker_b.unmask(third, session) == (
        "Again alice@example.com"
    )

    worker_a.end_session(session)


@pytest.mark.parametrize(
    "invalid_entity",
    [
        {
            "entity_type": "EMAIL_ADDRESS",
            "start": -1,
            "end": 7,
            "original_value": "john@example.com",
        },
        {
            "entity_type": "EMAIL_ADDRESS",
            "start": 8,
            "end": 100,
            "original_value": "john@example.com",
        },
        {
            "entity_type": "EMAIL_ADDRESS",
            "start": 8,
            "end": 24,
            "original_value": "jane@example.com",
        },
        {
            "entity_type": "EMAIL_ADDRESS",
            "start": 8,
            "end": 24,
        },
        {
            "entity_type": "EMAIL_ADDRESS",
            "start": True,
            "end": 24,
            "original_value": "john@example.com",
        },
    ],
)
def test_invalid_entity_metadata_rejected_before_allocation(
    interceptor,
    monkeypatch,
    invalid_entity,
):
    session = "invalid-metadata-session"
    allocation_called = False

    def fake_engine_redact(text):
        return text, [invalid_entity]

    def track_allocation(session_id, entities):
        nonlocal allocation_called
        allocation_called = True
        return ["<EMAIL_1>"]

    monkeypatch.setattr(
        interceptor._engine,
        "redact",
        fake_engine_redact,
    )

    monkeypatch.setattr(
        interceptor._vault,
        "allocate_placeholders",
        track_allocation,
    )

    with pytest.raises(ValueError):
        interceptor.redact(
            "Contact john@example.com",
            session,
        )

    assert allocation_called is False
    assert interceptor.has_session(session) is False


def test_entity_offsets_must_be_integers(
    interceptor,
    monkeypatch,
):
    session = "invalid-offset-type-session"

    def fake_engine_redact(text):
        return text, [
            {
                "entity_type": "EMAIL_ADDRESS",
                "start": "8",
                "end": 24,
                "original_value": "john@example.com",
            }
        ]

    monkeypatch.setattr(
        interceptor._engine,
        "redact",
        fake_engine_redact,
    )

    with pytest.raises(ValueError):
        interceptor.redact(
            "Contact john@example.com",
            session,
        )

    assert interceptor.has_session(session) is False


def test_overlapping_entity_offsets_rejected_before_allocation(
    interceptor,
    monkeypatch,
):
    session = "overlapping-entities-session"
    allocation_called = False

    def fake_engine_redact(text):
        return text, [
            {
                "entity_type": "EMAIL_ADDRESS",
                "start": 8,
                "end": 24,
                "original_value": "john@example.com",
            },
            {
                "entity_type": "PHONE_NUMBER",
                "start": 13,
                "end": 20,
                "original_value": "example",
            },
        ]

    def track_allocation(session_id, entities):
        nonlocal allocation_called
        allocation_called = True
        return ["<EMAIL_1>", "<PHONE_1>"]

    monkeypatch.setattr(
        interceptor._engine,
        "redact",
        fake_engine_redact,
    )

    monkeypatch.setattr(
        interceptor._vault,
        "allocate_placeholders",
        track_allocation,
    )

    with pytest.raises(ValueError, match="must not overlap"):
        interceptor.redact(
            "Contact john@example.com",
            session,
        )

    assert allocation_called is False
    assert interceptor.has_session(session) is False


@pytest.mark.parametrize(
    "invalid_response",
    [
        None,
        (),
        [],
        [None],
        ["INVALID_PLACEHOLDER"],
        ["<EMAIL>"],
        ["<EMAIL_1>", "<EMAIL_2>"],
    ],
)
def test_invalid_vault_placeholder_response_rejected(
    interceptor,
    monkeypatch,
    invalid_response,
):
    session = "invalid-placeholder-session"

    def fake_engine_redact(text):
        return text, [
            {
                "entity_type": "EMAIL_ADDRESS",
                "start": 8,
                "end": 24,
                "original_value": "john@example.com",
            },
        ]

    def fake_allocation(session_id, entities):
        return invalid_response

    monkeypatch.setattr(
        interceptor._engine,
        "redact",
        fake_engine_redact,
    )

    monkeypatch.setattr(
        interceptor._vault,
        "allocate_placeholders",
        fake_allocation,
    )

    with pytest.raises(RuntimeError):
        interceptor.redact(
            "Contact john@example.com",
            session,
        )

def test_repeated_value_in_same_text_reuses_placeholder(interceptor):
    text = (
        "Contact alice@example.com or "
        "email alice@example.com again."
    )

    masked, entities = interceptor.redact(
        text,
        "repeated-value-session",
    )

    assert masked.count("<EMAIL_1>") == 2
    assert len(entities) == 2

    restored = interceptor.unmask(
        masked,
        "repeated-value-session",
    )

    assert restored == text
