
import pytest

from dlp.vault import Vault, build_mapping_from_entities
from concurrent.futures import ThreadPoolExecutor
from dlp.dlp_engine import DLPEngine

@pytest.fixture
def vault():
    return Vault()

@pytest.fixture(scope="module")
def engine():
    return DLPEngine(include_original_value=True)

def test_store_and_retrieve_mapping(vault):
    mapping = {
        "<EMAIL_1>": "john@example.com"
    }

    vault.store("session_a", mapping)

    assert vault.get_mapping("session_a") == mapping


def test_sessions_are_isolated(vault):
    vault.store("session_a", {
        "<EMAIL_1>": "john@example.com"
    })

    vault.store("session_b", {
        "<EMAIL_1>": "jane@example.com"
    })

    assert vault.unmask_text(
        "Contact <EMAIL_1>", "session_a"
    ) == "Contact john@example.com"

    assert vault.unmask_text(
        "Contact <EMAIL_1>", "session_b"
    ) == "Contact jane@example.com"


def test_unknown_session_cannot_access_mapping(vault):
    vault.store("session_a", {
        "<EMAIL_1>": "john@example.com"
    })

    assert vault.get_mapping("unknown") == {}

    assert vault.unmask_text(
        "Contact <EMAIL_1>", "unknown"
    ) == "Contact <EMAIL_1>"


def test_clearing_session_does_not_affect_others(vault):
    vault.store("session_a", {
        "<EMAIL_1>": "john@example.com"
    })

    vault.store("session_b", {
        "<EMAIL_1>": "jane@example.com"
    })

    vault.clear_session("session_a")

    assert vault.get_mapping("session_a") == {}

    assert vault.unmask_text(
        "<EMAIL_1>", "session_b"
    ) == "jane@example.com"


def test_session_count(vault):
    vault.store("session_a", {
        "<EMAIL_1>": "john@example.com"
    })

    vault.store("session_b", {
        "<PHONE_1>": "+919876543210"
    })

    assert vault.session_count() == 2

    vault.clear_session("session_a")

    assert vault.session_count() == 1


def test_store_merges_existing_mapping(vault):
    vault.store("session_a", {
        "<EMAIL_1>": "john@example.com"
    })

    vault.store("session_a", {
        "<PHONE_1>": "+919876543210"
    })

    assert vault.get_mapping("session_a") == {
        "<EMAIL_1>": "john@example.com",
        "<PHONE_1>": "+919876543210"
    }


def test_returned_mapping_is_independent_copy(vault):
    vault.store("session_a", {
        "<EMAIL_1>": "john@example.com"
    })

    retrieved = vault.get_mapping("session_a")
    retrieved["<EMAIL_1>"] = "attacker@example.com"

    assert vault.get_mapping("session_a")[
        "<EMAIL_1>"
    ] == "john@example.com"


def test_build_mapping_from_entities():
    entities = [
        {
            "placeholder": "<EMAIL_1>",
            "original_value": "john@example.com"
        },
        {
            "placeholder": "<PHONE_1>",
            "original_value": "+919876543210"
        }
    ]

    assert build_mapping_from_entities(entities) == {
        "<EMAIL_1>": "john@example.com",
        "<PHONE_1>": "+919876543210"
    }


def test_empty_mapping_does_not_create_session(vault):
    vault.store("session_a", {})

    assert vault.session_count() == 0


def test_concurrent_session_access(vault):
    session_count = 32

    def process_session(index):
        session_id = f"session_{index}"
        original_email = f"user{index}@example.com"

        vault.store(session_id, {
            "<EMAIL_1>": original_email
        })

        masked_text = "Contact <EMAIL_1>"

        return vault.unmask_text(
            masked_text, session_id
        ) == f"Contact {original_email}"

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(
            executor.map(process_session, range(session_count))
        )

    assert all(results)
    assert vault.session_count() == session_count


# ---------- Additional roadmap coverage ----------

def test_unmask_single_placeholder(vault):
    vault.store("session-1", {
        "<EMAIL_1>": "john@acme.com"
    })

    assert vault.unmask_text(
        "Contact <EMAIL_1>.", "session-1"
    ) == "Contact john@acme.com."


def test_unmask_multiple_placeholders(vault):
    vault.store("session-1", {
        "<EMAIL_1>": "john@acme.com",
        "<PHONE_1>": "555-0147"
    })

    assert vault.unmask_text(
        "Email <EMAIL_1> or call <PHONE_1>.",
        "session-1"
    ) == "Email john@acme.com or call 555-0147."


def test_unmask_repeated_placeholder(vault):
    vault.store("session-1", {
        "<EMAIL_1>": "john@acme.com"
    })

    assert vault.unmask_text(
        "<EMAIL_1> again: <EMAIL_1>", "session-1"
    ) == "john@acme.com again: john@acme.com"


def test_wrong_session_never_returns_another_sessions_value(vault):
    vault.store("session-A", {
        "<EMAIL_1>": "alice@x.com"
    })

    result = vault.unmask_text("<EMAIL_1>", "session-B")

    assert result == "<EMAIL_1>"
    assert "alice@x.com" not in result


def test_later_turn_can_unmask_earlier_placeholder(vault):
    vault.store("session-1", {
        "<EMAIL_1>": "john@acme.com"
    })
    vault.store("session-1", {
        "<AWS_KEY_1>": "synthetic-test-key"
    })

    assert vault.unmask_text(
        "As mentioned, <EMAIL_1> was the contact.",
        "session-1"
    ) == "As mentioned, john@acme.com was the contact."


def test_text_without_placeholders_is_unchanged(vault):
    text = "This is ordinary text."

    assert vault.unmask_text(text, "session-1") == text


def test_unmask_empty_string(vault):
    assert vault.unmask_text("", "session-1") == ""


def test_unknown_placeholder_is_unchanged(vault):
    vault.store("session-1", {
        "<EMAIL_1>": "john@acme.com"
    })

    assert vault.unmask_text(
        "Unknown: <UNKNOWN_99>", "session-1"
    ) == "Unknown: <UNKNOWN_99>"


def test_clear_nonexistent_session_does_not_crash(vault):
    vault.clear_session("never-existed")


def test_full_round_trip_with_dlp_engine(engine, vault):
    prompt = (
        "Email john.doe@company.com and "
        "CC jane.smith@client.org about this."
    )

    masked_prompt, entities = engine.redact(prompt)

    mapping = build_mapping_from_entities(entities)
    session_id = "integration-session"

    vault.store(session_id, mapping)

    fake_llm_response = (
        "Drafted an email to <EMAIL_1>, "
        "CC'd to <EMAIL_2>."
    )

    final_response = vault.unmask_text(
        fake_llm_response, session_id
    )

    assert final_response == (
        "Drafted an email to john.doe@company.com, "
        "CC'd to jane.smith@client.org."
    )


def test_full_round_trip_keeps_sessions_isolated(engine, vault):
    prompt_a = "Contact alice@x.com"
    prompt_b = "Contact bob@y.com"

    masked_a, entities_a = engine.redact(prompt_a)
    masked_b, entities_b = engine.redact(prompt_b)

    vault.store(
        "session-A",
        build_mapping_from_entities(entities_a)
    )
    vault.store(
        "session-B",
        build_mapping_from_entities(entities_b)
    )

    assert masked_a == "Contact <EMAIL_1>"
    assert masked_b == "Contact <EMAIL_1>"

    assert vault.unmask_text(
        masked_a, "session-A"
    ) == "Contact alice@x.com"

    assert vault.unmask_text(
        masked_b, "session-B"
    ) == "Contact bob@y.com"
