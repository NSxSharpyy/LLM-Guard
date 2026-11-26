
import time
import pytest

from dlp.redis_vault import RedisVault

@pytest.fixture
def vault():
    instance = RedisVault(host="127.0.0.1", port=6380, db=15, ttl_seconds=60)
    instance._redis.flushdb()
    yield instance
    instance._redis.flushdb()


def test_redis_connection(vault):
    assert vault.ping() is True


def test_store_and_get_mapping(vault):
    mapping = {
        "<EMAIL_1>": "john@example.com",
        "<PHONE_1>": "9876543210",
    }

    vault.store("session1", mapping)

    assert vault.get_mapping("session1") == mapping


def test_session_isolation(vault):
    vault.store("session1", {"<EMAIL_1>": "john@example.com"})
    vault.store("session2", {"<EMAIL_1>": "jane@example.com"})

    assert vault.get_mapping("session1")["<EMAIL_1>"] == "john@example.com"
    assert vault.get_mapping("session2")["<EMAIL_1>"] == "jane@example.com"


def test_unmask_text(vault):
    vault.store("session1", {
        "<EMAIL_1>": "john@example.com"
    })

    result = vault.unmask_text(
        "Contact <EMAIL_1>",
        "session1"
    )

    assert result == "Contact john@example.com"


def test_clear_session(vault):
    vault.store("session1", {"<EMAIL_1>": "john@example.com"})
    vault.store("session2", {"<EMAIL_1>": "jane@example.com"})

    vault.clear_session("session1")

    assert vault.get_mapping("session1") == {}
    assert vault.has_session("session1") is False
    assert vault.has_session("session2") is True


def test_clear_session_removes_all_indexed_keys(vault):
    session_id = "indexed-cleanup-session"

    entities = [
        {
            "entity_type": "EMAIL_ADDRESS",
            "original_value": "alice@example.com",
        },
        {
            "entity_type": "PHONE_NUMBER",
            "original_value": "9876543210",
        },
    ]

    vault.allocate_placeholders(session_id, entities)

    index_key = f"vaultmeta:{session_id}:keys"
    indexed_keys = vault._redis.smembers(index_key)

    assert len(indexed_keys) >= 5

    vault.clear_session(session_id)

    assert vault.get_mapping(session_id) == {}
    assert vault._redis.exists(index_key) == 0

    remaining_keys = (
        list(vault._redis.scan_iter(match=f"vault:{session_id}:*"))
        + list(vault._redis.scan_iter(match=f"vaultmeta:{session_id}:*"))
    )

    assert remaining_keys == []


def test_store_keys_are_removed_by_clear_session(vault):
    session_id = "store-cleanup-session"

    mapping = {
        "<EMAIL_1>": "alice@example.com",
        "<PHONE_1>": "9876543210",
    }

    vault.store(session_id, mapping)

    index_key = f"vaultmeta:{session_id}:keys"

    assert vault._redis.scard(index_key) == 2

    vault.clear_session(session_id)

    assert vault.get_mapping(session_id) == {}
    assert vault._redis.exists(index_key) == 0

def test_session_count(vault):
    vault.store("session1", {"<EMAIL_1>": "john@example.com"})
    vault.store("session2", {"<EMAIL_1>": "jane@example.com"})

    assert vault.session_count() == 2


def test_invalid_ttl():
    with pytest.raises(ValueError):
        RedisVault(ttl_seconds=0)

@pytest.mark.parametrize(
    "entity_type",
    [
        "email_address",
        "EMAIL-ADDRESS",
        "EMAIL ADDRESS",
        "123EMAIL",
        "",
    ],
)
def test_allocate_rejects_invalid_entity_type(
    vault,
    monkeypatch,
    entity_type,
):
    monkeypatch.setattr(vault, "_hmac_secret", b"x" * 32)

    entities = [
        {
            "entity_type": entity_type,
            "original_value": "john@example.com",
        }
    ]

    with pytest.raises(ValueError, match="entity_type"):
        vault.allocate_placeholders("invalid-type-session", entities)

def test_allocate_accepts_valid_custom_entity_type(
    vault,
    monkeypatch,
):
    monkeypatch.setattr(vault, "_hmac_secret", b"x" * 32)

    entities = [
        {
            "entity_type": "PERSON",
            "original_value": "John",
        }
    ]

    placeholders = vault.allocate_placeholders(
        "custom-type-session",
        entities,
    )

    assert placeholders == ["<PERSON_1>"]

def test_entity_types_sharing_placeholder_prefix_use_unique_counters(
    vault,
    monkeypatch,
):
    monkeypatch.setattr(vault, "_hmac_secret", b"x" * 32)

    entities = [
        {
            "entity_type": "AWS_ACCESS_KEY",
            "original_value": "AKIAIOSFODNN7EXAMPLE",
        },
        {
            "entity_type": "AWS_KEY",
            "original_value": "another-access-key",
        },
    ]

    placeholders = vault.allocate_placeholders(
        "shared-prefix-session",
        entities,
    )

    assert placeholders == [
        "<AWS_KEY_1>",
        "<AWS_KEY_2>",
    ]

    mapping = vault.get_mapping("shared-prefix-session")

    assert mapping == {
        "<AWS_KEY_1>": "AKIAIOSFODNN7EXAMPLE",
        "<AWS_KEY_2>": "another-access-key",
    }

def test_invalid_placeholder(vault):
    with pytest.raises(ValueError):
        vault.store("session1", {"INVALID_KEY": "john@example.com"})


def test_invalid_value(vault):
    with pytest.raises(TypeError):
        vault.store("session1", {"<EMAIL_1>": 123})


def test_invalid_session(vault):
    with pytest.raises(ValueError):
        vault.get_mapping("")

def test_mapping_expires_after_ttl(vault):
    vault.ttl_seconds = 2

    vault.store("expiry_session", {
        "<EMAIL_1>": "john@example.com"
    })

    assert vault.get_mapping("expiry_session") != {}

    time.sleep(3)

    assert vault.get_mapping("expiry_session") == {}
    assert vault.has_session("expiry_session") is False


def test_default_ttl_is_900_seconds():
    vault = RedisVault(host="127.0.0.1", port=6380, db=15)
    assert vault.ttl_seconds == 900


def test_store_merges_existing_mapping(vault):
    vault.store("merge-session", {
        "<EMAIL_1>": "john@example.com"
    })

    vault.store("merge-session", {
        "<PHONE_1>": "9876543210"
    })

    assert vault.get_mapping("merge-session") == {
        "<EMAIL_1>": "john@example.com",
        "<PHONE_1>": "9876543210",
    }


def test_unmask_multiple_and_unknown_placeholders(vault):
    vault.store("multi-session", {
        "<EMAIL_1>": "john@example.com",
        "<PHONE_1>": "9876543210",
    })

    result = vault.unmask_text(
        "Email: <EMAIL_1>, Phone: <PHONE_1>, ID: <UNKNOWN_1>",
        "multi-session",
    )

    assert result == (
        "Email: john@example.com, "
        "Phone: 9876543210, "
        "ID: <UNKNOWN_1>"
    )


def test_unmask_empty_text(vault):
    assert vault.unmask_text("", "empty-session") == ""

def test_unmask_empty_text_rejects_invalid_session(vault):
    with pytest.raises(ValueError):
        vault.unmask_text("", "")

def test_independent_vault_instances_share_data(vault):
    second_vault = RedisVault(host="127.0.0.1", port=6380, db=15, ttl_seconds=60)

    vault.store("shared-session", {
        "<EMAIL_1>": "john@example.com"
    })

    assert second_vault.get_mapping("shared-session") == {
        "<EMAIL_1>": "john@example.com"
    }


def test_unmask_wrong_session_does_not_leak(vault):
    vault.store("session-a", {
        "<EMAIL_1>": "john@example.com"
    })

    result = vault.unmask_text(
        "Contact <EMAIL_1>",
        "session-b",
    )

    assert result == "Contact <EMAIL_1>"


from dlp.interceptor import DLPInterceptor


@pytest.fixture
def redis_interceptor():
    instance = DLPInterceptor(redis_db=15, ttl_seconds=60)
    instance._vault._redis.flushdb()

    yield instance

    instance._vault._redis.flushdb()


def test_interceptor_redis_round_trip(redis_interceptor):
    session = "interceptor-round-trip"

    original = "Contact john@example.com for assistance."

    masked, entities = redis_interceptor.redact(original, session)

    assert "<EMAIL_1>" in masked
    assert "john@example.com" not in masked
    assert entities

    restored = redis_interceptor.unmask(masked, session)

    assert restored == original


def test_interceptor_reports_redis_healthy(redis_interceptor):
    assert redis_interceptor.is_vault_healthy() is True


def test_interceptor_unmask_unknown_placeholder(redis_interceptor):
    result = redis_interceptor.unmask(
        "Contact <EMAIL_99>",
        "unknown-session",
    )

    assert result == "Contact <EMAIL_99>"


def test_interceptor_reports_redis_unhealthy(redis_interceptor, monkeypatch):
    def simulate_connection_failure():
        raise ConnectionError("Redis unavailable")

    monkeypatch.setattr(
        redis_interceptor._vault,
        "ping",
        simulate_connection_failure,
    )

    assert redis_interceptor.is_vault_healthy() is False

@pytest.mark.parametrize(
    "session_id",
    ["bad*session", "bad?session", "bad[session", "bad]session"],
)
def test_invalid_session_id_characters(vault, session_id):
    with pytest.raises(ValueError):
        vault.store(session_id, {"<EMAIL_1>": "john@example.com"})


def test_non_string_placeholder_key(vault):
    with pytest.raises(TypeError, match="placeholder must be a string"):
        vault.store("session1", {123: "john@example.com"})


@pytest.mark.parametrize("ttl", [0, -1, 1.5, True])
def test_invalid_ttl_values(ttl):
    with pytest.raises(ValueError):
        RedisVault(ttl_seconds=ttl)

def test_rejects_short_hmac_secret(monkeypatch):
    monkeypatch.setenv("DLP_HMAC_SECRET", "short-secret")

    with pytest.raises(ValueError, match="at least 32 bytes"):
        RedisVault(host="127.0.0.1", port=6380, db=15)

def test_store_refreshes_mapping_ttl(vault):
    vault.ttl_seconds = 3

    vault.store("refresh-session", {"<EMAIL_1>": "john@example.com"})
    time.sleep(2)

    vault.store("refresh-session", {"<PHONE_1>": "9876543210"})

    time.sleep(2)

    mapping = vault.get_mapping("refresh-session")

    assert "<EMAIL_1>" not in mapping
    assert mapping["<PHONE_1>"] == "9876543210"
