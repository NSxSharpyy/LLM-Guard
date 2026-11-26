import time
import uuid

import pytest
import redis

from dlp.redis_vault import RedisVault
from scripts.redis_memory_simulation import (
    count_namespace_keys,
    delete_namespace_keys,
)


REDIS_HOST = "127.0.0.1"
REDIS_PORT = 6380
REDIS_DB = 13


@pytest.fixture
def redis_client():
    client = redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        db=REDIS_DB,
        decode_responses=True,
    )

    client.ping()
    client.flushdb()

    yield client

    client.flushdb()
    client.close()


@pytest.fixture
def vault(redis_client):
    return RedisVault(
        host=REDIS_HOST,
        port=REDIS_PORT,
        db=REDIS_DB,
        ttl_seconds=3,
    )


def test_redis_uses_volatile_lru_policy(redis_client):
    policy = redis_client.config_get("maxmemory-policy")

    assert policy["maxmemory-policy"] == "volatile-lru"


def test_redis_has_256_mib_memory_limit(redis_client):
    config = redis_client.config_get("maxmemory")

    assert int(config["maxmemory"]) == 256 * 1024 * 1024


def test_session_mapping_keys_receive_ttl(vault, redis_client):
    session_id = f"day18_ttl_{uuid.uuid4().hex}"

    vault.store(
        session_id,
        {
            "<EMAIL_1>": "synthetic_email_value",
            "<PHONE_1>": "synthetic_phone_value",
        },
    )

    mapping_key = f"vault:{session_id}:<EMAIL_1>"
    index_key = f"vaultmeta:{session_id}:keys"

    assert redis_client.ttl(mapping_key) > 0
    assert redis_client.ttl(index_key) > 0


def test_expired_session_is_removed(vault):
    session_id = f"day18_expiry_{uuid.uuid4().hex}"

    vault.store(
        session_id,
        {"<EMAIL_1>": "synthetic_email_value"},
    )

    assert vault.has_session(session_id) is True

    time.sleep(4)

    assert vault.has_session(session_id) is False
    assert vault.get_mapping(session_id) == {}


def test_targeted_cleanup_preserves_unrelated_sessions(
    vault,
    redis_client,
):
    run_prefix = f"day18_test_{uuid.uuid4().hex}"
    session_id = f"{run_prefix}_session_00001"
    unrelated_session = f"unrelated_{uuid.uuid4().hex}"

    vault.store(
        session_id,
        {
            "<EMAIL_1>": "synthetic_email_value",
            "<PHONE_1>": "synthetic_phone_value",
        },
    )
    vault.store(
        unrelated_session,
        {"<EMAIL_1>": "unrelated_synthetic_value"},
    )

    assert count_namespace_keys(redis_client, run_prefix) == 3

    deleted = delete_namespace_keys(redis_client, run_prefix)

    assert deleted == 3
    assert count_namespace_keys(redis_client, run_prefix) == 0
    assert vault.has_session(unrelated_session) is True
    assert vault.get_mapping(unrelated_session) == {
        "<EMAIL_1>": "unrelated_synthetic_value"
    }
