import pytest

from src.security.api_key_store import (
    REDIS_INDEX_KEY,
    REDIS_RECORD_PREFIX,
    ROLE_RPM_LIMITS,
    create_client_api_key,
    hash_api_key,
    list_active_client_api_keys,
    lookup_client_api_key,
)


class FakePipeline:
    def __init__(self, store):
        self.store = store
        self.operations = []

    def hset(self, key, mapping):
        self.operations.append(("hset", key, mapping))
        return self

    def sadd(self, key, value):
        self.operations.append(("sadd", key, value))
        return self

    def execute(self):
        for operation in self.operations:
            if operation[0] == "hset":
                _, key, mapping = operation
                self.store.hashes.setdefault(key, {}).update(mapping)
            elif operation[0] == "sadd":
                _, key, value = operation
                self.store.sets.setdefault(key, set()).add(value)

        return [True] * len(self.operations)


class FakeRedis:
    def __init__(self):
        self.hashes = {}
        self.sets = {}

    def pipeline(self, transaction=True):
        return FakePipeline(self)

    def hgetall(self, key):
        return dict(self.hashes.get(key, {}))

    def smembers(self, key):
        return set(self.sets.get(key, set()))


@pytest.mark.parametrize(
    ("role", "expected_rpm"),
    [
        ("free", 5),
        ("pro", 60),
        ("enterprise", 10000),
    ],
)
def test_generated_key_uses_existing_role_quota(role, expected_rpm):
    store = FakeRedis()

    raw_key, metadata = create_client_api_key(
        "Test Client",
        role,
        redis_client=store,
    )

    assert raw_key.startswith("sk-guard-")
    assert metadata["user_role"] == role
    assert metadata["rpm_limit"] == str(expected_rpm)

    tenant = lookup_client_api_key(raw_key, redis_client=store)

    assert tenant is not None
    assert tenant.user_role == role
    assert tenant.rpm_limit == expected_rpm


def test_raw_key_is_never_stored_in_redis():
    store = FakeRedis()

    raw_key, _ = create_client_api_key(
        "Secure Client",
        "pro",
        redis_client=store,
    )

    digest = hash_api_key(raw_key)

    assert digest in store.sets[REDIS_INDEX_KEY]
    assert REDIS_RECORD_PREFIX + digest in store.hashes

    stored_content = repr(store.hashes) + repr(store.sets)

    assert raw_key not in stored_content
    assert digest not in repr(store.hashes.values())


def test_generated_keys_are_unique():
    store = FakeRedis()

    first_key, _ = create_client_api_key(
        "Client One", "free", redis_client=store
    )
    second_key, _ = create_client_api_key(
        "Client Two", "pro", redis_client=store
    )

    assert first_key != second_key


def test_active_key_list_contains_metadata_not_secrets():
    store = FakeRedis()

    raw_key, metadata = create_client_api_key(
        "Dashboard Client",
        "enterprise",
        redis_client=store,
    )

    records = list_active_client_api_keys(redis_client=store)

    assert len(records) == 1

    record = records[0]

    assert record["client_name"] == "Dashboard Client"
    assert record["user_role"] == "enterprise"
    assert record["rpm_limit"] == "10000"
    assert record["status"] == "Active"
    assert record["key_hint"] == metadata["key_hint"]

    assert raw_key not in repr(records)
    assert "hash" not in record
    assert "secret" not in record


def test_unknown_key_is_not_authenticated():
    store = FakeRedis()

    assert lookup_client_api_key(
        "sk-guard-unknown",
        redis_client=store,
    ) is None


@pytest.mark.parametrize(
    ("client_name", "role", "message"),
    [
        ("", "pro", "Client name is required."),
        ("Valid Client", "administrator", "Unsupported corporate role."),
        ("x" * 81, "free", "Client name cannot exceed 80 characters."),
    ],
)
def test_invalid_key_creation_is_rejected(client_name, role, message):
    store = FakeRedis()

    with pytest.raises(ValueError, match=message):
        create_client_api_key(
            client_name,
            role,
            redis_client=store,
        )


def test_active_key_list_is_empty_without_generated_keys():
    store = FakeRedis()

    assert list_active_client_api_keys(redis_client=store) == []


def test_role_limits_come_from_existing_backend_configuration():
    assert ROLE_RPM_LIMITS == {
        "free": 5,
        "pro": 60,
        "enterprise": 10000,
    }
