
import pytest

from dlp.masking_policy import MaskingPolicy
from dlp.dlp_engine import DLPEngine
from dlp import DLPInterceptor


@pytest.fixture
def interceptor():
    instance = DLPInterceptor(redis_db=15)
    instance._vault._redis.flushdb()

    yield instance

    instance._vault._redis.flushdb()


# ---------------------------------------------------------
# 1. MASKING POLICY TESTS
# ---------------------------------------------------------

def test_finance_allowed_entities():
    policy = MaskingPolicy()

    assert policy.allowed_entities_for_role("Finance") == {
        "CREDIT_CARD",
        "US_SSN",
    }


def test_developer_allowed_entities():
    policy = MaskingPolicy()

    assert policy.allowed_entities_for_role("Developer") == {
        "AWS_ACCESS_KEY",
        "AWS_SECRET_KEY",
        "JWT_TOKEN",
        "DB_CONNECTION_STRING",
        "PRIVATE_KEY",
        "INTERNAL_IPV4",
    }


def test_general_has_no_unmasked_entities():
    policy = MaskingPolicy()

    assert policy.allowed_entities_for_role("General") == set()


def test_unknown_role_defaults_to_general():
    policy = MaskingPolicy()

    assert policy.allowed_entities_for_role("Unknown") == set()

    assert policy.is_unmasked_for_role(
        "CREDIT_CARD",
        "Unknown",
    ) is False


def test_role_matching_is_case_sensitive():
    policy = MaskingPolicy()

    assert policy.is_unmasked_for_role(
        "CREDIT_CARD",
        "Finance",
    ) is True

    assert policy.is_unmasked_for_role(
        "CREDIT_CARD",
        "finance",
    ) is False


# ---------------------------------------------------------
# 2. ENGINE ROLE-BASED MASKING TESTS
# ---------------------------------------------------------

def test_finance_can_access_credit_card_but_not_email():
    engine = DLPEngine(include_original_value=True)

    original = (
        "Card 4532015112830366 "
        "and email alice@example.com"
    )

    masked, entities = engine.redact(
        original,
        role="Finance",
    )

    assert "4532015112830366" in masked
    assert "<EMAIL_" in masked

    card = next(
        entity for entity in entities
        if entity["entity_type"] == "CREDIT_CARD"
    )

    email = next(
        entity for entity in entities
        if entity["entity_type"] == "EMAIL_ADDRESS"
    )

    assert card["masked"] is False
    assert card["placeholder"] is None

    assert email["masked"] is True
    assert email["placeholder"] is not None


def test_developer_can_access_aws_key_but_not_email():
    engine = DLPEngine(include_original_value=True)

    original = (
        "AWS key AKIAIOSFODNN7EXAMPLE "
        "and email alice@example.com"
    )

    masked, entities = engine.redact(
        original,
        role="Developer",
    )

    assert "AKIAIOSFODNN7EXAMPLE" in masked
    assert "<EMAIL_" in masked

    aws_key = next(
        entity for entity in entities
        if entity["entity_type"] == "AWS_ACCESS_KEY"
    )

    email = next(
        entity for entity in entities
        if entity["entity_type"] == "EMAIL_ADDRESS"
    )

    assert aws_key["masked"] is False
    assert aws_key["placeholder"] is None

    assert email["masked"] is True
    assert email["placeholder"] is not None


@pytest.mark.parametrize(
    "role",
    ["General", "Unknown", None],
)
def test_general_unknown_and_missing_roles_mask_everything(role):
    engine = DLPEngine(include_original_value=True)

    original = (
        "Card 4532015112830366 "
        "and email alice@example.com"
    )

    masked, entities = engine.redact(
        original,
        role=role,
    )

    assert entities

    assert all(
        entity["masked"] is True
        for entity in entities
    )

    assert all(
        entity["placeholder"] is not None
        for entity in entities
    )

    assert "4532015112830366" not in masked
    assert "alice@example.com" not in masked


def test_engine_detects_entities_for_all_roles():
    engine = DLPEngine(include_original_value=True)

    original = "Contact alice@example.com"

    _, general_entities = engine.redact(
        original,
        role="General",
    )

    _, finance_entities = engine.redact(
        original,
        role="Finance",
    )

    assert [
        entity["entity_type"] for entity in general_entities
    ] == [
        entity["entity_type"] for entity in finance_entities
    ]


# ---------------------------------------------------------
# 3. INTERCEPTOR AND REDIS INTEGRATION TESTS
# ---------------------------------------------------------

def test_interceptor_finance_does_not_allocate_for_authorized_entity(
    interceptor,
    monkeypatch,
):
    session = "day17-finance-session"

    def reject_allocation(*args, **kwargs):
        raise AssertionError(
            "Redis allocation should not happen for authorized entities"
        )

    monkeypatch.setattr(
        interceptor._vault,
        "allocate_placeholders",
        reject_allocation,
    )

    original = "Card 4532015112830366"

    masked, entities = interceptor.redact(
        original,
        session,
        role="Finance",
    )

    assert masked == original
    assert entities

    assert all(
        entity["masked"] is False
        for entity in entities
    )

    assert all(
        entity["placeholder"] is None
        for entity in entities
    )

    assert all(
        "original_value" not in entity
        for entity in entities
    )

    assert interceptor.has_session(session) is False


def test_interceptor_allocates_only_masked_entities(
    interceptor,
    monkeypatch,
):
    session = "day17-selective-session"

    original_allocate = (
        interceptor._vault.allocate_placeholders
    )

    allocated_entities = []

    def track_allocation(session_id, entities):
        allocated_entities.extend(entities)

        return original_allocate(
            session_id,
            entities,
        )

    monkeypatch.setattr(
        interceptor._vault,
        "allocate_placeholders",
        track_allocation,
    )

    original = (
        "Card 4532015112830366 "
        "and email alice@example.com"
    )

    masked, entities = interceptor.redact(
        original,
        session,
        role="Finance",
    )

    assert "4532015112830366" in masked
    assert "<EMAIL_" in masked

    assert len(allocated_entities) == 1

    assert allocated_entities[0]["entity_type"] == (
        "EMAIL_ADDRESS"
    )

    assert all(
        "original_value" not in entity
        for entity in entities
    )

    restored = interceptor.unmask(masked, session)

    assert restored == original

    interceptor.end_session(session)


@pytest.mark.parametrize(
    "role",
    ["General", "Unknown", None],
)
def test_interceptor_fails_closed_for_unprivileged_roles(
    interceptor,
    role,
):
    session = f"day17-fail-closed-{role}"

    original = "Contact alice@example.com"

    masked, entities = interceptor.redact(
        original,
        session,
        role=role,
    )

    assert "alice@example.com" not in masked
    assert "<EMAIL_" in masked

    assert entities

    assert all(
        entity["masked"] is True
        for entity in entities
    )

    assert all(
        "original_value" not in entity
        for entity in entities
    )

    assert interceptor.unmask(masked, session) == original

    interceptor.end_session(session)


def test_interceptor_metadata_never_exposes_original_values(
    interceptor,
):
    _, entities = interceptor.redact(
        "Contact alice@example.com",
        "day17-metadata-session",
        role="General",
    )

    assert entities

    for entity in entities:
        assert "original_value" not in entity
        assert "entity_type" in entity
        assert "masked" in entity
        assert "placeholder" in entity
