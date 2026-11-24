
"""
Day 16 tests: Internal infrastructure and secret recognizers.

Tests:
- RFC1918 private IPv4 detection
- Public and malformed IPv4 rejection
- Database connection string detection
- Complete PEM private-key detection
- Multiple private-key detection
- Pre-filter support for infrastructure secrets
- Combined infrastructure configuration detection
"""

import pytest

from dlp.dlp_engine import DLPEngine
from dlp.pre_filter import might_contain_pii


@pytest.fixture(scope="module")
def engine():
    """Create one DLP engine for the test module."""
    return DLPEngine()


# ============================================================
# INTERNAL IPv4 DETECTION
# ============================================================

@pytest.mark.parametrize(
    "address",
    [
        "10.20.30.40",
        "172.16.10.20",
        "192.168.1.100",
    ],
)
def test_redacts_rfc1918_private_ipv4(engine, address):
    masked, entities = engine.redact(
        f"Internal server IP: {address}"
    )

    assert address not in masked
    assert any(
        item["entity_type"] == "INTERNAL_IPV4"
        for item in entities
    )


def test_does_not_redact_public_ipv4(engine):
    address = "8.8.8.8"

    masked, entities = engine.redact(
        f"Public DNS server: {address}"
    )

    assert address in masked
    assert not any(
        item["entity_type"] == "INTERNAL_IPV4"
        for item in entities
    )


def test_rejects_malformed_ipv4(engine):
    address = "999.10.10.10"

    masked, entities = engine.redact(
        f"Invalid server IP: {address}"
    )

    assert address in masked
    assert not any(
        item["entity_type"] == "INTERNAL_IPV4"
        for item in entities
    )


# ============================================================
# DATABASE CONNECTION STRING DETECTION
# ============================================================

@pytest.mark.parametrize(
    "connection_string",
    [
        "postgres://admin:secret@db.example.com/app",
        "postgresql://admin:secret@db.example.com/app",
        "mongodb://admin:secret@db.example.com/app",
        "mongodb+srv://admin:secret@cluster.example.com/app",
        "mysql://admin:secret@db.example.com/app",
        "redis://admin:secret@cache.example.com",
        "amqp://admin:secret@queue.example.com",
    ],
)
def test_redacts_supported_database_connection_strings(
    engine,
    connection_string,
):
    masked, entities = engine.redact(
        f"DATABASE_URL={connection_string}"
    )

    assert connection_string not in masked
    assert any(
        item["entity_type"] == "DB_CONNECTION_STRING"
        for item in entities
    )


# ============================================================
# PRIVATE KEY DETECTION
# ============================================================

def test_redacts_complete_pem_private_key(engine):
    private_key = (
        "-----BEGIN PRIVATE KEY-----\n"
        "FAKEPRIVATEKEYCONTENT123456\n"
        "-----END PRIVATE KEY-----"
    )

    masked, entities = engine.redact(
        f"PRIVATE_KEY=\n{private_key}"
    )

    assert private_key not in masked
    assert "FAKEPRIVATEKEYCONTENT123456" not in masked
    assert any(
        item["entity_type"] == "PRIVATE_KEY"
        for item in entities
    )


def test_detects_multiple_private_keys(engine):
    first_key = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "FAKE_RSA_KEY_CONTENT\n"
        "-----END RSA PRIVATE KEY-----"
    )

    second_key = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "FAKE_OPENSSH_KEY_CONTENT\n"
        "-----END OPENSSH PRIVATE KEY-----"
    )

    masked, entities = engine.redact(
        f"{first_key}\n\n{second_key}"
    )

    private_key_hits = [
        item for item in entities
        if item["entity_type"] == "PRIVATE_KEY"
    ]

    assert len(private_key_hits) == 2
    assert "FAKE_RSA_KEY_CONTENT" not in masked
    assert "FAKE_OPENSSH_KEY_CONTENT" not in masked


# ============================================================
# PRE-FILTER TESTS
# ============================================================

def test_database_connection_scheme_passes_prefilter():
    sample = "postgres://db.internal/app"

    assert might_contain_pii(sample) is True


def test_pem_marker_passes_prefilter():
    sample = "-----BEGIN PRIVATE KEY-----"

    assert might_contain_pii(sample) is True


def test_clean_text_does_not_trigger_prefilter():
    sample = "The application configuration is ready."

    assert might_contain_pii(sample) is False


# ============================================================
# COMBINED INFRASTRUCTURE DETECTION
# ============================================================

def test_detects_multiple_infrastructure_secrets(engine):
    private_key = (
        "-----BEGIN PRIVATE KEY-----\n"
        "FAKECOMBINEDKEYCONTENT\n"
        "-----END PRIVATE KEY-----"
    )

    configuration = (
        "INTERNAL_SERVER=10.20.30.40\n"
        "DATABASE_URL=postgresql://app:secret@db.internal:5432/prod\n"
        f"PRIVATE_KEY={private_key}"
    )

    masked, entities = engine.redact(configuration)

    detected_types = {
        item["entity_type"]
        for item in entities
    }

    assert "INTERNAL_IPV4" in detected_types
    assert "DB_CONNECTION_STRING" in detected_types
    assert "PRIVATE_KEY" in detected_types

    assert "10.20.30.40" not in masked
    assert "postgresql://app:secret@db.internal:5432/prod" not in masked
    assert "FAKECOMBINEDKEYCONTENT" not in masked

# ============================================================
# ADDITIONAL SECURITY EDGE CASES
# ============================================================

@pytest.mark.parametrize(
    "address, expected",
    [
        ("172.15.255.255", False),
        ("172.16.0.0", True),
        ("172.31.255.255", True),
        ("172.32.0.0", False),
    ],
)
def test_rfc1918_172_range_boundaries(engine, address, expected):
    masked, entities = engine.redact(
        f"Server address: {address}"
    )

    detected = any(
        item["entity_type"] == "INTERNAL_IPV4"
        for item in entities
    )

    assert detected is expected

    if expected:
        assert address not in masked
    else:
        assert address in masked


def test_rejects_incomplete_private_key(engine):
    incomplete_key = (
        "-----BEGIN PRIVATE KEY-----\n"
        "FAKEPRIVATEKEYCONTENT123456"
    )

    masked, entities = engine.redact(incomplete_key)

    assert not any(
        item["entity_type"] == "PRIVATE_KEY"
        for item in entities
    )


def test_rejects_mismatched_private_key_markers(engine):
    malformed_key = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "FAKEPRIVATEKEYCONTENT123456\n"
        "-----END PRIVATE KEY-----"
    )

    masked, entities = engine.redact(malformed_key)

    assert not any(
        item["entity_type"] == "PRIVATE_KEY"
        for item in entities
    )
