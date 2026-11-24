"""Redis-backed storage for dynamically generated client API keys."""

import hashlib
import os
import secrets
import uuid
from datetime import datetime, timezone
from typing import Any

from redis import Redis

from src.security.auth import DEFAULT_API_KEYS, TenantContext


REDIS_INDEX_KEY = "llm_guard:api_keys:index"
REDIS_RECORD_PREFIX = "llm_guard:api_keys:record:"

ROLE_RPM_LIMITS = {
    tenant.user_role: tenant.rpm_limit
    for tenant in DEFAULT_API_KEYS.values()
}

_redis_client: Redis | None = None
_redis_url: str | None = None


def get_redis_client() -> Redis | None:
    """Return the shared Redis client configured through REDIS_URL."""
    global _redis_client, _redis_url

    url = os.getenv("REDIS_URL")
    if not url:
        return None

    if _redis_client is None or _redis_url != url:
        if _redis_client is not None:
            _redis_client.close()

        _redis_client = Redis.from_url(
            url,
            decode_responses=True,
            socket_connect_timeout=3,
            socket_timeout=3,
        )
        _redis_url = url

    return _redis_client


def close_redis_client() -> None:
    """Close the cached Redis connection pool."""
    global _redis_client, _redis_url

    if _redis_client is not None:
        _redis_client.close()

    _redis_client = None
    _redis_url = None


def hash_api_key(raw_key: str) -> str:
    """Return the SHA-256 digest of an API key."""
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def create_client_api_key(
    client_name: str,
    user_role: str,
    redis_client: Any | None = None,
) -> tuple[str, dict[str, str]]:
    """Generate a client key and persist only its hash and metadata."""
    name = client_name.strip()

    if not name:
        raise ValueError("Client name is required.")

    if len(name) > 80:
        raise ValueError("Client name cannot exceed 80 characters.")

    if user_role not in ROLE_RPM_LIMITS:
        raise ValueError("Unsupported corporate role.")

    client = redis_client or get_redis_client()
    if client is None:
        raise RuntimeError("REDIS_URL is not configured.")

    raw_key = "sk-guard-" + secrets.token_urlsafe(32)
    digest = hash_api_key(raw_key)

    key_id = uuid.uuid4().hex
    tenant_id = f"tenant-{uuid.uuid4().hex}"
    user_id = f"usr-{uuid.uuid4().hex}"
    created_at = datetime.now(timezone.utc).isoformat()

    metadata = {
        "key_id": key_id,
        "client_name": name,
        "tenant_id": tenant_id,
        "user_id": user_id,
        "user_role": user_role,
        "rpm_limit": str(ROLE_RPM_LIMITS[user_role]),
        "created_at": created_at,
        "key_hint": f"••••{raw_key[-4:]}",
    }

    record_key = REDIS_RECORD_PREFIX + digest

    pipeline = client.pipeline(transaction=True)
    pipeline.hset(record_key, mapping=metadata)
    pipeline.sadd(REDIS_INDEX_KEY, digest)
    pipeline.execute()

    return raw_key, metadata


def lookup_client_api_key(
    raw_key: str,
    redis_client: Any | None = None,
) -> TenantContext | None:
    """Resolve a generated API key without storing or retrieving its secret."""
    client = redis_client or get_redis_client()
    if client is None:
        return None

    digest = hash_api_key(raw_key)
    record = client.hgetall(REDIS_RECORD_PREFIX + digest)

    if not record:
        return None

    return TenantContext(
        tenant_id=record["tenant_id"],
        user_id=record["user_id"],
        user_role=record["user_role"],
        rpm_limit=int(record["rpm_limit"]),
    )


def list_active_client_api_keys(
    redis_client: Any | None = None,
) -> list[dict[str, str]]:
    """Return active key metadata without exposing API key hashes or secrets."""
    client = redis_client or get_redis_client()
    if client is None:
        return []

    digests = client.smembers(REDIS_INDEX_KEY)
    records: list[dict[str, str]] = []

    for digest in digests:
        record = client.hgetall(REDIS_RECORD_PREFIX + digest)
        if not record:
            continue

        records.append({
            "key_id": record.get("key_id", ""),
            "client_name": record.get("client_name", ""),
            "key_hint": record.get("key_hint", ""),
            "user_role": record.get("user_role", ""),
            "rpm_limit": record.get("rpm_limit", ""),
            "created_at": record.get("created_at", ""),
            "status": "Active",
        })

    return sorted(
        records,
        key=lambda item: item["created_at"],
        reverse=True,
    )
