import hashlib
import hmac
from dataclasses import dataclass
from fastapi import HTTPException, Request


@dataclass(frozen=True)
class TenantContext:
    """Represents an authenticated API client tenant and its quota policy."""
    tenant_id: str
    tier: str
    rpm_limit: int


def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


# Pre-configured API Key registry (hashed at startup; never store plaintext secrets in logs)
# Default dev/test keys:
#   - Standard Tenant: "sk-guard-dev-tenant-001" (60 RPM)
#   - High-Throughput Benchmark/Enterprise Tenant: "sk-guard-bench-enterprise-999" (10000 RPM)
#   - Restricted Burst-Test Tenant: "sk-guard-ratelimit-test-005" (5 RPM)
DEFAULT_API_KEYS: dict[str, TenantContext] = {
    _hash_key("sk-guard-dev-tenant-001"): TenantContext(
        tenant_id="tenant-dev-001",
        tier="pro",
        rpm_limit=60,
    ),
    _hash_key("sk-guard-bench-enterprise-999"): TenantContext(
        tenant_id="tenant-enterprise-bench",
        tier="enterprise",
        rpm_limit=10000,
    ),
    _hash_key("sk-guard-ratelimit-test-005"): TenantContext(
        tenant_id="tenant-ratelimit-test",
        tier="free",
        rpm_limit=5,
    ),
}


def authenticate_request(request: Request) -> TenantContext:
    """
    Validates the Authorization: Bearer <API_KEY> header using constant-time
    digest comparison to prevent timing side-channel attacks.
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(
            status_code=401,
            detail="Unauthorized: Missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    parts = auth_header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        raise HTTPException(
            status_code=401,
            detail="Unauthorized: Invalid Authorization header format. Expected 'Bearer <API_KEY>'",
            headers={"WWW-Authenticate": "Bearer"},
        )

    raw_token = parts[1].strip()
    incoming_hash = _hash_key(raw_token)

    for stored_hash, tenant_ctx in DEFAULT_API_KEYS.items():
        if hmac.compare_digest(incoming_hash, stored_hash):
            return tenant_ctx

    raise HTTPException(
        status_code=403,
        detail="Forbidden: Invalid or revoked API key",
    )
