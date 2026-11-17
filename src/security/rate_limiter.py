import hashlib
import math
import os
from dataclasses import dataclass

from fastapi import HTTPException
from redis.asyncio import Redis
from redis.exceptions import RedisError


@dataclass(frozen=True)
class RateLimitResult:
    limit: int
    remaining: int
    reset_seconds: int


TOKEN_BUCKET_SCRIPT = """
local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill_rate = tonumber(ARGV[2])
local time_parts = redis.call('TIME')
local now = tonumber(time_parts[1]) + (tonumber(time_parts[2]) / 1000000)
local cost = 1

local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
local tokens = tonumber(bucket[1])
local last_refill = tonumber(bucket[2])

if tokens == nil then
    tokens = capacity
    last_refill = now
end

local elapsed = math.max(0, now - last_refill)
tokens = math.min(capacity, tokens + (elapsed * refill_rate))

local allowed = 0
local retry_after = 0

if tokens >= cost then
    tokens = tokens - cost
    allowed = 1
else
    retry_after = math.ceil((cost - tokens) / refill_rate)
end

local reset_seconds = math.ceil((capacity - tokens) / refill_rate)

redis.call('HSET', key,
    'tokens', tokens,
    'last_refill', now
)

redis.call('EXPIRE', key, math.ceil(capacity / refill_rate) + 1)

return {
    allowed,
    math.floor(tokens),
    retry_after,
    reset_seconds
}
"""


class SlidingWindowRateLimiter:
    """
    Redis-backed atomic token bucket rate limiter.

    Maintains check_and_record() compatibility with the existing proxy.
    """

    def __init__(
        self,
        window_seconds: float = 60.0,
        redis_url: str | None = None,
        redis_client: Redis | None = None,
    ) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")

        self.window_seconds = window_seconds
        self.redis_url = redis_url or os.getenv(
            "REDIS_URL", "redis://localhost:6379/0"
        )
        self.redis = redis_client or Redis.from_url(
            self.redis_url,
            decode_responses=True,
        )
        self._owns_client = redis_client is None
        self._script = self.redis.register_script(TOKEN_BUCKET_SCRIPT)

    async def connect(self) -> None:
        """Verify Redis connectivity."""
        await self.redis.ping()

    async def check_limit(
        self,
        api_key: str,
        max_reqs: int = 60,
        window_secs: int = 60,
    ) -> RateLimitResult:
        """Consume one token from the client's Redis token bucket."""

        if not api_key:
            raise ValueError("api_key must not be empty")

        if max_reqs <= 0 or window_secs <= 0:
            raise ValueError("Rate limit and window must be positive")

        client_hash = hashlib.sha256(
            api_key.encode("utf-8")
        ).hexdigest()

        redis_key = f"rate_limiter:bucket:{client_hash}"
        refill_rate = max_reqs / window_secs
        try:
            result = await self._script(
            keys=[redis_key],
            args=[max_reqs, refill_rate],
        )
        except RedisError as exc:
            raise HTTPException(
            status_code=503,
            detail="Rate limiting service unavailable",
            headers={"Retry-After": "5"},
        ) from exc

        allowed = int(result[0])
        remaining = int(result[1])
        retry_after = int(result[2])
        reset_seconds = int(result[3])

        if not allowed:
            raise HTTPException(
                status_code=429,
                detail=(
                    f"Too Many Requests: Rate limit of "
                    f"{max_reqs} RPM exceeded for client"
                ),
                headers={
                    "Retry-After": str(max(1, retry_after)),
                    "X-RateLimit-Limit": str(max_reqs),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(max(1, retry_after)),
                },
            )

        return RateLimitResult(
            limit=max_reqs,
            remaining=remaining,
            reset_seconds=max(1, reset_seconds),
        )

    async def check_and_record(
        self,
        tenant_id: str,
        rpm_limit: int,
    ) -> RateLimitResult:
        """Compatibility wrapper for the existing proxy."""

        return await self.check_limit(
            api_key=tenant_id,
            max_reqs=rpm_limit,
            window_secs=int(self.window_seconds),
        )

    async def reset(self) -> None:
        """Delete only this limiter's Redis keys."""

        keys = [
            key async for key in self.redis.scan_iter(
                match="rate_limiter:bucket:*",
                count=100,
            )
        ]

        if keys:
            await self.redis.delete(*keys)

    async def close(self) -> None:
        """Close the Redis connection pool when owned by this limiter."""

        if self._owns_client:
            await self.redis.aclose()
