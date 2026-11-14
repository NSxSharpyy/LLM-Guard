import asyncio
import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass

from fastapi import HTTPException


@dataclass(frozen=True)
class RateLimitResult:
    limit: int
    remaining: int
    reset_seconds: int


class SlidingWindowRateLimiter:
    """
    Thread/coroutine-safe sliding-window rate limiter tracking per-tenant
    request timestamps over a rolling 60-second window.
    """

    def __init__(self, window_seconds: float = 60.0) -> None:
        self.window_seconds = window_seconds
        self._requests: dict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def check_and_record(self, tenant_id: str, rpm_limit: int) -> RateLimitResult:
        now = time.monotonic()
        window_start = now - self.window_seconds

        async with self._lock:
            timestamps = self._requests[tenant_id]

            # Evict expired timestamps outside the rolling 60s window
            while timestamps and timestamps[0] <= window_start:
                timestamps.popleft()

            current_count = len(timestamps)
            if current_count >= rpm_limit:
                oldest_ts = timestamps[0]
                retry_after = max(1, math.ceil((oldest_ts + self.window_seconds) - now))
                raise HTTPException(
                    status_code=429,
                    detail=f"Too Many Requests: Rate limit of {rpm_limit} RPM exceeded for tenant '{tenant_id}'",
                    headers={
                        "Retry-After": str(retry_after),
                        "X-RateLimit-Limit": str(rpm_limit),
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": str(retry_after),
                    },
                )

            timestamps.append(now)
            remaining = max(0, rpm_limit - len(timestamps))
            reset_sec = (
                max(1, math.ceil((timestamps[0] + self.window_seconds) - now))
                if timestamps
                else int(self.window_seconds)
            )

            return RateLimitResult(
                limit=rpm_limit,
                remaining=remaining,
                reset_seconds=reset_sec,
            )

    async def reset(self) -> None:
        """Clears all tracked windows (used in test isolation)."""
        async with self._lock:
            self._requests.clear()
