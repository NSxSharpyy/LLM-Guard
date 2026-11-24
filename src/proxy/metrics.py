import asyncio
from collections import Counter
from typing import Any


class GuardRuntimeMetrics:
    """In-memory async-safe runtime counters for LLM-Guard proxy decisions."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self.total_requests: int = 0
        self.allowed_requests: int = 0
        self.blocked_requests: int = 0
        self.pii_redacted_requests: int = 0
        self.blocks_by_stage: Counter[str] = Counter()

    async def record_allow(self, pii_redacted: bool = False) -> None:
        async with self._lock:
            self.total_requests += 1
            self.allowed_requests += 1
            if pii_redacted:
                self.pii_redacted_requests += 1

    async def record_block(self, stage: str) -> None:
        async with self._lock:
            self.total_requests += 1
            self.blocked_requests += 1
            self.blocks_by_stage[stage] += 1

    async def snapshot(self) -> dict[str, Any]:
        async with self._lock:
            return {
                "total_requests": self.total_requests,
                "allowed_requests": self.allowed_requests,
                "blocked_requests": self.blocked_requests,
                "pii_redacted_requests": self.pii_redacted_requests,
                "blocks_by_stage": dict(self.blocks_by_stage),
            }

    async def reset(self) -> None:
        async with self._lock:
            self.total_requests = 0
            self.allowed_requests = 0
            self.blocked_requests = 0
            self.pii_redacted_requests = 0
            self.blocks_by_stage.clear()
