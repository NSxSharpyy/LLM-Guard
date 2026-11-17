import asyncio
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

DEFAULT_SIEM_LOG_PATH = "logs/security_events.jsonl"


def generate_trace_id() -> str:
    """Generates a universal UUIDv4 trace identifier prefixed with 'trc-'."""
    return f"trc-{uuid.uuid4()}"


class SIEMEventLogger:
    """
    Async-safe JSONL telemetry producer emitting Day 1 frozen schema events
    to logs/security_events.jsonl for real-time SOC dashboard consumption.
    """

    def __init__(self, log_path: str | None = None) -> None:
        self._explicit_path = log_path
        self._lock = asyncio.Lock()

    @property
    def log_path(self) -> Path:
        raw_path = self._explicit_path or os.getenv("SIEM_LOG_PATH", DEFAULT_SIEM_LOG_PATH)
        return Path(raw_path)

    async def log_event(
        self,
        *,
        trace_id: str,
        client_ip: str,
        user_id: str,
        user_role: str,
        action: Literal["ALLOW", "BLOCK"],
        rule_id: str,
        ml_score: float = 0.0,
        latency_ms: float = 0.0,
    ) -> dict[str, str | float]:
        """Appends a single 9-field schema-compliant JSONL record."""
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

        # Exact 9-field frozen schema (additionalProperties: false compliant)
        event: dict[str, str | float] = {
            "timestamp": ts,
            "trace_id": trace_id,
            "client_ip": client_ip,
            "user_id": user_id,
            "user_role": user_role,
            "action": action,
            "rule_id": rule_id,
            "ml_score": float(ml_score),
            "latency_ms": round(float(latency_ms), 2),
        }

        line = json.dumps(event, separators=(",", ":")) + "\n"
        target_file = self.log_path

        async with self._lock:
            target_file.parent.mkdir(parents=True, exist_ok=True)
            with target_file.open("a", encoding="utf-8") as f:
                f.write(line)
                f.flush()

        return event
