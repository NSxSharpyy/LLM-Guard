"""Trace-correlated latency metrics written to an append-only JSONL sidecar."""

import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class LatencyMetricsLogger:
    """Append latency measurements without changing the frozen SIEM event schema."""

    def __init__(self, log_path: str | Path | None = None) -> None:
        if log_path is None:
            siem_path = Path(
                os.getenv("SIEM_LOG_PATH", "logs/security_events.jsonl")
            )
            log_path = os.getenv(
                "LATENCY_METRICS_PATH",
                str(siem_path.with_name("latency_metrics.jsonl")),
            )

        self.log_path = Path(log_path)
        self._lock = asyncio.Lock()

    async def log_metric(
        self,
        *,
        trace_id: str,
        firewall_inspection_ms: float,
        upstream_latency_ms: float | None,
        upstream_measurement: str,
    ) -> None:
        record: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "trace_id": trace_id,
            "firewall_inspection_ms": round(float(firewall_inspection_ms), 3),
            "upstream_latency_ms": (
                round(float(upstream_latency_ms), 3)
                if upstream_latency_ms is not None
                else None
            ),
            "upstream_measurement": upstream_measurement,
        }

        line = json.dumps(record, allow_nan=False, separators=(",", ":")) + "\n"

        async with self._lock:
            await asyncio.to_thread(self._append_line, line)

    def _append_line(self, line: str) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as log_file:
            log_file.write(line)
            log_file.flush()
