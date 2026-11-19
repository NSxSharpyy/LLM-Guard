"""Incremental, validated JSONL reader for proxy latency sidecar metrics."""

import json
import math
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from statistics import fmean
from typing import Any


EXPECTED_KEYS = {
    "timestamp",
    "trace_id",
    "firewall_inspection_ms",
    "upstream_latency_ms",
    "upstream_measurement",
}

MEASUREMENTS = {
    "not_forwarded",
    "unary_full_response",
    "stream_full_response",
    "stream_interrupted",
}


@dataclass(frozen=True)
class LatencySnapshot:
    available: bool
    total_records: int
    malformed: int
    recent_samples: list[dict[str, Any]]
    unary_sample_count: int
    firewall_avg_ms: float | None
    upstream_avg_ms: float | None
    streaming_sample_count: int
    streaming_avg_ms: float | None
    blocked_sample_count: int
    interrupted_sample_count: int
    message: str


class JsonlLatencyTailReader:
    """Tail complete, validated latency records with bounded in-memory history."""

    def __init__(self, path: str | Path, max_samples: int = 500) -> None:
        if max_samples < 1:
            raise ValueError("max_samples must be at least 1")

        self.path = Path(path)
        self.max_samples = max_samples
        self._identity: tuple[int, int] | None = None
        self._offset = 0
        self._pending = b""
        self._samples: deque[dict[str, Any]] = deque(maxlen=max_samples)
        self.total_records = 0
        self.malformed = 0
        self.message = "Waiting for latency metrics."

    def _reset(self, identity: tuple[int, int]) -> None:
        self._identity = identity
        self._offset = 0
        self._pending = b""
        self._samples.clear()
        self.total_records = 0
        self.malformed = 0

    @staticmethod
    def _valid_number(value: Any, *, nullable: bool = False) -> bool:
        if value is None:
            return nullable
        return (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(value)
            and value >= 0
        )

    def _process_line(self, raw_line: bytes) -> dict[str, Any] | None:
        if not raw_line.strip():
            return None

        try:
            record = json.loads(raw_line.decode("utf-8"))
            if not isinstance(record, dict) or set(record) != EXPECTED_KEYS:
                raise ValueError("Unexpected latency record fields")

            timestamp = record["timestamp"]
            if not isinstance(timestamp, str):
                raise ValueError("Timestamp must be a string")
            parsed_timestamp = datetime.fromisoformat(
                timestamp.replace("Z", "+00:00")
            )
            if parsed_timestamp.tzinfo is None:
                raise ValueError("Timestamp must include a timezone")

            if not isinstance(record["trace_id"], str) or not record["trace_id"]:
                raise ValueError("Trace ID must be a non-empty string")

            firewall_ms = record["firewall_inspection_ms"]
            if not self._valid_number(firewall_ms):
                raise ValueError("Invalid firewall inspection latency")

            upstream_ms = record["upstream_latency_ms"]
            if not self._valid_number(upstream_ms, nullable=True):
                raise ValueError("Invalid upstream latency")

            measurement = record["upstream_measurement"]
            if measurement not in MEASUREMENTS:
                raise ValueError("Unknown upstream measurement type")

            if measurement == "not_forwarded" and upstream_ms is not None:
                raise ValueError("Non-forwarded request cannot have upstream latency")

            if measurement != "not_forwarded" and upstream_ms is None:
                raise ValueError("Forwarded request must have upstream latency")

            return record
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            TypeError,
            ValueError,
            OverflowError,
        ):
            self.malformed += 1
            return None

    def poll(self) -> LatencySnapshot:
        """Read newly appended complete records and return the current window."""
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            return self.snapshot(
                available=False,
                message="Latency metrics file does not exist yet.",
            )
        except OSError as exc:
            return self.snapshot(
                available=False,
                message=f"Cannot inspect latency metrics file: {exc}",
            )

        identity = (stat.st_dev, stat.st_ino)
        if identity != self._identity or stat.st_size < self._offset:
            self._reset(identity)

        try:
            with self.path.open("rb") as log_file:
                log_file.seek(self._offset)
                new_data = log_file.read()
                self._offset += len(new_data)
        except OSError as exc:
            return self.snapshot(
                available=False,
                message=f"Cannot read latency metrics file: {exc}",
            )

        data = self._pending + new_data
        complete_lines = data.split(b"\n")
        self._pending = complete_lines.pop()

        for line in complete_lines:
            record = self._process_line(line.rstrip(b"\r"))
            if record is not None:
                self._samples.append(record)
                self.total_records += 1

        self.message = (
            "Waiting for the current latency record to finish."
            if self._pending
            else "Latency metrics read successfully."
        )
        return self.snapshot(available=True, message=self.message)

    def snapshot(
        self,
        *,
        available: bool = True,
        message: str | None = None,
    ) -> LatencySnapshot:
        """Calculate averages from the bounded recent sample window."""
        samples = list(self._samples)

        unary = [
            item for item in samples
            if item["upstream_measurement"] == "unary_full_response"
        ]
        streaming = [
            item for item in samples
            if item["upstream_measurement"] == "stream_full_response"
        ]
        blocked = [
            item for item in samples
            if item["upstream_measurement"] == "not_forwarded"
        ]
        interrupted = [
            item for item in samples
            if item["upstream_measurement"] == "stream_interrupted"
        ]

        return LatencySnapshot(
            available=available,
            total_records=self.total_records,
            malformed=self.malformed,
            recent_samples=samples,
            unary_sample_count=len(unary),
            firewall_avg_ms=(
                fmean(item["firewall_inspection_ms"] for item in unary)
                if unary else None
            ),
            upstream_avg_ms=(
                fmean(item["upstream_latency_ms"] for item in unary)
                if unary else None
            ),
            streaming_sample_count=len(streaming),
            streaming_avg_ms=(
                fmean(item["upstream_latency_ms"] for item in streaming)
                if streaming else None
            ),
            blocked_sample_count=len(blocked),
            interrupted_sample_count=len(interrupted),
            message=message or self.message,
        )
