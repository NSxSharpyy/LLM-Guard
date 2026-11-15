"""Incremental JSONL reader for LLM-Guard security events."""

import json
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker, ValidationError

from telemetry.telemetry_logger import DEFAULT_SCHEMA_PATH


@dataclass(frozen=True)
class EventSnapshot:
    available: bool
    total: int
    allowed: int
    blocked: int
    malformed: int
    recent_events: list[dict[str, Any]]
    message: str


class JsonlEventTailReader:
    """Read appended, complete and schema-valid JSONL records incrementally."""

    def __init__(
        self,
        path: str | Path,
        schema_path: str | Path = DEFAULT_SCHEMA_PATH,
        max_recent: int = 100,
    ) -> None:
        if max_recent < 1:
            raise ValueError("max_recent must be at least 1")

        self.path = Path(path)
        self.max_recent = max_recent

        schema = json.loads(
            Path(schema_path).read_text(encoding="utf-8")
        )
        self.validator = Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        )

        self._identity: tuple[int, int] | None = None
        self._offset = 0
        self._pending = b""

        self.total = 0
        self.allowed = 0
        self.blocked = 0
        self.malformed = 0
        self.recent_events: deque[dict[str, Any]] = deque(
            maxlen=max_recent
        )

        self.message = "Waiting for security events."

    def _reset_for_new_file(
        self,
        identity: tuple[int, int],
    ) -> None:
        """Reset the reader when the active file is replaced or truncated."""
        self._identity = identity
        self._offset = 0
        self._pending = b""

        self.total = 0
        self.allowed = 0
        self.blocked = 0
        self.malformed = 0
        self.recent_events.clear()

        self.message = "Security log file opened or replaced."

    def _process_line(self, raw_line: bytes) -> None:
        """Parse and validate one complete JSONL record."""
        if not raw_line.strip():
            return

        try:
            event = json.loads(raw_line.decode("utf-8"))
            self.validator.validate(event)

        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            self.malformed += 1
            return

        except ValidationError:
            # Invalid schema records are counted and skipped.
            self.malformed += 1
            return

        self.total += 1

        if event["action"] == "ALLOW":
            self.allowed += 1
        elif event["action"] == "BLOCK":
            self.blocked += 1

        self.recent_events.append(event)

    def poll(self) -> EventSnapshot:
        """Read bytes appended since the previous poll."""
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            return self.snapshot(
                available=False,
                message="Security event log does not exist yet.",
            )
        except OSError as exc:
            return self.snapshot(
                available=False,
                message=f"Cannot inspect security log: {exc}",
            )

        identity = (stat.st_dev, stat.st_ino)

        if (
            identity != self._identity
            or stat.st_size < self._offset
        ):
            self._reset_for_new_file(identity)

        try:
            with self.path.open("rb") as log_file:
                log_file.seek(self._offset)
                new_data = log_file.read()
                self._offset += len(new_data)
        except OSError as exc:
            return self.snapshot(
                available=False,
                message=f"Cannot read security log: {exc}",
            )

        data = self._pending + new_data
        complete_lines = data.split(b"\n")
        self._pending = complete_lines.pop()

        for line in complete_lines:
            self._process_line(line.rstrip(b"\r"))

        if self._pending:
            message = "Waiting for the current JSONL record to finish."
        else:
            message = "Security event log read successfully."

        self.message = message
        return self.snapshot(available=True, message=message)

    def snapshot(
        self,
        available: bool = True,
        message: str | None = None,
    ) -> EventSnapshot:
        """Return the current reader metrics and recent event window."""
        return EventSnapshot(
            available=available,
            total=self.total,
            allowed=self.allowed,
            blocked=self.blocked,
            malformed=self.malformed,
            recent_events=list(self.recent_events),
            message=message or self.message,
        )
