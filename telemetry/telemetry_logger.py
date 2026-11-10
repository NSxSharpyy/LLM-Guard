"""Asynchronous, schema-validated SIEM security event logger."""

import json
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator, FormatChecker
from loguru import logger


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCHEMA_PATH = PROJECT_ROOT / "schemas" / "siem_event.schema.json"
DEFAULT_LOG_PATH = PROJECT_ROOT / "logs" / "security_events.jsonl"

DEFAULT_ROTATION = "100 MB"


class SecurityTelemetryLogger:
    """Validate and asynchronously write SIEM events using Loguru."""

    def __init__(
        self,
        log_path: str | Path = DEFAULT_LOG_PATH,
        schema_path: str | Path = DEFAULT_SCHEMA_PATH,
        rotation: str | int = DEFAULT_ROTATION,
    ) -> None:
        self.log_path = Path(log_path)
        self.schema_path = Path(schema_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

        with self.schema_path.open("r", encoding="utf-8") as schema_file:
            schema = json.load(schema_file)

        self.validator = Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        )

        # Use a dedicated Loguru core so telemetry does not write to or
        # modify the application's shared logger handlers.
        # Loguru is pinned to 0.7.3 because this uses its private Core API.
        self._logger = type(logger)(
            type(logger._core)(),
            *logger._options,
        )
        self._closed = False

        self._handler_id = self._logger.add(
            self.log_path,
            level="INFO",
            format="{message}",
            rotation=rotation,
            enqueue=True,
            encoding="utf-8",
            catch=False,
        )

    def log_event(self, event: Mapping[str, Any]) -> None:
        """Validate and enqueue one SIEM security event."""
        if self._closed:
            raise RuntimeError("Cannot log an event after the logger is closed")

        if not isinstance(event, Mapping):
            raise TypeError("Security event must be a mapping")

        # Validate the supplied event against the frozen Day 1 schema.
        self.validator.validate(event)

        # Copy the event so caller mutations cannot change queued log data.
        event_copy = json.loads(json.dumps(dict(event)))

        serialized_event = json.dumps(
            event_copy,
            separators=(",", ":"),
            ensure_ascii=False,
        )

        # Raw mode prevents Loguru from appending its own message formatting.
        # Add exactly one newline to preserve JSON Lines format.
        self._logger.opt(raw=True).info(serialized_event + "\n")

    def close(self) -> None:
        """Flush queued messages and stop this logger's file handler."""
        if self._closed:
            return

        # Wait for queued messages to be processed before removing the sink.
        self._logger.complete()
        self._logger.remove(self._handler_id)
        self._closed = True

    def __enter__(self) -> "SecurityTelemetryLogger":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()
