"""Asynchronous, schema-validated SIEM and audit event logger."""

import json
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator, FormatChecker
from loguru import logger


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCHEMA_PATH = PROJECT_ROOT / "schemas" / "siem_event.schema.json"
DEFAULT_LOG_PATH = PROJECT_ROOT / "logs" / "security_events.jsonl"
DEFAULT_AUDIT_LOG_PATH = PROJECT_ROOT / "logs" / "audit_security.jsonl"

DEFAULT_ROTATION = "100 MB"
HIGH_SEVERITY_SCORE_THRESHOLD = 0.90


class SecurityTelemetryLogger:
    """Validate and asynchronously write SIEM and high-severity audit events."""

    def __init__(
        self,
        log_path: str | Path = DEFAULT_LOG_PATH,
        schema_path: str | Path = DEFAULT_SCHEMA_PATH,
        rotation: str | int = DEFAULT_ROTATION,
        audit_log_path: str | Path | None = None,
    ) -> None:
        self.log_path = Path(log_path)
        self.schema_path = Path(schema_path)

        self.audit_log_path = (
            Path(audit_log_path)
            if audit_log_path is not None
            else self.log_path.parent / DEFAULT_AUDIT_LOG_PATH.name
        )

        if self.log_path.resolve() == self.audit_log_path.resolve():
            raise ValueError("Normal and audit log paths must be different")

        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)

        with self.schema_path.open("r", encoding="utf-8") as schema_file:
            schema = json.load(schema_file)

        self.validator = Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        )

        # Dedicated Loguru core; does not modify the application's logger.
        # Uses the private Core API, supported by the pinned Loguru 0.7.3.
        self._logger = type(logger)(
            type(logger._core)(),
            *logger._options,
        )

        self._closed = False

        # Main telemetry sink: all valid events, with 100 MB rotation.
        self._log_handler_id = self._logger.add(
            self.log_path,
            level="INFO",
            format="{message}",
            rotation=rotation,
            enqueue=True,
            encoding="utf-8",
            mode="a",
            catch=False,
        )

        # Audit sink: high-severity events only.
        # Append mode preserves existing audit history.
        # Rotation is intentionally disabled for this dedicated file.
        self._audit_handler_id = self._logger.add(
            self.audit_log_path,
            level="INFO",
            format="{message}",
            filter=lambda record: record["extra"].get(
                "audit_high_severity", False
            ),
            enqueue=True,
            encoding="utf-8",
            mode="a",
            catch=False,
        )

    @staticmethod
    def is_high_severity(event: Mapping[str, Any]) -> bool:
        """Classify blocked events with confidence strictly above 0.90."""
        return (
            event["action"] == "BLOCK"
            and event["ml_score"] > HIGH_SEVERITY_SCORE_THRESHOLD
        )

    def log_event(self, event: Mapping[str, Any]) -> None:
        """Validate and asynchronously enqueue a security event."""
        if self._closed:
            raise RuntimeError("Cannot log an event after the logger is closed")

        if not isinstance(event, Mapping):
            raise TypeError("Security event must be a mapping")

        # Preserve the frozen Day 1 SIEM schema.
        self.validator.validate(event)

        # Copy event data before enqueueing.
        event_copy = json.loads(json.dumps(dict(event)))

        serialized_event = json.dumps(
            event_copy,
            separators=(",", ":"),
            ensure_ascii=False,
        )

        high_severity = self.is_high_severity(event_copy)

        # The extra field controls audit filtering. It is not serialized
        # into the event, so the Day 1 schema remains unchanged.
        event_logger = self._logger.bind(
            audit_high_severity=high_severity
        )

        # Queue the same original JSON event to both applicable sinks.
        event_logger.opt(raw=True).info(serialized_event + "\n")

    def close(self) -> None:
        """Flush queued messages and close both file handlers."""
        if self._closed:
            return

        self._logger.complete()
        self._logger.remove(self._log_handler_id)
        self._logger.remove(self._audit_handler_id)
        self._closed = True

    def __enter__(self) -> "SecurityTelemetryLogger":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()
