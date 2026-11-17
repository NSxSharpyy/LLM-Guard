"""Search and filtering utilities for SOC security events."""

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Any

from telemetry.telemetry_logger import HIGH_SEVERITY_SCORE_THRESHOLD


SEVERITY_OPTIONS = ("ALL", "HIGH", "OTHER")


def _parse_utc(value: str) -> datetime:
    """Parse an event timestamp and normalize it to UTC."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))

    if parsed.tzinfo is None:
        raise ValueError("Timestamp must include a timezone")

    return parsed.astimezone(timezone.utc)


def _normalize_bound(value: datetime | None) -> datetime | None:
    """Normalize a filter boundary to UTC."""
    if value is None:
        return None

    if value.tzinfo is None:
        raise ValueError("Date/time filters must include a timezone")

    return value.astimezone(timezone.utc)


def severity_for_event(event: Mapping[str, Any]) -> str:
    """
    Apply the existing telemetry audit policy.

    HIGH means BLOCK with ml_score strictly above the configured threshold.
    OTHER means the event does not satisfy that existing policy.
    """
    if (
        event["action"] == "BLOCK"
        and float(event["ml_score"]) > HIGH_SEVERITY_SCORE_THRESHOLD
    ):
        return "HIGH"

    return "OTHER"


def filter_events(
    events: Sequence[Mapping[str, Any]],
    *,
    rule_id: str = "",
    client_ip: str = "",
    user_id: str = "",
    severity: str = "ALL",
    start_datetime: datetime | None = None,
    end_datetime: datetime | None = None,
) -> list[dict[str, Any]]:
    """Filter events without modifying the original event records."""
    severity = severity.upper().strip()

    if severity not in SEVERITY_OPTIONS:
        raise ValueError(f"Unsupported severity filter: {severity}")

    start_utc = _normalize_bound(start_datetime)
    end_utc = _normalize_bound(end_datetime)

    if start_utc and end_utc and start_utc > end_utc:
        raise ValueError("Start datetime must not be after end datetime")

    rule_query = rule_id.strip().casefold()
    user_query = user_id.strip().casefold()
    ip_query = client_ip.strip()

    filtered = []

    for event in events:
        if rule_query and rule_query not in event["rule_id"].casefold():
            continue

        if ip_query and event["client_ip"] != ip_query:
            continue

        if user_query and user_query not in event["user_id"].casefold():
            continue

        if severity != "ALL" and severity_for_event(event) != severity:
            continue

        if start_utc or end_utc:
            event_time = _parse_utc(event["timestamp"])

            if start_utc and event_time < start_utc:
                continue

            if end_utc and event_time > end_utc:
                continue

        filtered.append(dict(event))

    return filtered
