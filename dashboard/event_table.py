"""Sorting and pagination utilities for the SOC security event table."""

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Any


SORTABLE_FIELDS = {
    "Timestamp": "timestamp",
    "Action": "action",
    "ML Score": "ml_score",
    "Latency": "latency_ms",
}


def _sort_key(event: Mapping[str, Any], field: str) -> Any:
    """Return a normalized key for a supported event field."""
    value = event[field]

    if field == "timestamp":
        timestamp = datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )
        return timestamp.astimezone(timezone.utc)

    if field in {"ml_score", "latency_ms"}:
        return float(value)

    return str(value).casefold()


def sort_events(
    events: Sequence[Mapping[str, Any]],
    sort_by: str = "timestamp",
    descending: bool = True,
) -> list[dict[str, Any]]:
    """Return events sorted by an approved field."""
    if sort_by not in SORTABLE_FIELDS.values():
        raise ValueError(f"Unsupported sort field: {sort_by}")

    return sorted(
        (dict(event) for event in events),
        key=lambda event: _sort_key(event, sort_by),
        reverse=descending,
    )


def paginate_events(
    events: Sequence[Mapping[str, Any]],
    page: int = 1,
    page_size: int = 10,
) -> tuple[list[dict[str, Any]], int, int]:
    """
    Return one page of events.

    Returns:
        (page_events, safe_page_number, total_pages)
    """
    if page < 1:
        raise ValueError("Page number must be at least 1")

    if page_size < 1:
        raise ValueError("Page size must be at least 1")

    total_items = len(events)
    total_pages = max(1, (total_items + page_size - 1) // page_size)

    safe_page = min(page, total_pages)
    start = (safe_page - 1) * page_size
    end = start + page_size

    return (
        [dict(event) for event in events[start:end]],
        safe_page,
        total_pages,
    )


def status_badge(action: str) -> str:
    """Return a colour-coded presentation label for a valid SIEM action."""
    badges = {
        "ALLOW": "🟢 ALLOW",
        "BLOCK": "🔴 BLOCK",
    }

    if action not in badges:
        raise ValueError(f"Unsupported SIEM action: {action}")

    return badges[action]
