"""Pure data transformations for SOC dashboard analytics."""

from collections.abc import Mapping
from datetime import datetime, timezone


def action_distribution(
    allowed: int,
    blocked: int,
) -> list[dict[str, int | str]]:
    """Return cumulative ALLOW and BLOCK totals for the pie chart."""
    return [
        {"action": "ALLOW", "events": allowed},
        {"action": "BLOCK", "events": blocked},
    ]


def top_rule_counts(
    rule_counts: Mapping[str, int],
    limit: int = 10,
) -> list[dict[str, int | str]]:
    """Return the most frequently triggered rules."""
    if limit < 1:
        raise ValueError("Limit must be at least 1")

    ranked = sorted(
        rule_counts.items(),
        key=lambda item: (-item[1], item[0]),
    )

    return [
        {"rule_id": rule_id, "events": count}
        for rule_id, count in ranked[:limit]
    ]


def hourly_volume(
    hourly_counts: Mapping[str, int],
) -> list[dict[str, int | str]]:
    """Return continuous hourly counts, including zero-event hours, in UTC."""
    buckets: dict[datetime, int] = {}

    for hour, count in hourly_counts.items():
        parsed = datetime.fromisoformat(
            hour.replace("Z", "+00:00")
        )

        if parsed.tzinfo is None:
            raise ValueError("Hourly bucket must include a timezone")

        utc_hour = parsed.astimezone(timezone.utc).replace(
            minute=0,
            second=0,
            microsecond=0,
        )

        buckets[utc_hour] = buckets.get(utc_hour, 0) + count

    if not buckets:
        return []

    first_hour = min(buckets)
    last_hour = max(buckets)

    points = []
    current_hour = first_hour

    from datetime import timedelta

    while current_hour <= last_hour:
        points.append(
            {
                "hour": current_hour.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "events": buckets.get(current_hour, 0),
            }
        )
        current_hour += timedelta(hours=1)

    return points
