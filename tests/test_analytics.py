import pytest

from dashboard.analytics import (
    action_distribution,
    hourly_volume,
    top_rule_counts,
)


def test_action_distribution_returns_allowed_and_blocked():
    assert action_distribution(80, 20) == [
        {"action": "ALLOW", "events": 80},
        {"action": "BLOCK", "events": 20},
    ]


def test_top_rule_counts_orders_by_frequency():
    result = top_rule_counts(
        {
            "RULE-C": 3,
            "RULE-A": 10,
            "RULE-B": 5,
        }
    )

    assert result == [
        {"rule_id": "RULE-A", "events": 10},
        {"rule_id": "RULE-B", "events": 5},
        {"rule_id": "RULE-C", "events": 3},
    ]


def test_top_rule_counts_uses_alphabetical_tie_breaking():
    result = top_rule_counts(
        {"RULE-B": 5, "RULE-A": 5}
    )

    assert [row["rule_id"] for row in result] == [
        "RULE-A",
        "RULE-B",
    ]


def test_top_rule_counts_applies_limit():
    result = top_rule_counts(
        {"RULE-A": 10, "RULE-B": 5, "RULE-C": 2},
        limit=2,
    )

    assert len(result) == 2
    assert result[0]["rule_id"] == "RULE-A"


def test_top_rule_counts_rejects_invalid_limit():
    with pytest.raises(ValueError, match="Limit"):
        top_rule_counts({}, limit=0)


def test_hourly_volume_returns_chronological_utc_points():
    result = hourly_volume(
        {
            "2026-11-15T12:00Z": 3,
            "2026-11-15T10:00Z": 8,
            "2026-11-15T11:00Z": 5,
        }
    )

    assert [point["events"] for point in result] == [8, 5, 3]
    assert [point["hour"] for point in result] == [
        "2026-11-15T10:00:00Z",
        "2026-11-15T11:00:00Z",
        "2026-11-15T12:00:00Z",
    ]


def test_hourly_volume_handles_empty_data():
    assert hourly_volume({}) == []



def test_hourly_volume_normalizes_timezone_offsets_to_utc():
    result = hourly_volume(
        {
            "2026-11-15T15:30+05:30": 7,
        }
    )

    assert result == [
        {
            "hour": "2026-11-15T10:00:00Z",
            "events": 7,
        }
    ]


def test_hourly_volume_rejects_timezone_naive_bucket():
    with pytest.raises(ValueError, match="must include a timezone"):
        hourly_volume({"2026-11-15T10:00": 3})


def test_hourly_volume_fills_missing_hours_with_zero():
    result = hourly_volume(
        {
            "2026-11-15T10:00Z": 8,
            "2026-11-15T13:00Z": 3,
        }
    )

    assert result == [
        {"hour": "2026-11-15T10:00:00Z", "events": 8},
        {"hour": "2026-11-15T11:00:00Z", "events": 0},
        {"hour": "2026-11-15T12:00:00Z", "events": 0},
        {"hour": "2026-11-15T13:00:00Z", "events": 3},
    ]
