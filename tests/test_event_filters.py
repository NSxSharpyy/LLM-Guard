from datetime import datetime, timezone

import pytest

from dashboard.event_filters import (
    filter_events,
    severity_for_event,
)
from telemetry.telemetry_logger import HIGH_SEVERITY_SCORE_THRESHOLD


def make_event(
    number,
    *,
    action="ALLOW",
    score=0.5,
    rule="POLICY_ALLOW_001",
    ip="192.0.2.10",
    user="analyst-01",
    timestamp="2026-11-17T10:00:00Z",
):
    return {
        "timestamp": timestamp,
        "trace_id": f"filter-test-{number}",
        "client_ip": ip,
        "user_id": user,
        "user_role": "analyst",
        "action": action,
        "rule_id": rule,
        "ml_score": score,
        "latency_ms": 12.5,
    }


@pytest.fixture
def sample_events():
    return [
        make_event(1),
        make_event(
            2,
            action="BLOCK",
            score=0.96,
            rule="PROMPT_INJECTION_001",
            user="user-admin",
            timestamp="2026-11-17T11:00:00Z",
        ),
        make_event(
            3,
            action="BLOCK",
            score=0.40,
            rule="RL-429-RPM-EXCEEDED",
            ip="192.0.2.20",
            user="user-rate-limit",
            timestamp="2026-11-17T12:00:00Z",
        ),
    ]


def test_no_filters_returns_all_events(sample_events):
    assert filter_events(sample_events) == sample_events


def test_rule_id_filter_is_case_insensitive(sample_events):
    result = filter_events(sample_events, rule_id="prompt_injection")

    assert [event["trace_id"] for event in result] == [
        "filter-test-2"
    ]


def test_client_ip_filter_matches_exact_address(sample_events):
    result = filter_events(sample_events, client_ip="192.0.2.20")

    assert [event["trace_id"] for event in result] == [
        "filter-test-3"
    ]


def test_user_id_filter_is_case_insensitive(sample_events):
    result = filter_events(sample_events, user_id="USER-ADMIN")

    assert [event["trace_id"] for event in result] == [
        "filter-test-2"
    ]


def test_high_severity_uses_existing_policy(sample_events):
    result = filter_events(sample_events, severity="HIGH")

    assert [event["trace_id"] for event in result] == [
        "filter-test-2"
    ]


def test_other_severity_includes_events_outside_high_policy(sample_events):
    result = filter_events(sample_events, severity="OTHER")

    assert [event["trace_id"] for event in result] == [
        "filter-test-1",
        "filter-test-3",
    ]


def test_score_equal_to_threshold_is_not_high():
    event = make_event(
        4,
        action="BLOCK",
        score=HIGH_SEVERITY_SCORE_THRESHOLD,
    )

    assert severity_for_event(event) == "OTHER"


def test_allowed_event_above_threshold_is_not_high():
    event = make_event(5, action="ALLOW", score=0.99)

    assert severity_for_event(event) == "OTHER"


def test_datetime_filter_includes_boundary_events(sample_events):
    start = datetime(2026, 11, 17, 11, 0, tzinfo=timezone.utc)
    end = datetime(2026, 11, 17, 12, 0, tzinfo=timezone.utc)

    result = filter_events(
        sample_events,
        start_datetime=start,
        end_datetime=end,
    )

    assert [event["trace_id"] for event in result] == [
        "filter-test-2",
        "filter-test-3",
    ]


def test_datetime_filter_handles_timezone_offsets(sample_events):
    start = datetime.fromisoformat("2026-11-17T16:30:00+05:30")
    end = datetime.fromisoformat("2026-11-17T17:29:59+05:30")

    result = filter_events(
        sample_events,
        start_datetime=start,
        end_datetime=end,
    )

    assert [event["trace_id"] for event in result] == [
        "filter-test-2"
    ]


def test_combined_filters_work_together(sample_events):
    result = filter_events(
        sample_events,
        rule_id="prompt",
        client_ip="192.0.2.10",
        user_id="admin",
        severity="HIGH",
    )

    assert [event["trace_id"] for event in result] == [
        "filter-test-2"
    ]


def test_invalid_severity_is_rejected(sample_events):
    with pytest.raises(ValueError, match="Unsupported severity"):
        filter_events(sample_events, severity="CRITICAL")


def test_reversed_datetime_range_is_rejected(sample_events):
    with pytest.raises(ValueError, match="must not be after"):
        filter_events(
            sample_events,
            start_datetime=datetime(2026, 11, 18, tzinfo=timezone.utc),
            end_datetime=datetime(2026, 11, 17, tzinfo=timezone.utc),
        )


def test_timezone_naive_datetime_boundary_is_rejected(sample_events):
    with pytest.raises(ValueError, match="must include a timezone"):
        filter_events(
            sample_events,
            start_datetime=datetime(2026, 11, 17, 10, 0),
        )


def test_filtering_does_not_modify_original_events(sample_events):
    original = [dict(event) for event in sample_events]

    filter_events(sample_events, severity="HIGH")

    assert sample_events == original
