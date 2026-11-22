import pytest

from dashboard.alerts import HighSeverityAlertTracker
from telemetry.telemetry_logger import HIGH_SEVERITY_SCORE_THRESHOLD


def make_event(
    trace_id="alert-test-1",
    *,
    action="BLOCK",
    score=0.96,
):
    return {
        "timestamp": "2026-11-18T10:00:00Z",
        "trace_id": trace_id,
        "client_ip": "192.0.2.10",
        "user_id": "analyst-01",
        "user_role": "analyst",
        "action": action,
        "rule_id": "PROMPT_INJECTION_001",
        "ml_score": score,
        "latency_ms": 12.5,
    }


def test_new_high_severity_block_creates_alert():
    tracker = HighSeverityAlertTracker()
    event = make_event()

    result = tracker.ingest([event])

    assert result == [event]
    assert list(tracker.alerts) == [event]


def test_allow_event_never_creates_attack_alert():
    tracker = HighSeverityAlertTracker()

    result = tracker.ingest([
        make_event(action="ALLOW", score=0.99)
    ])

    assert result == []
    assert list(tracker.alerts) == []


def test_block_at_exact_threshold_does_not_alert():
    tracker = HighSeverityAlertTracker()

    result = tracker.ingest([
        make_event(score=HIGH_SEVERITY_SCORE_THRESHOLD)
    ])

    assert result == []
    assert list(tracker.alerts) == []


def test_block_below_threshold_does_not_alert():
    tracker = HighSeverityAlertTracker()

    result = tracker.ingest([make_event(score=0.89)])

    assert result == []


def test_duplicate_trace_id_is_suppressed():
    tracker = HighSeverityAlertTracker()
    event = make_event()

    assert tracker.ingest([event]) == [event]
    assert tracker.ingest([event]) == []
    assert len(tracker.alerts) == 1


def test_duplicate_trace_id_in_same_batch_is_suppressed():
    tracker = HighSeverityAlertTracker()
    event = make_event()

    result = tracker.ingest([event, event])

    assert result == [event]
    assert len(tracker.alerts) == 1


def test_multiple_alerts_are_kept_newest_first():
    tracker = HighSeverityAlertTracker()

    events = [
        make_event("alert-1"),
        make_event("alert-2"),
        make_event("alert-3"),
    ]

    tracker.ingest(events)

    assert [
        event["trace_id"] for event in tracker.alerts
    ] == ["alert-3", "alert-2", "alert-1"]


def test_visible_alert_history_is_bounded():
    tracker = HighSeverityAlertTracker(max_alerts=2)

    tracker.ingest([
        make_event("alert-1"),
        make_event("alert-2"),
        make_event("alert-3"),
    ])

    assert [
        event["trace_id"] for event in tracker.alerts
    ] == ["alert-3", "alert-2"]


def test_notifications_are_consumed_only_once():
    tracker = HighSeverityAlertTracker()
    event = make_event()

    tracker.ingest([event])

    assert tracker.consume_notifications() == [event]
    assert tracker.consume_notifications() == []


def test_clear_dismisses_alerts_but_preserves_deduplication():
    tracker = HighSeverityAlertTracker()
    event = make_event()

    tracker.ingest([event])
    tracker.clear()

    assert list(tracker.alerts) == []
    assert tracker.consume_notifications() == []
    assert tracker.ingest([event]) == []


def test_invalid_tracker_limits_are_rejected():
    with pytest.raises(ValueError):
        HighSeverityAlertTracker(max_alerts=0)

    with pytest.raises(ValueError):
        HighSeverityAlertTracker(max_seen=0)


def test_reader_and_tracker_alert_only_new_high_severity_events(tmp_path):
    import json

    from dashboard.event_reader import JsonlEventTailReader

    path = tmp_path / "security_events.jsonl"
    historical_event = make_event("historical-attack")

    path.write_text(
        json.dumps(historical_event) + "\n",
        encoding="utf-8",
    )

    reader = JsonlEventTailReader(path)
    tracker = HighSeverityAlertTracker()

    initial = reader.poll()
    assert initial.new_events == []
    assert tracker.ingest(initial.new_events) == []

    new_event = make_event("new-attack")

    with path.open("a", encoding="utf-8") as file:
        file.write(json.dumps(new_event) + "\n")

    update = reader.poll()

    assert update.new_events == [new_event]
    assert tracker.ingest(update.new_events) == [new_event]

    next_update = reader.poll()

    assert next_update.new_events == []
    assert tracker.ingest(next_update.new_events) == []

    assert tracker.consume_notifications() == [new_event]
    assert tracker.consume_notifications() == []
