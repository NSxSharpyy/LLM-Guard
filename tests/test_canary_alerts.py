from dashboard.alerts import CanaryTokenAlertTracker


def make_event(
    trace_id="canary-test-1",
    *,
    action="BLOCK",
    rule_id="CANARY-001-TOKEN-EXFILTRATION",
):
    return {
        "timestamp": "2026-11-26T14:30:12.481920Z",
        "trace_id": trace_id,
        "client_ip": "10.0.14.22",
        "user_id": "usr-analyst-04",
        "user_role": "developer",
        "action": action,
        "rule_id": rule_id,
        "ml_score": 1.0,
        "latency_ms": 6.42,
    }


def test_canary_block_creates_alert():
    tracker = CanaryTokenAlertTracker()
    event = make_event()

    assert tracker.ingest([event]) == [event]
    assert list(tracker.alerts) == [event]





def test_canary_block_does_not_create_generic_high_severity_alert():
    from dashboard.alerts import HighSeverityAlertTracker

    tracker = HighSeverityAlertTracker()
    event = make_event()

    assert tracker.ingest([event]) == []
    assert list(tracker.alerts) == []


def test_allow_canary_event_does_not_create_alert():
    tracker = CanaryTokenAlertTracker()

    assert tracker.ingest([make_event(action="ALLOW")]) == []
    assert list(tracker.alerts) == []


def test_generic_dlp_block_does_not_create_canary_alert():
    tracker = CanaryTokenAlertTracker()

    event = make_event(rule_id="DLP-001-SECRET-EXFILTRATION")

    assert tracker.ingest([event]) == []
    assert list(tracker.alerts) == []


def test_unrelated_block_does_not_create_canary_alert():
    tracker = CanaryTokenAlertTracker()

    event = make_event(rule_id="PROMPT_INJECTION_001")

    assert tracker.ingest([event]) == []
    assert list(tracker.alerts) == []


def test_canary_prefix_is_recognized():
    tracker = CanaryTokenAlertTracker()

    event = make_event(rule_id="CANARY-002-OTHER-CANARY-EVENT")

    assert tracker.ingest([event]) == [event]


def test_duplicate_trace_id_is_suppressed():
    tracker = CanaryTokenAlertTracker()
    event = make_event()

    assert tracker.ingest([event]) == [event]
    assert tracker.ingest([event]) == []
    assert len(tracker.alerts) == 1


def test_notifications_are_consumed_only_once():
    tracker = CanaryTokenAlertTracker()
    event = make_event()

    tracker.ingest([event])

    assert tracker.consume_notifications() == [event]
    assert tracker.consume_notifications() == []


def test_clear_dismisses_alerts_but_preserves_deduplication():
    tracker = CanaryTokenAlertTracker()
    event = make_event()

    tracker.ingest([event])
    tracker.clear()

    assert list(tracker.alerts) == []
    assert tracker.consume_notifications() == []
    assert tracker.ingest([event]) == []
