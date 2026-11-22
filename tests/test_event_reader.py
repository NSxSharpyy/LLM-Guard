import json

from dashboard.event_reader import JsonlEventTailReader


def make_event(number=1, action="ALLOW"):
    return {
        "timestamp": "2026-11-15T10:00:00Z",
        "trace_id": f"reader-test-{number}",
        "client_ip": "192.0.2.10",
        "user_id": "user-1001",
        "user_role": "analyst",
        "action": action,
        "rule_id": (
            "POLICY_ALLOW_001"
            if action == "ALLOW"
            else "PROMPT_INJECTION_001"
        ),
        "ml_score": 0.5 if action == "ALLOW" else 0.96,
        "latency_ms": 12.5,
    }


def append_event(path, event, newline=True):
    with path.open("ab") as file:
        payload = json.dumps(event).encode("utf-8")
        file.write(payload + (b"\n" if newline else b""))


def test_reader_loads_existing_events_and_metrics(tmp_path):
    path = tmp_path / "security_events.jsonl"

    append_event(path, make_event(1, "ALLOW"))
    append_event(path, make_event(2, "BLOCK"))

    reader = JsonlEventTailReader(path)
    result = reader.poll()

    assert result.available
    assert result.total == 2
    assert result.allowed == 1
    assert result.blocked == 1
    assert len(result.recent_events) == 2


def test_reader_detects_newly_appended_events(tmp_path):
    path = tmp_path / "security_events.jsonl"
    append_event(path, make_event(1))

    reader = JsonlEventTailReader(path)

    assert reader.poll().total == 1

    append_event(path, make_event(2, "BLOCK"))

    result = reader.poll()

    assert result.total == 2
    assert result.allowed == 1
    assert result.blocked == 1


def test_reader_does_not_double_count_existing_lines(tmp_path):
    path = tmp_path / "security_events.jsonl"
    append_event(path, make_event(1))

    reader = JsonlEventTailReader(path)

    first = reader.poll()
    second = reader.poll()

    assert first.total == second.total == 1


def test_reader_waits_for_partial_jsonl_line(tmp_path):
    path = tmp_path / "security_events.jsonl"
    event = json.dumps(make_event(1)).encode("utf-8")

    path.write_bytes(event[:20])

    reader = JsonlEventTailReader(path)

    assert reader.poll().total == 0

    with path.open("ab") as file:
        file.write(event[20:] + b"\n")

    result = reader.poll()

    assert result.total == 1
    assert result.malformed == 0


def test_reader_skips_malformed_records(tmp_path):
    path = tmp_path / "security_events.jsonl"

    path.write_bytes(
        b'not-json\n'
        + json.dumps(make_event()).encode("utf-8")
        + b'\n'
    )

    reader = JsonlEventTailReader(path)
    result = reader.poll()

    assert result.total == 1
    assert result.malformed == 1


def test_reader_skips_schema_invalid_events(tmp_path):
    path = tmp_path / "security_events.jsonl"
    event = make_event()
    event["action"] = "SUSPICIOUS"

    append_event(path, event)

    result = JsonlEventTailReader(path).poll()

    assert result.total == 0
    assert result.malformed == 1


def test_reader_handles_missing_log_file(tmp_path):
    reader = JsonlEventTailReader(
        tmp_path / "not-created-yet.jsonl"
    )

    result = reader.poll()

    assert not result.available
    assert result.total == 0
    assert "does not exist" in result.message


def test_reader_limits_recent_event_window(tmp_path):
    path = tmp_path / "security_events.jsonl"

    for number in range(1, 6):
        append_event(path, make_event(number))

    reader = JsonlEventTailReader(path, max_recent=3)
    result = reader.poll()

    assert result.total == 5
    assert len(result.recent_events) == 3
    assert result.recent_events[-1]["trace_id"] == "reader-test-5"


def test_reader_resets_after_log_truncation(tmp_path):
    path = tmp_path / "security_events.jsonl"

    append_event(path, make_event(1))
    append_event(path, make_event(2, "BLOCK"))

    reader = JsonlEventTailReader(path)
    assert reader.poll().total == 2

    # Truncate and replace the active log with a new event.
    path.write_text(
        json.dumps(make_event(3, "BLOCK")) + "\n",
        encoding="utf-8",
    )

    result = reader.poll()

    assert result.total == 1
    assert result.allowed == 0
    assert result.blocked == 1
    assert len(result.recent_events) == 1


def test_reader_resets_after_log_file_replacement(tmp_path):
    path = tmp_path / "security_events.jsonl"
    replacement = tmp_path / "replacement.jsonl"

    append_event(path, make_event(1))
    reader = JsonlEventTailReader(path)

    assert reader.poll().total == 1

    append_event(replacement, make_event(2, "BLOCK"))
    replacement.replace(path)

    result = reader.poll()

    assert result.total == 1
    assert result.allowed == 0
    assert result.blocked == 1
    assert result.recent_events[0]["trace_id"] == "reader-test-2"


def test_reader_aggregates_events_by_rule_and_hour(tmp_path):
    path = tmp_path / "security_events.jsonl"

    append_event(path, make_event(1, "ALLOW"))
    append_event(path, make_event(2, "BLOCK"))
    append_event(path, make_event(3, "BLOCK"))

    result = JsonlEventTailReader(path).poll()

    assert result.rule_counts == {
        "POLICY_ALLOW_001": 1,
        "PROMPT_INJECTION_001": 2,
    }
    assert result.hourly_counts == {
        "2026-11-15T10:00Z": 3,
    }


def test_reader_normalizes_timezone_for_hourly_aggregation(tmp_path):
    path = tmp_path / "security_events.jsonl"

    utc_event = make_event(1)
    offset_event = make_event(2, "BLOCK")
    offset_event["timestamp"] = "2026-11-15T15:30:00+05:30"

    append_event(path, utc_event)
    append_event(path, offset_event)

    result = JsonlEventTailReader(path).poll()

    assert result.hourly_counts == {
        "2026-11-15T10:00Z": 2,
    }


def test_reader_updates_aggregations_for_appended_events(tmp_path):
    path = tmp_path / "security_events.jsonl"
    reader = JsonlEventTailReader(path)

    append_event(path, make_event(1, "ALLOW"))
    first = reader.poll()

    assert first.rule_counts["POLICY_ALLOW_001"] == 1

    append_event(path, make_event(2, "BLOCK"))
    second = reader.poll()

    assert second.rule_counts == {
        "POLICY_ALLOW_001": 1,
        "PROMPT_INJECTION_001": 1,
    }
    assert second.hourly_counts["2026-11-15T10:00Z"] == 2


def test_reader_resets_aggregations_after_truncation(tmp_path):
    path = tmp_path / "security_events.jsonl"

    append_event(path, make_event(1, "ALLOW"))
    append_event(path, make_event(2, "BLOCK"))

    reader = JsonlEventTailReader(path)
    assert reader.poll().total == 2

    path.write_text(
        json.dumps(make_event(3, "BLOCK")) + "\n",
        encoding="utf-8",
    )

    result = reader.poll()

    assert result.rule_counts == {
        "PROMPT_INJECTION_001": 1,
    }
    assert result.hourly_counts == {
        "2026-11-15T10:00Z": 1,
    }


def test_reader_does_not_aggregate_malformed_records(tmp_path):
    path = tmp_path / "security_events.jsonl"
    path.write_bytes(b'not-json\n')

    result = JsonlEventTailReader(path).poll()

    assert result.total == 0
    assert result.malformed == 1
    assert result.rule_counts == {}
    assert result.hourly_counts == {}


def test_reader_returns_only_newly_appended_events(tmp_path):
    path = tmp_path / "security_events.jsonl"
    append_event(path, make_event(1, "BLOCK"))

    reader = JsonlEventTailReader(path)

    initial = reader.poll()
    assert initial.total == 1
    assert initial.new_events == []

    append_event(path, make_event(2, "BLOCK"))

    appended = reader.poll()
    assert [event["trace_id"] for event in appended.new_events] == [
        "reader-test-2"
    ]

    assert reader.poll().new_events == []


def test_reader_exposes_event_only_after_complete_jsonl_line(tmp_path):
    path = tmp_path / "security_events.jsonl"
    append_event(path, make_event(1, "ALLOW"))

    reader = JsonlEventTailReader(path)
    reader.poll()

    event_bytes = json.dumps(make_event(2, "BLOCK")).encode("utf-8")
    split_at = len(event_bytes) // 2

    with path.open("ab") as file:
        file.write(event_bytes[:split_at])

    partial = reader.poll()
    assert partial.new_events == []

    with path.open("ab") as file:
        file.write(event_bytes[split_at:] + b"\n")

    completed = reader.poll()
    assert [event["trace_id"] for event in completed.new_events] == [
        "reader-test-2"
    ]


def test_reader_suppresses_existing_records_after_file_replacement(tmp_path):
    path = tmp_path / "security_events.jsonl"
    replacement = tmp_path / "replacement.jsonl"

    append_event(path, make_event(1, "BLOCK"))
    reader = JsonlEventTailReader(path)
    reader.poll()

    append_event(replacement, make_event(2, "BLOCK"))
    replacement.replace(path)

    replaced = reader.poll()
    assert replaced.total == 1
    assert replaced.new_events == []

    append_event(path, make_event(3, "BLOCK"))

    appended = reader.poll()
    assert [event["trace_id"] for event in appended.new_events] == [
        "reader-test-3"
    ]
