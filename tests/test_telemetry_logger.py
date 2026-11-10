import json
from concurrent.futures import ThreadPoolExecutor

import pytest
from jsonschema import ValidationError

from telemetry.telemetry_logger import SecurityTelemetryLogger


def make_event(event_number=1):
    return {
        "timestamp": "2026-11-10T10:00:00Z",
        "trace_id": f"req-{event_number}",
        "client_ip": "192.168.1.100",
        "user_id": "user-101",
        "user_role": "analyst",
        "action": "BLOCK",
        "rule_id": "PROMPT_INJECTION_001",
        "ml_score": 0.96,
        "latency_ms": 12.5,
    }


def read_events(log_path):
    return [
        json.loads(line)
        for line in log_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_valid_event_is_written_as_flat_json(tmp_path):
    log_path = tmp_path / "security_events.jsonl"

    with SecurityTelemetryLogger(log_path=log_path) as telemetry:
        telemetry.log_event(make_event())

    events = read_events(log_path)

    assert len(events) == 1
    assert events[0] == make_event()
    assert set(events[0]) == set(make_event())


def test_invalid_event_is_rejected(tmp_path):
    log_path = tmp_path / "security_events.jsonl"
    invalid_event = make_event()
    invalid_event["action"] = "SUSPICIOUS"

    with SecurityTelemetryLogger(log_path=log_path) as telemetry:
        with pytest.raises(ValidationError):
            telemetry.log_event(invalid_event)

    assert not log_path.exists() or log_path.read_text() == ""


def test_missing_required_field_is_rejected(tmp_path):
    log_path = tmp_path / "security_events.jsonl"
    invalid_event = make_event()
    del invalid_event["trace_id"]

    with SecurityTelemetryLogger(log_path=log_path) as telemetry:
        with pytest.raises(ValidationError):
            telemetry.log_event(invalid_event)


def test_concurrent_events_are_written(tmp_path):
    log_path = tmp_path / "security_events.jsonl"

    with SecurityTelemetryLogger(log_path=log_path) as telemetry:
        with ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(telemetry.log_event, [
                make_event(number) for number in range(100)
            ]))

    events = read_events(log_path)

    assert len(events) == 100
    assert len({event["trace_id"] for event in events}) == 100


def test_log_rotation_creates_rotated_file(tmp_path):
    log_path = tmp_path / "security_events.jsonl"

    # Small threshold to test rotation without writing 100 MB.
    with SecurityTelemetryLogger(
        log_path=log_path,
        rotation="1 KB",
    ) as telemetry:
        for number in range(30):
            event = make_event(number)
            event["rule_id"] = "TEST_RULE_" + ("X" * 100)
            telemetry.log_event(event)

    rotated_files = [
        file_path
        for file_path in tmp_path.iterdir()
        if file_path.is_file() and file_path != log_path
    ]

    assert rotated_files, "Expected Loguru to create a rotated log file"




def test_logger_instances_write_to_separate_files(tmp_path):
    first_path = tmp_path / "first.jsonl"
    second_path = tmp_path / "second.jsonl"

    first = SecurityTelemetryLogger(log_path=first_path)
    second = SecurityTelemetryLogger(log_path=second_path)

    try:
        first.log_event(make_event(1))
        second.log_event(make_event(2))
    finally:
        first.close()
        second.close()

    first_events = read_events(first_path)
    second_events = read_events(second_path)

    assert [event["trace_id"] for event in first_events] == ["req-1"]
    assert [event["trace_id"] for event in second_events] == ["req-2"]

def test_logger_does_not_write_to_stderr(tmp_path, capsys):
    log_path = tmp_path / "security_events.jsonl"

    with SecurityTelemetryLogger(log_path=log_path) as telemetry:
        telemetry.log_event(make_event())

    captured = capsys.readouterr()
    assert captured.err == ""

def test_logging_after_close_is_rejected(tmp_path):
    telemetry = SecurityTelemetryLogger(
        log_path=tmp_path / "security_events.jsonl"
    )
    telemetry.close()

    with pytest.raises(RuntimeError):
        telemetry.log_event(make_event())
