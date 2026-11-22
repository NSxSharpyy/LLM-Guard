import json
import random
from argparse import ArgumentTypeError
from datetime import datetime, timezone

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from telemetry.mock_telemetry import (
    build_mock_event,
    non_negative_interval,
    positive_count,
    run_generator,
)
from telemetry.telemetry_logger import DEFAULT_SCHEMA_PATH


def read_events(path):
    if not path.exists():
        return []

    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_generated_events_match_frozen_siem_schema():
    schema = json.loads(DEFAULT_SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
    )

    rng = random.Random(42)

    for sequence in range(1, 201):
        event = build_mock_event(sequence, rng)
        validator.validate(event)


def test_event_generation_is_reproducible_with_seed():
    fixed_time = datetime(
        2026, 11, 14, 10, 30, tzinfo=timezone.utc
    )

    first = build_mock_event(1, random.Random(42), fixed_time)
    second = build_mock_event(1, random.Random(42), fixed_time)

    assert first == second


def test_zero_or_negative_sequence_is_rejected():
    with pytest.raises(ValueError):
        build_mock_event(0, random.Random(42))


def test_naive_timestamp_is_rejected():
    naive_time = datetime(2026, 11, 14, 10, 30)

    with pytest.raises(ValueError, match="timezone"):
        build_mock_event(1, random.Random(42), naive_time)


def test_finite_generator_writes_expected_events_and_audit_records(tmp_path):
    normal_path = tmp_path / "security_events.jsonl"
    audit_path = tmp_path / "audit_security.jsonl"

    summary = run_generator(
        count=100,
        interval=0,
        seed=42,
        continuous=False,
        log_path=normal_path,
        audit_log_path=audit_path,
    )

    events = read_events(normal_path)
    audit_events = read_events(audit_path)

    assert len(events) == 100
    assert summary["total"] == 100

    assert summary["allowed"] == sum(
        event["action"] == "ALLOW" for event in events
    )
    assert summary["blocked"] == sum(
        event["action"] == "BLOCK" for event in events
    )

    expected_audit = [
        event for event in events
        if event["action"] == "BLOCK" and event["ml_score"] > 0.90
    ]

    assert audit_events == expected_audit
    assert summary["high_severity"] == len(expected_audit)


def test_positive_count_rejects_zero():
    with pytest.raises(ArgumentTypeError):
        positive_count("0")


def test_negative_interval_is_rejected():
    with pytest.raises(ArgumentTypeError):
        non_negative_interval("-0.1")



def test_generator_runs_use_unique_trace_ids_when_appending(tmp_path):
    normal_path = tmp_path / "security_events.jsonl"
    audit_path = tmp_path / "audit_security.jsonl"

    for _ in range(2):
        run_generator(
            count=5,
            interval=0,
            seed=42,
            continuous=False,
            log_path=normal_path,
            audit_log_path=audit_path,
        )

    events = read_events(normal_path)
    trace_ids = [event["trace_id"] for event in events]

    assert len(events) == 10
    assert len(set(trace_ids)) == 10


def test_non_finite_intervals_are_rejected():
    for value in ("nan", "inf", "-inf"):
        with pytest.raises(ArgumentTypeError):
            non_negative_interval(value)
