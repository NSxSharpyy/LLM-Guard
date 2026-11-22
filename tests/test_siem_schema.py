import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]

SCHEMA_PATH = ROOT / "schemas" / "siem_event.schema.json"
SAMPLE_PATH = ROOT / "schemas" / "sample_event.json"


@pytest.fixture
def validator():
    schema = json.loads(SCHEMA_PATH.read_text())

    Draft202012Validator.check_schema(schema)

    return Draft202012Validator(
        schema,
        format_checker=FormatChecker()
    )


@pytest.fixture
def valid_event():
    return json.loads(SAMPLE_PATH.read_text())


def test_schema_is_valid(validator):
    assert validator.schema["type"] == "object"


def test_valid_event_is_accepted(validator, valid_event):
    assert validator.is_valid(valid_event)


def test_missing_required_field_is_rejected(validator, valid_event):
    del valid_event["trace_id"]

    assert not validator.is_valid(valid_event)


def test_invalid_action_is_rejected(validator, valid_event):
    valid_event["action"] = "DELETE"

    assert not validator.is_valid(valid_event)


def test_invalid_ml_score_is_rejected(validator, valid_event):
    valid_event["ml_score"] = 1.5

    assert not validator.is_valid(valid_event)


def test_negative_latency_is_rejected(validator, valid_event):
    valid_event["latency_ms"] = -5

    assert not validator.is_valid(valid_event)


def test_invalid_ip_is_rejected(validator, valid_event):
    valid_event["client_ip"] = "999.999.999.999"

    assert not validator.is_valid(valid_event)


def test_extra_field_is_rejected(validator, valid_event):
    valid_event["unexpected_field"] = "malicious"

    assert not validator.is_valid(valid_event)


def test_invalid_timestamp_is_rejected(validator, valid_event):
    valid_event["timestamp"] = "not-a-timestamp"

    assert not validator.is_valid(valid_event)
