"""
Day 7: Live HTTP integration tests.

Requires:
    Mock LLM running on 127.0.0.1:6002
    Mock proxy running on 127.0.0.1:6001

Run with:
    python -m pytest -v tests/test_day7_integration.py
"""

import json
import uuid
from pathlib import Path

import pytest
import requests


PROXY_URL = "http://127.0.0.1:6001"
LLM_URL = "http://127.0.0.1:6002"
LOG_FILE = Path(__file__).resolve().parent.parent / "logs" / "mock_llm_received.jsonl"

EMAIL = "day7.test@example.com"
PHONE = "+1 415-555-0132"
CARD = "4111 1111 1111 1111"


@pytest.fixture(scope="module", autouse=True)
def services_ready():
    """Skip live integration tests if either mock service is unavailable."""

    try:
        proxy_response = requests.get(
            f"{PROXY_URL}/health",
            timeout=2,
        )
        llm_response = requests.get(
            f"{LLM_URL}/health",
            timeout=2,
        )

        proxy_response.raise_for_status()
        llm_response.raise_for_status()

    except requests.RequestException:
        pytest.skip(
            "Start both mock servers before running Day 7 integration tests."
        )


def new_session():
    return f"day7-test-{uuid.uuid4().hex}"


def end_session(session_id):
    response = requests.post(
        f"{PROXY_URL}/end-session",
        json={"session_id": session_id},
        timeout=5,
    )
    assert response.status_code == 200


def read_new_log_entries(previous_size):
    """Read only JSONL entries appended after the given file size."""

    if not LOG_FILE.exists():
        return []

    with LOG_FILE.open("rb") as log_file:
        log_file.seek(previous_size)
        new_content = log_file.read().decode("utf-8")

    return [
        json.loads(line)
        for line in new_content.splitlines()
        if line.strip()
    ]


def current_log_size():
    return LOG_FILE.stat().st_size if LOG_FILE.exists() else 0


def test_proxy_health():
    response = requests.get(f"{PROXY_URL}/health", timeout=5)

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    assert response.json()["service"] == "mock-proxy"


def test_llm_health():
    response = requests.get(f"{LLM_URL}/health", timeout=5)

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    assert response.json()["service"] == "mock-llm"


@pytest.mark.parametrize(
    ("entity_value", "expected_placeholder", "entity_type"),
    [
        (EMAIL, "<EMAIL_1>", "EMAIL_ADDRESS"),
        (PHONE, "<PHONE_1>", "PHONE_NUMBER"),
        (CARD, "<CREDIT_CARD_1>", "CREDIT_CARD"),
    ],
)
def test_entity_is_masked_and_restored(
    entity_value,
    expected_placeholder,
    entity_type,
):
    session_id = new_session()

    try:
        response = requests.post(
            f"{PROXY_URL}/chat",
            json={
                "session_id": session_id,
                "prompt": f"Please check this value: {entity_value}",
            },
            timeout=10,
        )

        assert response.status_code == 200

        result = response.json()

        # The client receives the original value after unmasking.
        assert entity_value in result["completion"]

        # Entity metadata identifies the detected sensitive value.
        assert any(
            entity["entity_type"] == entity_type
            and entity["placeholder"] == expected_placeholder
            for entity in result["entities"]
        )

    finally:
        end_session(session_id)


def test_mock_llm_receives_only_masked_prompt():
    session_id = new_session()
    previous_size = current_log_size()

    try:
        response = requests.post(
            f"{PROXY_URL}/chat",
            json={
                "session_id": session_id,
                "prompt": (
                    f"Email {EMAIL}, phone {PHONE}, card {CARD}"
                ),
            },
            timeout=10,
        )

        assert response.status_code == 200

        entries = read_new_log_entries(previous_size)
        assert entries, "No new mock LLM log entry was created."

        # The proxy should have made exactly one upstream request.
        assert len(entries) == 1

        upstream_prompt = entries[0]["prompt"]

        # Original values must not reach the mock LLM.
        assert EMAIL not in upstream_prompt
        assert PHONE not in upstream_prompt
        assert CARD not in upstream_prompt

        # All three semantic placeholders must reach the mock LLM.
        assert "<EMAIL_1>" in upstream_prompt
        assert "<PHONE_1>" in upstream_prompt
        assert "<CREDIT_CARD_1>" in upstream_prompt

        # The client response must contain the restored values.
        completion = response.json()["completion"]
        assert EMAIL in completion
        assert PHONE in completion
        assert CARD in completion

    finally:
        end_session(session_id)


def test_missing_prompt_is_rejected():
    response = requests.post(
        f"{PROXY_URL}/chat",
        json={"session_id": new_session()},
        timeout=5,
    )

    assert response.status_code == 400
    assert "prompt" in response.json()["error"]


def test_missing_session_id_is_rejected():
    response = requests.post(
        f"{PROXY_URL}/chat",
        json={"prompt": "Hello"},
        timeout=5,
    )

    assert response.status_code == 400
    assert "session_id" in response.json()["error"]


def test_invalid_json_is_rejected():
    response = requests.post(
        f"{PROXY_URL}/chat",
        data="not-json",
        headers={"Content-Type": "application/json"},
        timeout=5,
    )

    assert response.status_code == 400
    assert "JSON" in response.json()["error"]


def test_session_cleanup():
    session_id = new_session()

    response = requests.post(
        f"{PROXY_URL}/chat",
        json={
            "session_id": session_id,
            "prompt": f"Contact {EMAIL}",
        },
        timeout=10,
    )

    assert response.status_code == 200

    cleanup_response = requests.post(
        f"{PROXY_URL}/end-session",
        json={"session_id": session_id},
        timeout=5,
    )

    assert cleanup_response.status_code == 200
    assert cleanup_response.json()["session_active"] is False
