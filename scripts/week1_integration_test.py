import atexit
import json
import sys
import time
from pathlib import Path

import requests


PROXY_URL = "http://127.0.0.1:6001"
LLM_LOG = Path("logs/mock_llm_received.jsonl")

ORIGINAL_VALUES = [
    "john.doe@example.com",
    "9876543210",
    "4111111111111111",
]

TEST_PROMPT = (
    "Please contact john.doe@example.com, "
    "call 9876543210, and process card "
    "4111111111111111."
)


def fail(message):
    print(f"[FAIL] {message}")
    sys.exit(1)


def main():
    print("=== Week 1 DLP Security Verification ===")

    # Confirm that both services are running.
    try:
        proxy_health = requests.get(
            f"{PROXY_URL}/health", timeout=5
        )
        llm_health = requests.get(
            "http://127.0.0.1:6002/health", timeout=5
        )
        proxy_health.raise_for_status()
        llm_health.raise_for_status()
    except requests.RequestException as exc:
        fail(f"Could not reach both mock services: {exc}")

    print("[PASS] Mock proxy and mock LLM are reachable.")

    # Remember the current log size so older requests
    # cannot affect this test.
    previous_size = LLM_LOG.stat().st_size if LLM_LOG.exists() else 0

    session_id = f"week1-security-test-{int(time.time())}"

    def cleanup_session():
        try:
            cleanup_response = requests.post(
                f"{PROXY_URL}/end-session",
                json={"session_id": session_id},
                timeout=5,
            )
            cleanup_response.raise_for_status()
            print("[INFO] Test session cleaned up.")
        except requests.RequestException as exc:
            print(f"[WARNING] Could not clean up test session: {exc}")

    atexit.register(cleanup_session)

    try:
        response = requests.post(
            f"{PROXY_URL}/chat",
            json={
                "prompt": TEST_PROMPT,
                "session_id": session_id,
            },
            timeout=15,
        )
        response.raise_for_status()
        result = response.json()
    except (requests.RequestException, ValueError) as exc:
        fail(f"Proxy request failed: {exc}")

    print("[PASS] Prompt successfully passed through the proxy.")

    # Verify that the response has been restored.
    completion = result.get("completion", "")

    missing_values = [
        value for value in ORIGINAL_VALUES
        if value not in completion
    ]

    if missing_values:
        fail(
            "Original values were not fully restored in the "
            f"response: {missing_values}"
        )

    print("[PASS] Original values were restored in the response.")

    # Read only log entries written by this request.
    if not LLM_LOG.exists():
        fail("Mock LLM log file was not created.")

    with LLM_LOG.open("r", encoding="utf-8") as log_file:
        log_file.seek(previous_size)
        new_lines = log_file.readlines()

    matching_entries = []

    for line in new_lines:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        if "prompt" in entry:
            matching_entries.append(entry["prompt"])

    if not matching_entries:
        fail("No new upstream prompt was found in the mock LLM log.")

    upstream_prompt = "\n".join(matching_entries)

    # The original sensitive values must never reach the LLM.
    leaked_values = [
        value for value in ORIGINAL_VALUES
        if value in upstream_prompt
    ]

    if leaked_values:
        fail(
            "SECURITY FAILURE: Raw sensitive values reached "
            f"the mock LLM: {leaked_values}"
        )

    print("[PASS] No original sensitive values reached the mock LLM.")

    # Confirm that placeholders were actually sent upstream.
    if "<EMAIL_" not in upstream_prompt:
        fail("Email placeholder was not found upstream.")

    if "<PHONE_" not in upstream_prompt:
        fail("Phone placeholder was not found upstream.")

    if "<CREDIT_CARD_" not in upstream_prompt:
        fail("Credit-card placeholder was not found upstream.")

    print("[PASS] Email, phone, and credit-card placeholders were sent.")
    print("\n=== DAY 7 SECURITY VERIFICATION PASSED ===")


if __name__ == "__main__":
    main()
