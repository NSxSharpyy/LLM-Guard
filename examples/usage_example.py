
#!/usr/bin/env python3
"""LLM-Guard DLP module — Day 6 usage example."""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from dlp import DLPInterceptor


def fake_llm_call(masked_prompt: str) -> str:
    """Simulate an external LLM receiving masked information."""
    print(f"  [LLM sees]: {masked_prompt}")

    return (
        "Sure, I've sent the update to <EMAIL_1> "
        "and CC'd <EMAIL_2>."
    )


def main():
    interceptor = DLPInterceptor()
    session_id = "demo-session-001"

    user_prompt = (
        "Please email john.doe@company.com about the contract "
        "and CC jane.smith@client.org."
    )

    print(f"User prompt: {user_prompt}\n")

    # Step 1: Mask sensitive information.
    masked_prompt, entities = interceptor.redact(
        user_prompt, session_id
    )

    print(f"Masked prompt sent upstream: {masked_prompt}")
    print(
        f"Entities detected: "
        f"{[e['entity_type'] for e in entities]}\n"
    )

    # Step 2: Send ONLY masked text to the LLM.
    llm_response = fake_llm_call(masked_prompt)
    print()

    # Step 3: Restore original information.
    final_response = interceptor.unmask(
        llm_response, session_id
    )

    print(f"Final response shown to user: {final_response}")

    # Step 4: Clear session data.
    interceptor.end_session(session_id)

    print(
        f"\nActive sessions after cleanup: "
        f"{interceptor.active_session_count()}"
    )


if __name__ == "__main__":
    main()
