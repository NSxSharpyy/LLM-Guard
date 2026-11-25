import os
from dataclasses import dataclass
from typing import Any

MAX_PAYLOAD_BYTES = int(os.getenv("LLM_GUARD_MAX_PAYLOAD_BYTES", str(256 * 1024)))
MAX_MESSAGES = int(os.getenv("LLM_GUARD_MAX_MESSAGES", "32"))


@dataclass(frozen=True)
class PayloadVerdict:
    blocked: bool
    rule_id: str
    reason: str
    risk_score: float = 0.0


def inspect_request_limits(
    raw_body: bytes,
    parsed_body: dict[str, Any],
    max_payload_bytes: int = MAX_PAYLOAD_BYTES,
    max_messages: int = MAX_MESSAGES,
) -> PayloadVerdict:
    """Enforce request byte size and conversation message turn limits."""
    if len(raw_body) > max_payload_bytes:
        return PayloadVerdict(
            blocked=True,
            rule_id="REQ-400-OVERSIZED-PAYLOAD",
            reason=f"Payload size ({len(raw_body)} bytes) exceeds limit ({max_payload_bytes} bytes)",
            risk_score=0.65,
        )

    messages = parsed_body.get("messages")
    if isinstance(messages, list) and len(messages) > max_messages:
        return PayloadVerdict(
            blocked=True,
            rule_id="REQ-400-TOO-MANY-MESSAGES",
            reason=f"Message count ({len(messages)}) exceeds limit ({max_messages})",
            risk_score=0.60,
        )

    return PayloadVerdict(
        blocked=False,
        rule_id="PAYLOAD-OK",
        reason="Payload within limits",
        risk_score=0.0,
    )
