import os
import re
from dataclasses import dataclass
from typing import Any

CANARY_RULE_ID = "CANARY-001-TOKEN-EXFILTRATION"

_DEFAULT_CANARY_PATTERNS = (
    re.compile(r"\bCANARY-[A-Z0-9_-]{4,64}\b", re.IGNORECASE),
    re.compile(r"\bllmguard_canary_[a-zA-Z0-9_-]{4,64}\b", re.IGNORECASE),
    re.compile(r"\bsk-canary-[a-zA-Z0-9_-]{4,64}\b", re.IGNORECASE),
)


@dataclass(frozen=True)
class CanaryVerdict:
    blocked: bool
    rule_id: str
    reason: str
    risk_score: float = 0.0


def _configured_custom_tokens() -> list[str]:
    raw = os.getenv("LLM_GUARD_CANARY_TOKENS", "").strip()
    if not raw:
        return []
    return [tok.strip() for tok in raw.split(",") if tok.strip()]


def inspect_canary_text(text: str) -> CanaryVerdict:
    """Detect deterministic canary-token strings in arbitrary text."""
    if not text:
        return CanaryVerdict(
            blocked=False,
            rule_id="CANARY-OK",
            reason="No canary token detected",
            risk_score=0.0,
        )

    for custom_tok in _configured_custom_tokens():
        if custom_tok in text:
            return CanaryVerdict(
                blocked=True,
                rule_id=CANARY_RULE_ID,
                reason="Configured canary token exfiltration detected",
                risk_score=1.0,
            )

    for pattern in _DEFAULT_CANARY_PATTERNS:
        if pattern.search(text):
            return CanaryVerdict(
                blocked=True,
                rule_id=CANARY_RULE_ID,
                reason="Canary token exfiltration pattern detected",
                risk_score=1.0,
            )

    return CanaryVerdict(
        blocked=False,
        rule_id="CANARY-OK",
        reason="No canary token detected",
        risk_score=0.0,
    )


def _iter_strings(obj: Any) -> list[str]:
    found: list[str] = []
    if isinstance(obj, str):
        found.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            found.extend(_iter_strings(v))
    elif isinstance(obj, list):
        for item in obj:
            found.extend(_iter_strings(item))
    return found


def inspect_canary_payload(parsed_body: dict[str, Any]) -> CanaryVerdict:
    """Inspect all string fields in an incoming JSON payload for canary tokens."""
    for text in _iter_strings(parsed_body):
        verdict = inspect_canary_text(text)
        if verdict.blocked:
            return verdict

    return CanaryVerdict(
        blocked=False,
        rule_id="CANARY-OK",
        reason="No canary token detected in payload",
        risk_score=0.0,
    )
