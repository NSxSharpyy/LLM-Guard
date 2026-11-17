import re
import unicodedata
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class GuardrailVerdict:
    blocked: bool
    rule_id: str
    risk_score: float
    reason: str


# Zero-width & invisible Unicode formatting characters used to evade keyword filters
_INVISIBLE_CHARS_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]")
_WHITESPACE_RE = re.compile(r"\s+")


def normalize_prompt_text(text: str) -> str:
    """
    Normalizes Unicode NFKC form, strips invisible zero-width characters,
    and collapses redundant whitespace to prevent trivial filter evasion.
    """
    normalized = unicodedata.normalize("NFKC", text)
    normalized = _INVISIBLE_CHARS_RE.sub("", normalized)
    normalized = _WHITESPACE_RE.sub(" ", normalized).strip()
    return normalized


# Compiled high-precision adversarial signatures: (rule_id, risk_score, reason, regex)
_INJECTION_RULES: list[tuple[str, float, str, re.Pattern[str]]] = [
         (
        "PI-004-DELIMITER-INJECTION",
        0.88,
        "Detected chat-template control token or role-delimiter smuggling",
        re.compile(
            r"(<\|im_start\|>\s*system|<\|im_end\|>|\[INST\]|\[/INST\]|"
            r"<\|system\|>|<<SYS>>|<</SYS>>|"
            r"###\s*System\s*(?:Prompt)?\s*:)",
            re.IGNORECASE,
        ),
    ),

    (
        "PI-001-INSTRUCTION-OVERRIDE",
        0.95,
        "Detected direct instruction override attempt",
        re.compile(
            r"\b(ignore|disregard|forget|override|bypass)\b.{0,40}\b(all\s+)?(previous|prior|above|system|earlier)\b.{0,25}\b(instructions?|rules?|prompts?|directives?|constraints?)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "PI-002-JAILBREAK-PERSONA",
        0.92,
        "Detected known jailbreak persona or unrestricted mode activation",
        re.compile(
            r"\b(you\s+are\s+now\s+(dan|do\s+anything\s+now|developer\s+mode|jailbroken)|enter\s+(developer|god|unrestricted|sudo)\s+mode|act\s+without\s+(any\s+)?(restrictions|ethical\s+guidelines|filters))\b",
            re.IGNORECASE,
        ),
    ),
    (
        "PI-003-SYSTEM-PROMPT-LEAK",
        0.90,
        "Detected attempt to exfiltrate system prompt or hidden instructions",
        re.compile(
            r"\b(reveal|repeat|print|output|show|display|dump)\b.{0,35}\b(your\s+)?(system\s+prompt|initial\s+instructions|hidden\s+prompt|developer\s+message|secret\s+instructions)\b",
            re.IGNORECASE,
        ),
    ),
]


def _extract_messages_text(payload: dict[str, Any]) -> str:
    """Extracts user-supplied text content across OpenAI chat message objects."""
    messages = payload.get("messages")
    if not isinstance(messages, list):
        return ""

    extracted_parts: list[str] = []
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        role = str(msg.get("role", "")).lower()
        # Inspect user and tool/function inputs; skip trusted assistant history if needed,
        # or inspect all non-system messages to prevent multi-turn injection smuggling.
        if role in ("user", "tool", "function", ""):
            content = msg.get("content", "")
            if isinstance(content, str):
                extracted_parts.append(content)
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        extracted_parts.append(str(part.get("text", "")))

    return "\n".join(extracted_parts)


def inspect_chat_payload(payload: dict[str, Any]) -> GuardrailVerdict:
    """
    Evaluates a parsed OpenAI chat completion payload against prompt injection
    and jailbreak detection rules.
    """
    raw_text = _extract_messages_text(payload)
    if not raw_text:
        return GuardrailVerdict(
            blocked=False,
            rule_id="PASS-ALL-CHECKS",
            risk_score=0.0,
            reason="No inspectable user text present",
        )

    clean_text = normalize_prompt_text(raw_text)

    for rule_id, score, reason, pattern in _INJECTION_RULES:
        if pattern.search(clean_text):
            return GuardrailVerdict(
                blocked=True,
                rule_id=rule_id,
                risk_score=score,
                reason=reason,
            )

    return GuardrailVerdict(
        blocked=False,
        rule_id="PASS-ALL-CHECKS",
        risk_score=0.0,
        reason="Prompt passed pre-inference injection checks",
    )
