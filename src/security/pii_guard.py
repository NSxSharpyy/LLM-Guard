import copy
import json
import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class DLPVerdict:
    blocked: bool
    redacted: bool
    rule_id: str
    risk_score: float
    reason: str
    sanitized_body: bytes
    redacted_categories: tuple[str, ...]


# High-severity hardcoded credentials/secrets -> Immediate BLOCK
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS_ACCESS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("OPENAI_OR_GUARD_KEY", re.compile(r"\bsk-[A-Za-z0-9\-_]{20,}\b")),
    ("GITHUB_PAT", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("PRIVATE_KEY_BLOCK", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]

# PII patterns for inline redaction
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_PAN_RE = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
_PHONE_RE = re.compile(r"(?<!\w)(?:\+91[\-\s]?|0)?[6-9]\d{9}\b|\b\(\d{3}\)\s*\d{3}-\d{4}\b")
_CARD_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")


def _passes_luhn(digits: str) -> bool:
    """Validates credit/debit card numbers using the Luhn checksum algorithm."""
    if not digits.isdigit() or not (13 <= len(digits) <= 19):
        return False
    total = 0
    reverse_digits = digits[::-1]
    for idx, ch in enumerate(reverse_digits):
        n = int(ch)
        if idx % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _mask_credit_cards(text: str, found_categories: set[str]) -> str:
    def _replace_card(match: re.Match[str]) -> str:
        raw = match.group(0)
        digits = re.sub(r"[ -]", "", raw)
        if _passes_luhn(digits):
            found_categories.add("CREDIT_CARD")
            return "[REDACTED_CREDIT_CARD]"
        return raw

    return _CARD_CANDIDATE_RE.sub(_replace_card, text)


def _redact_text(text: str, found_categories: set[str]) -> str:
    updated = _mask_credit_cards(text, found_categories)

    if _EMAIL_RE.search(updated):
        found_categories.add("EMAIL")
        updated = _EMAIL_RE.sub("[REDACTED_EMAIL]", updated)

    if _SSN_RE.search(updated):
        found_categories.add("SSN")
        updated = _SSN_RE.sub("[REDACTED_SSN]", updated)

    if _PAN_RE.search(updated):
        found_categories.add("PAN_ID")
        updated = _PAN_RE.sub("[REDACTED_PAN]", updated)

    if _PHONE_RE.search(updated):
        found_categories.add("PHONE")
        updated = _PHONE_RE.sub("[REDACTED_PHONE]", updated)

    return updated


def inspect_and_sanitize_payload(
    parsed_body: dict[str, Any],
    original_raw_body: bytes,
) -> DLPVerdict:
    """
    Scans chat messages for hardcoded secrets (hard block) and PII (inline redaction).
    Returns sanitized JSON bytes ready for safe upstream forwarding.
    """
    messages = parsed_body.get("messages")
    if not isinstance(messages, list):
        return DLPVerdict(
            blocked=False,
            redacted=False,
            rule_id="PASS-ALL-CHECKS",
            risk_score=0.0,
            reason="No messages array to inspect",
            sanitized_body=original_raw_body,
            redacted_categories=(),
        )

    # Pass 1: Detect high-severity secrets across all message contents
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        content = msg.get("content", "")
        texts_to_check: list[str] = []
        if isinstance(content, str):
            texts_to_check.append(content)
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text":
                    texts_to_check.append(str(part.get("text", "")))

        for txt in texts_to_check:
            for secret_name, pattern in _SECRET_PATTERNS:
                if pattern.search(txt):
                    return DLPVerdict(
                        blocked=True,
                        redacted=False,
                        rule_id="DLP-001-SECRET-EXFILTRATION",
                        risk_score=0.98,
                        reason=f"Blocked outbound credential/secret leak ({secret_name})",
                        sanitized_body=original_raw_body,
                        redacted_categories=(),
                    )

    # Pass 2: Inline redaction of PII fields
    sanitized_payload = copy.deepcopy(parsed_body)
    found_categories: set[str] = set()

    for msg in sanitized_payload.get("messages", []):
        if not isinstance(msg, dict):
            continue
        content = msg.get("content")
        if isinstance(content, str):
            msg["content"] = _redact_text(content, found_categories)
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text" and "text" in part:
                    part["text"] = _redact_text(str(part["text"]), found_categories)

    if found_categories:
        new_raw_body = json.dumps(sanitized_payload).encode("utf-8")
        sorted_cats = tuple(sorted(found_categories))
        return DLPVerdict(
            blocked=False,
            redacted=True,
            rule_id="DLP-002-PII-REDACTED",
            risk_score=0.35,
            reason=f"Redacted PII categories before upstream dispatch: {', '.join(sorted_cats)}",
            sanitized_body=new_raw_body,
            redacted_categories=sorted_cats,
        )

    return DLPVerdict(
        blocked=False,
        redacted=False,
        rule_id="PASS-ALL-CHECKS",
        risk_score=0.0,
        reason="No secrets or PII detected",
        sanitized_body=original_raw_body,
        redacted_categories=(),
    )
