import re
from dataclasses import dataclass

@dataclass(frozen=True)
class OutputGuardVerdict:
    flagged: bool
    sanitized_text: str
    rule_id: str


_SENSITIVE_PATTERNS = [
    (
        "DLP-OUT-001-API-KEY",
        re.compile(r"\bsk-[A-Za-z0-9\-_]{20,}\b"),
        "[REDACTED_API_KEY]",
    ),
    (
        "DLP-OUT-002-EMAIL",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "[REDACTED_EMAIL]",
    ),
]


def inspect_and_sanitize_output(text: str) -> OutputGuardVerdict:
    """Scans and redacts sensitive patterns in model output text."""
    current_text = text
    flagged = binned_rule = False
    triggered_rule = "PASS-ALL-CHECKS"

    for rule_id, pattern, replacement in _SENSITIVE_PATTERNS:
        if pattern.search(current_text):
            current_text = pattern.sub(replacement, current_text)
            triggered_rule = rule_id
            flagged = True

    return OutputGuardVerdict(
        flagged=flagged,
        sanitized_text=current_text,
        rule_id=triggered_rule,
    )
