"""
Day 8: Lightweight regex pre-filter for potential PII and secrets.

The filter is intentionally permissive:
- False means no known indicators were found.
- True means the full Presidio analysis should run.
"""

import re


_HAS_DIGIT = re.compile(r"\d")
_HAS_AT_SIGN = re.compile(r"@")
_HAS_AWS_PREFIX = re.compile(r"\b(?:AKIA|ASIA)", re.IGNORECASE)
_HAS_JWT_PREFIX = re.compile(r"\beyJ", re.IGNORECASE)
_HAS_KEY_SYMBOLS = re.compile(r"[+/=]")

# AWS secret recognizer requires AWS and secret context.
_HAS_AWS_SECRET_CONTEXT = re.compile(
    r"\baws\b|\bsecret\b|aws[_\s-]*secret|"
    r"secret[_\s-]*access[_\s-]*key",
    re.IGNORECASE,
)


def might_contain_pii(text: str) -> bool:
    """
    Return True when text has indicators of possible PII or secrets.

    False allows the caller to skip Presidio analysis.
    """
    if not text:
        return False

    return any(
        pattern.search(text)
        for pattern in (
            _HAS_DIGIT,
            _HAS_AT_SIGN,
            _HAS_AWS_PREFIX,
            _HAS_JWT_PREFIX,
            _HAS_KEY_SYMBOLS,
            _HAS_AWS_SECRET_CONTEXT,
        )
    )
