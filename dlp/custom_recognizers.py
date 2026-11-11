"""
Custom Presidio recognizers for enterprise PII and secret detection.

Supported custom entities:
- AADHAAR_CARD
- PAN_CARD
- AWS_ACCESS_KEY
- AWS_SECRET_KEY
- JWT_TOKEN
"""

import re

from presidio_analyzer import Pattern, PatternRecognizer

from dlp.verhoeff import validate as verhoeff_validate


# ============================================================
# 1. AADHAAR CARD RECOGNIZER
# ============================================================

class AadhaarRecognizer(PatternRecognizer):

    PATTERNS = [
        Pattern(
            name="aadhaar_pattern",
            regex=r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
            score=0.4,
        )
    ]

    def __init__(self):
        super().__init__(
            supported_entity="AADHAAR_CARD",
            patterns=self.PATTERNS,
            supported_language="en",
            context=["aadhaar", "aadhar", "uidai"],
        )

    def validate_result(self, pattern_text: str) -> bool:
        """Accept only numbers passing Verhoeff validation."""

        digits_only = re.sub(r"[\s-]", "", pattern_text)

        if len(digits_only) != 12:
            return False

        return verhoeff_validate(digits_only)


# ============================================================
# 2. INDIAN PAN CARD RECOGNIZER
# ============================================================

class PANRecognizer(PatternRecognizer):

    PATTERNS = [
        Pattern(
            name="pan_pattern",
            regex=r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
            score=0.75,
        )
    ]

    def __init__(self):
        super().__init__(
            supported_entity="PAN_CARD",
            patterns=self.PATTERNS,
            supported_language="en",
            context=["pan", "permanent account number"],
        )


# ============================================================
# 3. AWS ACCESS KEY RECOGNIZER
# ============================================================

class AWSAccessKeyRecognizer(PatternRecognizer):

    PATTERNS = [
        Pattern(
            name="aws_access_key_pattern",
            regex=r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
            score=0.9,
        )
    ]

    def __init__(self):
        super().__init__(
            supported_entity="AWS_ACCESS_KEY",
            patterns=self.PATTERNS,
            supported_language="en",
            context=["aws", "access key", "aws_access_key_id"],
        )


# ============================================================
# 4. AWS SECRET KEY RECOGNIZER
# ============================================================

class AWSSecretKeyRecognizer(PatternRecognizer):
    """Detect AWS secret keys only when nearby text identifies AWS and a secret."""

    CONTEXT_WINDOW = 100

    def __init__(self):
        patterns = [
            Pattern(
                name="aws_secret_key",
                regex=r"\b[A-Za-z0-9/+=]{40}\b",
                score=0.3,
            )
        ]

        super().__init__(
            supported_entity="AWS_SECRET_KEY",
            patterns=patterns,
            context=[
                "aws",
                "secret",
                "secret access key",
                "aws_secret_access_key",
            ],
        )

    def analyze(self, text, entities, nlp_artifacts):
        results = super().analyze(text, entities, nlp_artifacts)
        filtered_results = []

        for result in results:
            start = max(0, result.start - self.CONTEXT_WINDOW)
            end = min(len(text), result.end + self.CONTEXT_WINDOW)
            nearby_text = text[start:end].lower()

            # Normalize separators so AWS_SECRET_ACCESS_KEY is recognized.
            normalized_context = re.sub(r"[^a-z0-9]+", " ", nearby_text)
            context_words = set(normalized_context.split())

            if "aws" in context_words and "secret" in context_words:
                filtered_results.append(result)

        return filtered_results

# ============================================================
# 5. JWT TOKEN RECOGNIZER
# ============================================================

class JWTRecognizer(PatternRecognizer):

    PATTERNS = [
        Pattern(
            name="jwt_pattern",
            regex=r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
            score=0.9,
        )
    ]

    def __init__(self):
        super().__init__(
            supported_entity="JWT_TOKEN",
            patterns=self.PATTERNS,
            supported_language="en",
            context=["jwt", "token", "bearer", "authorization"],
        )


# ============================================================
# REGISTRY CONFIGURATION
# ============================================================

ALL_CUSTOM_RECOGNIZERS = [
    AadhaarRecognizer,
    PANRecognizer,
    AWSAccessKeyRecognizer,
    AWSSecretKeyRecognizer,
    JWTRecognizer,
]


CUSTOM_ENTITY_TYPES = [
    "AADHAAR_CARD",
    "PAN_CARD",
    "AWS_ACCESS_KEY",
    "AWS_SECRET_KEY",
    "JWT_TOKEN",
]


def register_custom_recognizers(analyzer):
    """
    Register all custom recognizers with an AnalyzerEngine.

    This allows analyzer.analyze() to discover the new entities
    through Presidio's existing recognition pipeline.
    """

    for recognizer_class in ALL_CUSTOM_RECOGNIZERS:
        analyzer.registry.add_recognizer(recognizer_class())
