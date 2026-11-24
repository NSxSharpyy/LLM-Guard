
"""
Baseline + custom PII/secret redaction engine.

Days 2-3: Presidio-based detection.
Day 4: Deterministic semantic placeholder masking.
Day 16: Infrastructure secret detection and IPv4 false-positive handling.
"""

import re
import ipaddress

from presidio_analyzer import AnalyzerEngine

from dlp.pre_filter import might_contain_pii
from dlp.custom_recognizers import (
    CUSTOM_ENTITY_TYPES,
    register_custom_recognizers,
)
from dlp.placeholder_manager import PlaceholderManager


# Day 2 built-in entities
STANDARD_ENTITIES = [
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "US_SSN",
]

# All supported standard and custom entities
SUPPORTED_ENTITIES = STANDARD_ENTITIES + CUSTOM_ENTITY_TYPES


class DLPEngine:
    """Detects and redacts PII and secrets using Presidio."""

    def __init__(self, include_original_value=False):
        self.include_original_value = include_original_value

        self.analyzer = AnalyzerEngine()
        register_custom_recognizers(self.analyzer)

    @staticmethod
    def _is_valid_ipv4(value):
        try:
            return ipaddress.ip_address(value).version == 4
        except ValueError:
            return False

    def _resolve_overlaps(self, results, text=None):
        """
        Resolve overlapping detections.

        Higher-priority secret detections take precedence.
        For other detections, higher confidence wins.
        For equal confidence, longer detections take priority.

        IPv4-shaped values incorrectly detected as phone numbers
        are excluded when the original text is available.
        """

        # Filter IPv4-shaped values misclassified as phone numbers.
        if text is not None:
            results = [
                result
                for result in results
                if not (
                    result.entity_type == "PHONE_NUMBER"
                    and self._is_valid_ipv4(
                        text[result.start:result.end]
                    )
                )
            ]

        # Give infrastructure secrets priority over overlapping entities.
        priority_entities = {
            "PRIVATE_KEY",
            "DB_CONNECTION_STRING",
            "AWS_SECRET_KEY",
            "AWS_ACCESS_KEY",
        }

        ranked_results = sorted(
            results,
            key=lambda result: (
                result.entity_type not in priority_entities,
                -result.score,
                -(result.end - result.start),
                result.start,
                result.entity_type,
            ),
        )

        accepted = []

        for candidate in ranked_results:
            overlaps = any(
                candidate.start < existing.end
                and existing.start < candidate.end
                for existing in accepted
            )

            if not overlaps:
                accepted.append(candidate)

        return sorted(
            accepted,
            key=lambda result: result.start,
        )

    def redact(self, text: str):
        """
        Detect and redact sensitive information.

        Each call creates a fresh placeholder mapping.

        Returns:
            masked_text: Text containing semantic placeholders.
            entities_found: Detection metadata.
        """

        if not text:
            return text, []

        # STEP 1: Lightweight pre-filter.
        # Skip expensive Presidio analysis when no indicators are found.
        if might_contain_pii(text):
            results = self.analyzer.analyze(
                text=text,
                language="en",
                entities=SUPPORTED_ENTITIES,
            )
        else:
            results = []

        # STEP 2: Filter false positives and resolve overlapping detections.
        results = self._resolve_overlaps(results, text)

        # STEP 3: Create a fresh placeholder mapping for this operation.
        placeholder_manager = PlaceholderManager()

        # Assign placeholders from left to right so numbering follows
        # the first appearance of each sensitive value.
        replacements = []

        for result in results:
            original_value = text[result.start:result.end]

            placeholder = placeholder_manager.get_placeholder(
                result.entity_type,
                original_value,
            )

            replacements.append((result, placeholder))

        # STEP 4: Replace sensitive values from right to left.
        # This preserves the original offsets of remaining entities.
        masked_text = text

        for result, placeholder in reversed(replacements):
            masked_text = (
                masked_text[:result.start]
                + placeholder
                + masked_text[result.end:]
            )

        # STEP 5: Collect detection metadata.
        entities_found = []

        for result, placeholder in replacements:
            entity = {
                "entity_type": result.entity_type,
                "start": result.start,
                "end": result.end,
                "score": round(result.score, 3),
                "placeholder": placeholder,
            }

            if self.include_original_value:
                entity["original_value"] = text[
                    result.start:result.end
                ]

            entities_found.append(entity)

        return masked_text, entities_found
