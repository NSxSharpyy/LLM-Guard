
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
from dlp.masking_policy import MaskingPolicy

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

    def __init__(
        self,
        include_original_value=False,
        masking_policy=None,
    ):
        self.include_original_value = include_original_value

        self.analyzer = AnalyzerEngine()
        register_custom_recognizers(self.analyzer)

        self._masking_policy = (
            masking_policy
            if masking_policy is not None
            else MaskingPolicy()
        )

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

    def redact(self, text: str, role: str = None):
        """Detect and redact sensitive information.

        Day 17:
        - All entities are detected regardless of role.
        - Authorized entities remain unmasked.
        - All other entities receive temporary placeholders.
        - role=None preserves the original full-masking behavior.

        Returns:
            masked_text: Text with unauthorized sensitive values masked.
            entities_found: Detection metadata.
        """

        if not text:
            return text, []

        # STEP 1: Detect all supported entities.
        if might_contain_pii(text):
            results = self.analyzer.analyze(
                text=text,
                language="en",
                entities=SUPPORTED_ENTITIES,
            )
        else:
            results = []

        # STEP 2: Resolve false positives and overlapping detections.
        results = self._resolve_overlaps(results, text)

        # STEP 3: Prepare placeholders and masking decisions.
        placeholder_manager = PlaceholderManager()

        replacements = []
        entities_found = []

        for result in results:
            original_value = text[result.start:result.end]

            should_unmask = (
                role is not None
                and self._masking_policy.is_unmasked_for_role(
                    result.entity_type,
                    role,
                )
            )

            if should_unmask:
                placeholder = None
            else:
                placeholder = placeholder_manager.get_placeholder(
                    result.entity_type,
                    original_value,
                )

            replacements.append(
                (result, placeholder, should_unmask)
            )

            entity = {
                "entity_type": result.entity_type,
                "start": result.start,
                "end": result.end,
                "score": round(result.score, 3),
                "original_value": original_value,
                "placeholder": placeholder,
                "masked": not should_unmask,
            }

            entities_found.append(entity)

        # STEP 4: Replace only entities that require masking.
        masked_text = text

        for result, placeholder, should_unmask in reversed(replacements):
            if should_unmask:
                continue

            masked_text = (
                masked_text[:result.start]
                + placeholder
                + masked_text[result.end:]
            )

        # STEP 5: Preserve the existing optional original-value behavior.
        if not self.include_original_value:
            for entity in entities_found:
                entity.pop("original_value", None)

        return masked_text, entities_found
