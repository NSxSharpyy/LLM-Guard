"""
Baseline PII redaction engine (Day 2).

Detects EMAIL_ADDRESS and PHONE_NUMBER entities and replaces
them with static placeholder tags using Microsoft Presidio.
"""

from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig


# Entities supported by the Day 2 implementation.
# Day 3 will introduce custom entities.
SUPPORTED_ENTITIES = ["EMAIL_ADDRESS", "PHONE_NUMBER"]


class DLPEngine:
    """Detects and redacts PII from text using Presidio."""

    def __init__(self):
        """Initialize the Analyzer and Anonymizer engines."""

        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()

    def _build_operator_config(self):
        """
        Map each detected entity to its replacement tag.

        Example:
        EMAIL_ADDRESS -> <REDACTED_EMAIL_ADDRESS>
        """

        return {
            entity: OperatorConfig(
                "replace",
                {"new_value": f"<REDACTED_{entity}>"}
            )
            for entity in SUPPORTED_ENTITIES
        }

    def redact(self, text: str):
        """
        Detect and redact sensitive information.

        Args:
            text: Original input text.

        Returns:
            masked_text: Text with sensitive information replaced.
            entities_found: List of detected entity metadata.
        """

        # Handle empty input.
        if not text:
            return text, []

        # STEP 1: Detect sensitive information.
        results = self.analyzer.analyze(
            text=text,
            language="en",
            entities=SUPPORTED_ENTITIES
        )

        # STEP 2: Replace detected sensitive information.
        anonymized = self.anonymizer.anonymize(
            text=text,
            analyzer_results=results,
            operators=self._build_operator_config()
        )

        # STEP 3: Collect detection metadata.
        entities_found = [
            {
                "entity_type": result.entity_type,
                "start": result.start,
                "end": result.end,
                "score": round(result.score, 3),
                "original_value": text[result.start:result.end]
            }
            for result in results
        ]

        # STEP 4: Return masked text and detection information.
        return anonymized.text, entities_found
