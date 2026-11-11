"""
Baseline + custom PII/secret redaction engine (Days 2-3).

Detects standard entities using Presidio's built-in recognizers
and custom entities using Day 3 PatternRecognizer implementations.
"""

from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

from dlp.custom_recognizers import (
    CUSTOM_ENTITY_TYPES,
    register_custom_recognizers,
)


# Day 2 built-in entities
STANDARD_ENTITIES = [
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
]

# Day 2 + Day 3 supported entities
SUPPORTED_ENTITIES = STANDARD_ENTITIES + CUSTOM_ENTITY_TYPES


class DLPEngine:
    """Detects and redacts PII and secrets using Presidio."""

    def __init__(self, include_original_value=False):
        self.include_original_value = include_original_value

        self.analyzer = AnalyzerEngine()
        register_custom_recognizers(self.analyzer)
        self.anonymizer = AnonymizerEngine()

    def _build_operator_config(self):
        """Create replacement operators for every supported entity."""

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

        Returns:
            masked_text: Text containing replacement placeholders.
            entities_found: Detection metadata.
        """

        if not text:
            return text, []

        # STEP 1: Detect sensitive entities
        results = self.analyzer.analyze(
            text=text,
            language="en",
            entities=SUPPORTED_ENTITIES,
        )

        # STEP 2: Redact detected entities
        anonymized = self.anonymizer.anonymize(
            text=text,
            analyzer_results=results,
            operators=self._build_operator_config(),
        )

        # STEP 3: Collect detection metadata
        entities_found = []

        for result in results:
            entity = {
                "entity_type": result.entity_type,
                "start": result.start,
                "end": result.end,
                "score": round(result.score, 3),
            }

            if self.include_original_value:
                entity["original_value"] = text[result.start:result.end]

            entities_found.append(entity)

        return anonymized.text, entities_found
