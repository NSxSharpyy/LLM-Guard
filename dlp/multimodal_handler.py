"""Multimodal input validation and DLP processing.

This module accepts text and pre-extracted attachment text.
It does not perform OCR or document parsing.
"""

from dataclasses import dataclass


REQUIRED_TOP_LEVEL_KEYS = {"text"}
ALLOWED_TOP_LEVEL_KEYS = {"text", "attachments"}

REQUIRED_ATTACHMENT_KEYS = {"filename", "extracted_text"}

ALLOWED_ATTACHMENT_KEYS = {
    "filename",
    "extracted_text",
    "mime_type",
    "size_bytes",
}

# These fields are metadata, not content to be scanned for PII.
METADATA_ONLY_FIELDS = {"filename", "mime_type", "size_bytes"}


class MultiModalInputError(ValueError):
    """Raised when multimodal input does not follow the expected contract."""


@dataclass(frozen=True)
class MultiModalInput:
    """Validated representation of text and extracted attachment content."""

    text: str
    attachments: tuple

    @classmethod
    def from_dict(cls, raw_input: dict):
        """Validate and convert a dictionary into a MultiModalInput."""
        MultiModalHandler.validate_input(raw_input)

        attachments = tuple(
            dict(attachment)
            for attachment in raw_input.get("attachments", [])
        )

        return cls(
            text=raw_input["text"],
            attachments=attachments,
        )


class MultiModalHandler:
    """Apply DLP redaction to text and pre-extracted attachment content."""

    def __init__(self, interceptor):
        if interceptor is None or not callable(
            getattr(interceptor, "redact", None)
        ):
            raise TypeError(
                "interceptor must provide a callable redact method"
            )

        self._interceptor = interceptor

    @staticmethod
    def validate_input(raw_input: dict) -> None:
        """Validate the top-level input and every attachment."""

        if not isinstance(raw_input, dict):
            raise MultiModalInputError(
                "Input must be a dictionary"
            )

        missing_keys = REQUIRED_TOP_LEVEL_KEYS - raw_input.keys()

        if missing_keys:
            raise MultiModalInputError(
                f"Missing required top-level keys: {sorted(missing_keys)}"
            )

        unexpected_keys = raw_input.keys() - ALLOWED_TOP_LEVEL_KEYS

        if unexpected_keys:
            raise MultiModalInputError(
                f"Unexpected top-level keys: {sorted(unexpected_keys)}"
            )

        if not isinstance(raw_input["text"], str):
            raise MultiModalInputError(
                "'text' must be a string"
            )

        attachments = raw_input.get("attachments", [])

        if not isinstance(attachments, list):
            raise MultiModalInputError(
                "'attachments' must be a list"
            )

        for index, attachment in enumerate(attachments):
            if not isinstance(attachment, dict):
                raise MultiModalInputError(
                    f"Attachment {index} must be a dictionary"
                )
            unexpected_attachment_keys = (
                attachment.keys() - ALLOWED_ATTACHMENT_KEYS
            )

            if unexpected_attachment_keys:
                raise MultiModalInputError(
                    f"Attachment {index} contains unexpected keys: "
                    f"{sorted(unexpected_attachment_keys)}"
                )

            missing_attachment_keys = (
                REQUIRED_ATTACHMENT_KEYS - attachment.keys()
            )

            if missing_attachment_keys:
                raise MultiModalInputError(
                    f"Attachment {index} is missing required keys: "
                    f"{sorted(missing_attachment_keys)}"
                )

            if not isinstance(attachment["filename"], str):
                raise MultiModalInputError(
                    f"Attachment {index} filename must be a string"
                )

            if not isinstance(attachment["extracted_text"], str):
                raise MultiModalInputError(
                    f"Attachment {index} extracted_text must be a string"
                )
            if (
                "mime_type" in attachment
                and not isinstance(attachment["mime_type"], str)
            ):
                raise MultiModalInputError(
                    f"Attachment {index} mime_type must be a string"
                )

            if "size_bytes" in attachment:
                size = attachment["size_bytes"]

                if (
                    isinstance(size, bool)
                    or not isinstance(size, int)
                    or size < 0
                ):
                    raise MultiModalInputError(
                        f"Attachment {index} size_bytes must be "
                        "a non-negative integer"
                    )

    def process(self, raw_input: dict, session_id: str) -> dict:
        """Redact main text and attachment text using one shared session."""

        multimodal_input = MultiModalInput.from_dict(raw_input)

        all_entities = []

        masked_text, text_entities = self._interceptor.redact(
            multimodal_input.text,
            session_id,
        )

        all_entities.extend(text_entities)

        processed_attachments = []

        for attachment in multimodal_input.attachments:
            masked_attachment_text, attachment_entities = (
                self._interceptor.redact(
                    attachment["extracted_text"],
                    session_id,
                )
            )

            all_entities.extend(attachment_entities)

            # Preserve metadata and other attachment fields, but never
            # return the original extracted text.
            attachment_result = {
                key: value
                for key, value in attachment.items()
                if key != "extracted_text"
            }

            attachment_result["masked_text"] = masked_attachment_text

            processed_attachments.append(attachment_result)

        entity_types = sorted({
            entity["entity_type"]
            for entity in all_entities
        })

        return {
            "masked_text": masked_text,
            "attachments": processed_attachments,
            "total_entities_found": len(all_entities),
            "entity_types_found": entity_types,
        }
