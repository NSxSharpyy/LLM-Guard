
"""DLPInterceptor — public entry point into the DLP module.

Combines DLPEngine with a Redis-backed session vault.
Placeholder allocation is shared across workers through Redis.
"""

import threading

from dlp.dlp_engine import DLPEngine
from dlp.redis_vault import RedisVault
from dlp.vault import PLACEHOLDER_PATTERN
from dlp.output_scanner import OutputScanner

class DLPInterceptor:
    """Public interface for reversible PII and secret masking."""

    def __init__(
        self,
        vault=None,
        redis_host="localhost",
        redis_port=6379,
        redis_db=0,
        redis_password=None,
        ttl_seconds=900,
    ):
        self._engine = DLPEngine(include_original_value=True)

        self._vault = vault if vault is not None else RedisVault(
            host=redis_host,
            port=redis_port,
            db=redis_db,
            password=redis_password,
            ttl_seconds=ttl_seconds,
        )
        # Initialize the output response scanner.
        self._output_scanner = OutputScanner(
            self._vault,
            self._engine,
        )

        # This lock coordinates threads within this process.
        # Redis Lua allocation coordinates separate workers/processes.
        self._lock = threading.RLock()

    @staticmethod
    def _validate_session_id(session_id: str) -> None:
        """Apply the same session ID rules as RedisVault."""
        if not isinstance(session_id, str) or not session_id.strip():
            raise ValueError("session_id must be a non-empty string")

        if not all(
            char.isalnum() or char in "_-"
            for char in session_id
        ):
            raise ValueError(
                "session_id may contain only letters, numbers, "
                "underscores, and hyphens"
            )

    @staticmethod
    def _validate_entities(text: str, entities: list) -> None:
        """Validate detected entity metadata before placeholder allocation."""

        if not isinstance(text, str):
            raise TypeError("text must be a string")

        if not isinstance(entities, list):
            raise TypeError("entities must be a list")

        # Validate each entity individually.
        for entity in entities:
            if not isinstance(entity, dict):
                raise TypeError("Each entity must be a dictionary")

            start = entity.get("start")
            end = entity.get("end")
            original_value = entity.get("original_value")

            # Validate offset types.
            if (
                isinstance(start, bool)
                or not isinstance(start, int)
                or isinstance(end, bool)
                or not isinstance(end, int)
            ):
                raise ValueError("Entity offsets must be integers")

            # Validate offset boundaries.
            if start < 0 or end <= start or end > len(text):
                raise ValueError("Invalid entity offsets")

            # Validate original sensitive value.
            if not isinstance(original_value, str):
                raise ValueError("Entity original_value must be a string")

            if text[start:end] != original_value:
                raise ValueError(
                    "Entity original_value does not match text"
                )

        # Reject overlapping entity ranges before allocating placeholders.
        ranges = sorted(
            (entity["start"], entity["end"])
            for entity in entities
        )

        for previous, current in zip(ranges, ranges[1:]):
            if current[0] < previous[1]:
                raise ValueError("Entity offsets must not overlap")

    def redact(self, text: str, session_id: str):
        """Mask sensitive information and allocate shared placeholders."""
        self._validate_session_id(session_id)

        if not isinstance(text, str):
            raise TypeError("text must be a string")

        with self._lock:
            _, entities_found = self._engine.redact(text)

            if not entities_found:
                return text, []

            # Validate all detection metadata before writing to Redis.
            self._validate_entities(text, entities_found)

            # Allocate placeholders through Redis.
            placeholders = self._vault.allocate_placeholders(
                session_id,
                entities_found,
            )

            # Validate the complete allocation response before modifying
            # entity metadata or constructing the masked response.
            if not isinstance(placeholders, list):
                raise RuntimeError(
                    "Vault must return a list of placeholders"
                )

            if len(placeholders) != len(entities_found):
                raise RuntimeError(
                    "Vault returned an unexpected number of placeholders"
                )

            if not all(
                isinstance(placeholder, str)
                and PLACEHOLDER_PATTERN.fullmatch(placeholder)
                for placeholder in placeholders
            ):
                raise RuntimeError(
                    "Vault returned an invalid placeholder"
                )
            # Repeated values may legitimately reuse a placeholder.
            # A placeholder must never represent different entities.
            placeholder_owners = {}

            for entity, placeholder in zip(entities_found, placeholders):
                owner = (
                    entity["entity_type"],
                    entity["original_value"],
                )

                existing_owner = placeholder_owners.get(placeholder)

                if existing_owner is not None and existing_owner != owner:
                    raise RuntimeError(
                        "Vault assigned one placeholder to different entities"
                    )

                placeholder_owners[placeholder] = owner

            replacements = []

            for entity, placeholder in zip(
                entities_found,
                placeholders,
            ):
                replacements.append((
                    entity["start"],
                    entity["end"],
                    placeholder,
                ))

            # Only update metadata after the complete response is validated.
            for entity, placeholder in zip(
                entities_found,
                placeholders,
            ):
                entity["placeholder"] = placeholder
                entity.pop("original_value", None)

            # Replace from right to left to preserve original offsets.
            masked_text = text

            for start, end, placeholder in reversed(replacements):
                masked_text = (
                    masked_text[:start]
                    + placeholder
                    + masked_text[end:]
                )

            return masked_text, entities_found

    def unmask(self, text: str, session_id: str) -> str:
        """Restore original values using the session vault."""
        self._validate_session_id(session_id)
        return self._vault.unmask_text(text, session_id)

    def scan_output(self, final_response: str, session_id: str):
        """Scan a final LLM response for unexpected PII.

        This is an explicit opt-in operation. It does not modify
        or block the response.
        """
        self._validate_session_id(session_id)

        with self._lock:
            return self._output_scanner.scan(
                final_response,
                session_id,
            )

    def end_session(self, session_id: str) -> None:
        """Clear all data associated with a session."""
        self._validate_session_id(session_id)

        with self._lock:
            self._vault.clear_session(session_id)

    def active_session_count(self) -> int:
        """Return the number of active vault sessions."""
        return self._vault.session_count()

    def has_session(self, session_id: str) -> bool:
        """Check whether a session exists in the vault."""
        self._validate_session_id(session_id)
        return self._vault.has_session(session_id)

    def is_vault_healthy(self) -> bool:
        """Return False if the configured vault is unavailable."""
        try:
            return bool(self._vault.ping())
        except Exception:
            return False
