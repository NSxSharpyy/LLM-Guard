
"""DLPInterceptor — the public entry point into the DLP module.

Combines DLPEngine, PlaceholderManager and Vault.
Maintains unique placeholders across calls within each session.
"""

import threading

from dlp.dlp_engine import DLPEngine
from dlp.placeholder_manager import PlaceholderManager
from dlp.vault import Vault


class DLPInterceptor:
    """Public interface for reversible PII and secret masking."""

    def __init__(self):
        self._engine = DLPEngine(include_original_value=True)
        self._vault = Vault()
        self._session_managers = {}
        self._lock = threading.RLock()


    def redact(self, text: str, session_id: str):
        """Mask sensitive information and store session mappings."""

        if not isinstance(session_id, str) or not session_id.strip():
            raise ValueError(
                "redact() requires a non-empty session_id"
            )

        with self._lock:
            _, entities_found = self._engine.redact(text)

            if not entities_found:
                return text, []

            # Work on a temporary manager so failures cannot
            # corrupt an existing session or leave a partial one.
            manager = PlaceholderManager()

            existing_manager = self._session_managers.get(session_id)

            if existing_manager is not None:
                manager.value_mapping = dict(
                    existing_manager.value_mapping
                )
                manager.entity_counters = dict(
                    existing_manager.entity_counters
                )

            mapping = {}
            replacements = []

            for entity in entities_found:
                original_value = entity["original_value"]

                session_placeholder = manager.get_placeholder(
                    entity["entity_type"],
                    original_value,
                )

                replacements.append((
                    entity["start"],
                    entity["end"],
                    session_placeholder,
                ))

                mapping[session_placeholder] = original_value
                entity["placeholder"] = session_placeholder

                # Never expose original values in returned metadata.
                entity.pop("original_value", None)

            # Rebuild using original offsets, from right to left.
            masked_text = text

            for start, end, placeholder in reversed(replacements):
                masked_text = (
                    masked_text[:start]
                    + placeholder
                    + masked_text[end:]
                )

            # Store mappings before committing the new manager.
            self._vault.store(session_id, mapping)
            self._session_managers[session_id] = manager

            return masked_text, entities_found

    def unmask(self, text: str, session_id: str) -> str:
        """Restore original values using the session vault."""

        if not isinstance(session_id, str) or not session_id.strip():
            raise ValueError(
                "unmask() requires a non-empty session_id"
            )

        return self._vault.unmask_text(text, session_id)

    def end_session(self, session_id: str) -> None:
        """Clear all data associated with a session."""

        if not isinstance(session_id, str) or not session_id.strip():
            raise ValueError(
                "end_session() requires a non-empty session_id"
            )

        with self._lock:
            self._vault.clear_session(session_id)
            self._session_managers.pop(session_id, None)

    def active_session_count(self) -> int:
        """Return the number of active vault sessions."""

        return self._vault.session_count()

    def has_session(self, session_id: str) -> bool:
        """Check whether a session exists in the vault."""

        return self._vault.has_session(session_id)
