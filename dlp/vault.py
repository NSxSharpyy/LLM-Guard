
"""In-memory, session-scoped reversible lookup vault (Day 5).

Stores placeholder -> original_value mappings per session_id.
"""

import re
import threading


# Matches placeholders such as <EMAIL_1>, <AWS_KEY_12>
PLACEHOLDER_PATTERN = re.compile(r"<([A-Z_]+\d+)>")


class Vault:
    """Session-scoped store for placeholder-to-original mappings."""

    def __init__(self):
        self._store = {}
        self._lock = threading.Lock()

    def store(self, session_id: str, mapping: dict) -> None:
        """Save or merge mappings for a particular session."""
        if not mapping:
            return

        with self._lock:
            if session_id not in self._store:
                self._store[session_id] = {}

            self._store[session_id].update(mapping)

    def get_mapping(self, session_id: str) -> dict:
        """Return a copy of the session's mapping."""
        with self._lock:
            return dict(self._store.get(session_id, {}))

    def unmask_text(self, masked_text: str, session_id: str) -> str:
        """Restore known placeholders without leaking across sessions."""
        if not masked_text:
            return masked_text

        with self._lock:
            session_mapping = dict(self._store.get(session_id, {}))

        def replace_placeholder(match):
            placeholder = match.group(0)
            return session_mapping.get(placeholder, placeholder)

        return PLACEHOLDER_PATTERN.sub(replace_placeholder, masked_text)

    def clear_session(self, session_id: str) -> None:
        """Remove all mappings belonging to a session."""
        with self._lock:
            self._store.pop(session_id, None)

    def session_count(self) -> int:
        """Return the number of active sessions."""
        with self._lock:
            return len(self._store)


def build_mapping_from_entities(entities_found: list) -> dict:
    """Convert Day 4 entities into a vault mapping."""
    return {
        entity["placeholder"]: entity["original_value"]
        for entity in entities_found
    }
