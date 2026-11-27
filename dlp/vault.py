
"""In-memory, session-scoped reversible lookup vault (Day 5).

Stores placeholder -> original_value mappings per session_id.
"""
import json
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

    def unmask_json(self, masked_json: str, session_id: str) -> str:
        """Restore placeholders while preserving valid JSON structure."""

        if not isinstance(masked_json, str):
            raise TypeError("masked_json must be a string")

        try:
            def reject_non_standard_constant(value):
                raise ValueError(f"Invalid JSON constant: {value}")

            data = json.loads(
                masked_json,
                parse_constant=reject_non_standard_constant,
            )
        except json.JSONDecodeError as exc:
            raise ValueError("masked_json must contain valid JSON") from exc

        with self._lock:
            session_mapping = dict(self._store.get(session_id, {}))

        def restore(value):
            if isinstance(value, str):
                return PLACEHOLDER_PATTERN.sub(
                    lambda match: session_mapping.get(
                        match.group(0),
                        match.group(0),
                    ),
                    value,
                )

            if isinstance(value, list):
                return [restore(item) for item in value]

            if isinstance(value, dict):
                return {
                    key: restore(item)
                    for key, item in value.items()
                }

            return value

        restored_data = restore(data)

        return json.dumps(restored_data, ensure_ascii=False)

    def clear_session(self, session_id: str) -> None:
        """Remove all mappings belonging to a session."""
        with self._lock:
            self._store.pop(session_id, None)

    def session_count(self) -> int:
        """Return the number of active sessions."""
        with self._lock:
            return len(self._store)

    def has_session(self, session_id: str) -> bool:
        """Check whether a session currently exists in the vault."""
        with self._lock:
            return session_id in self._store

def build_mapping_from_entities(entities_found: list) -> dict:
    """Convert Day 4 entities into a vault mapping."""
    return {
        entity["placeholder"]: entity["original_value"]
        for entity in entities_found
    }
