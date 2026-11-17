"""Redis-backed, session-scoped reversible lookup vault (Day 9).

Stores placeholder -> original_value mappings in Redis.
Each mapping expires after the configured TTL.
"""

import redis

from dlp.vault import PLACEHOLDER_PATTERN


class RedisVault:
    """Redis-backed replacement for the in-memory Vault."""

    def __init__(
        self,
        host="localhost",
        port=6379,
        db=0,
        password=None,
        ttl_seconds=900,
    ):
        if (
           isinstance(ttl_seconds, bool)
           or not isinstance(ttl_seconds, int)
           or ttl_seconds <= 0
        ):
           raise ValueError("ttl_seconds must be a positive integer")

        self.ttl_seconds = ttl_seconds

        self._redis = redis.Redis(
            host=host,
            port=port,
            db=db,
            password=password,
            decode_responses=True,
        )

    def ping(self) -> bool:
        """Check whether Redis is reachable."""
        return bool(self._redis.ping())

    def _session_prefix(self, session_id: str) -> str:
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

        return f"vault:{session_id}:"

    def store(self, session_id: str, mapping: dict) -> None:
        """Save or merge mappings for a session, refreshing their TTL."""

        prefix = self._session_prefix(session_id)

        if not isinstance(mapping, dict):
            raise TypeError("mapping must be a dictionary")

        for placeholder, original_value in mapping.items():
            if not isinstance(placeholder, str):
                raise TypeError("placeholder must be a string")

            if not PLACEHOLDER_PATTERN.fullmatch(placeholder):
                raise ValueError(f"Invalid placeholder: {placeholder}")

            if not isinstance(original_value, str):
                raise TypeError("original_value must be a string")

        if not mapping:
            return

        with self._redis.pipeline(transaction=True) as pipe:
            for placeholder, original_value in mapping.items():
                key = prefix + placeholder
                pipe.set(key, original_value, ex=self.ttl_seconds)

            pipe.execute()

    def get_mapping(self, session_id: str) -> dict:
        """Return all currently available mappings for a session."""
        prefix = self._session_prefix(session_id)
        result = {}

        for key in self._redis.scan_iter(match=prefix + "*"):
            # Confirm the exact prefix to avoid wildcard session-ID matches.
            if not key.startswith(prefix):
                continue

            placeholder = key[len(prefix):]
            original_value = self._redis.get(key)

            if original_value is not None:
                result[placeholder] = original_value

        return result

    def unmask_text(self, masked_text: str, session_id: str) -> str:
        """Restore known placeholders without leaking across sessions."""
        if not masked_text:
            return masked_text

        session_mapping = self.get_mapping(session_id)

        def replace_placeholder(match):
            placeholder = match.group(0)
            return session_mapping.get(placeholder, placeholder)

        return PLACEHOLDER_PATTERN.sub(replace_placeholder, masked_text)

    def clear_session(self, session_id: str) -> None:
        """Remove all mappings belonging to a session."""
        prefix = self._session_prefix(session_id)

        keys = [
            key
            for key in self._redis.scan_iter(match=prefix + "*")
            if key.startswith(prefix)
        ]

        if keys:
            self._redis.delete(*keys)

    def session_count(self) -> int:
        """Count distinct sessions that currently have stored mappings."""
        sessions = set()

        for key in self._redis.scan_iter(match="vault:*:*"):
            if not key.startswith("vault:"):
                continue

            # The placeholder is the final colon-separated key component.
            session_id = key[len("vault:"):].rsplit(":", 1)[0]
            sessions.add(session_id)

        return len(sessions)

    def has_session(self, session_id: str) -> bool:
        """Check whether a session currently has stored mappings."""
        prefix = self._session_prefix(session_id)

        return any(
            key.startswith(prefix)
            for key in self._redis.scan_iter(match=prefix + "*")
        )
