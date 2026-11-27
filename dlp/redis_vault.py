"""Redis-backed, session-scoped reversible lookup vault (Day 9).

Stores placeholder -> original_value mappings in Redis.
Each mapping expires after the configured TTL.
"""

import hashlib
import hmac
import json
import os
import re

import redis
from dlp.vault import PLACEHOLDER_PATTERN


class RedisVault:
    """Redis-backed replacement for the in-memory Vault."""

    PREFIX_MAPPING = {
        "EMAIL_ADDRESS": "EMAIL",
        "PHONE_NUMBER": "PHONE",
        "AADHAAR_CARD": "AADHAAR",
        "PAN_CARD": "PAN",
        "AWS_ACCESS_KEY": "AWS_KEY",
        "AWS_SECRET_KEY": "AWS_SECRET",
        "JWT_TOKEN": "JWT",
    }

    ALLOCATE_SCRIPT = """
    local results = {}
    local index_key = KEYS[1]

    for i = 2, #KEYS, 3 do
        local reverse_key = KEYS[i]
        local counter_key = KEYS[i + 1]
        local forward_prefix = KEYS[i + 2]

        local entity_index = math.floor((i - 2) / 3)
        local arg_index = entity_index * 3 + 1

        local prefix = ARGV[arg_index]
        local original_value = ARGV[arg_index + 1]
        local ttl = tonumber(ARGV[arg_index + 2])

        local existing = redis.call("GET", reverse_key)
        local placeholder
        local forward_key

        if existing then
            placeholder = existing
        else
            local count = redis.call("INCR", counter_key)
            placeholder = "<" .. prefix .. "_" .. count .. ">"
        end

        forward_key = forward_prefix .. placeholder

        redis.call(
            "SET",
            forward_key,
            original_value,
            "EX",
            ttl
        )

        redis.call("SET", reverse_key, placeholder, "EX", ttl)
        redis.call("EXPIRE", counter_key, ttl)

        redis.call(
            "SADD",
            index_key,
            reverse_key,
            counter_key,
            forward_key
        )

        redis.call("EXPIRE", index_key, ttl)

        table.insert(results, placeholder)
    end

    return results
    """
    CLEAR_SESSION_SCRIPT = """
    local index_key = KEYS[1]
    local members = redis.call("SMEMBERS", index_key)
    local deleted = 0

    for i = 1, #members, 500 do
        local batch = {}

        for j = i, math.min(i + 499, #members) do
            table.insert(batch, members[j])
        end

        deleted = deleted + redis.call("DEL", unpack(batch))
    end

    redis.call("DEL", index_key)

    return deleted
    """

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
        self._hmac_secret = os.getenv("DLP_HMAC_SECRET")

        if self._hmac_secret:
            self._hmac_secret = self._hmac_secret.encode("utf-8")

            if len(self._hmac_secret) < 32:
                raise ValueError(
                    "DLP_HMAC_SECRET must contain at least 32 bytes"
                )

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

        index_key = f"vaultmeta:{session_id}:keys"
        forward_keys = []

        with self._redis.pipeline(transaction=True) as pipe:
            for placeholder, original_value in mapping.items():
                key = prefix + placeholder
                forward_keys.append(key)
                pipe.set(key, original_value, ex=self.ttl_seconds)

            pipe.sadd(index_key, *forward_keys)
            pipe.expire(index_key, self.ttl_seconds)

            pipe.execute()

    def allocate_placeholders(
        self,
        session_id: str,
        entities: list,
    ) -> list:
        """Atomically allocate session-wide placeholders in Redis."""

        prefix = self._session_prefix(session_id)

        if not self._hmac_secret:
            raise RuntimeError(
                "DLP_HMAC_SECRET environment variable is required"
            )

        if not isinstance(entities, list):
            raise TypeError("entities must be a list")

        if not entities:
            return []

        index_key = f"vaultmeta:{session_id}:keys"

        keys = [index_key]
        args = []

        forward_prefix = prefix

        for entity in entities:
            if not isinstance(entity, dict):
                raise TypeError("each entity must be a dictionary")

            entity_type = entity.get("entity_type")
            original_value = entity.get("original_value")

            if (
               not isinstance(entity_type, str)
               or not re.fullmatch(r"[A-Z][A-Z_]*", entity_type)
            ):
               raise ValueError(
                   "entity_type must contain only uppercase letters and underscores"
               )

            if not isinstance(original_value, str):
                raise TypeError("original_value must be a string")

            placeholder_prefix = self.PREFIX_MAPPING.get(
                entity_type,
                entity_type,
            )

            digest_input = (
                entity_type + "\0" + original_value
            ).encode("utf-8")

            digest = hmac.new(
                self._hmac_secret,
                digest_input,
                hashlib.sha256,
            ).hexdigest()

            reverse_key = (
                f"vaultmeta:{session_id}:reverse:"
                f"{entity_type}:{digest}"
            )

            counter_key = (
                f"vaultmeta:{session_id}:counter:{placeholder_prefix}"
            )

            keys.extend([
                reverse_key,
                counter_key,
                forward_prefix,
            ])

            args.extend([
                placeholder_prefix,
                original_value,
                self.ttl_seconds,
            ])

        script = self._redis.register_script(self.ALLOCATE_SCRIPT)

        return script(
            keys=keys,
            args=args,
            client=self._redis,
        )

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
        self._session_prefix(session_id)

        if not isinstance(masked_text, str):
            raise TypeError("masked_text must be a string")

        if not masked_text:
            return masked_text

        session_mapping = self.get_mapping(session_id)

        def replace_placeholder(match):
            placeholder = match.group(0)
            return session_mapping.get(placeholder, placeholder)

        return PLACEHOLDER_PATTERN.sub(replace_placeholder, masked_text)

    def unmask_json(self, masked_json: str, session_id: str) -> str:
        """Restore placeholders while preserving valid JSON structure."""

        self._session_prefix(session_id)

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

        session_mapping = self.get_mapping(session_id)

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
        """Atomically remove all indexed data associated with a session."""

        self._session_prefix(session_id)

        index_key = f"vaultmeta:{session_id}:keys"

        script = self._redis.register_script(
            self.CLEAR_SESSION_SCRIPT
        )

        script(
            keys=[index_key],
            client=self._redis,
        )

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
