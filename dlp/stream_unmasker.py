"""Ring-buffer streaming unmask engine (Day 12).

Handles placeholder tags split across streamed LLM response chunks.
Only releases text that is safe to send to the client.
"""

import re


COMPLETE_TAG_PATTERN = re.compile(r"<([A-Z_]+\d+)>")
PARTIAL_TAG_PATTERN = re.compile(r"<(?:[A-Z_][A-Z_0-9]*)?")


class StreamUnmasker:
    """Buffers incomplete placeholder fragments during streaming."""

    def __init__(self, vault, session_id, json_mode=False):
        if not isinstance(json_mode, bool):
            raise TypeError("json_mode must be a boolean")

        self._vault = vault
        self._session_id = session_id
        self._json_mode = json_mode
        self._buffer = ""
        self._closed = False

    def feed(self, chunk: str) -> str:
        """Accept a chunk and return currently safe, unmasked text."""

        if self._closed:
            raise RuntimeError("Cannot feed after flush()")

        if not isinstance(chunk, str):
            raise TypeError("chunk must be a string")

        self._buffer += chunk
        if self._json_mode:
            return ""
        last_open = self._buffer.rfind("<")
        last_close = self._buffer.rfind(">")

        if last_open > last_close:
            candidate = self._buffer[last_open:]

            if PARTIAL_TAG_PATTERN.fullmatch(candidate):
                safe_part = self._buffer[:last_open]
                held_part = candidate
            else:
                safe_part = self._buffer
                held_part = ""
        else:
            safe_part = self._buffer
            held_part = ""

        self._buffer = held_part

        return self._unmask(safe_part)

    def flush(self):
        if self._closed:
            raise RuntimeError("Cannot flush: StreamUnmasker is already closed")

        remaining = self._buffer
        self._buffer = ""
        self._closed = True

        if self._json_mode:
            return self._vault.unmask_json(
                remaining,
                self._session_id,
            )

        return self._unmask(remaining)

    def _unmask(self, text: str) -> str:
        """Restore placeholders using the existing vault mapping."""

        if not text:
            return text

        mapping = self._vault.get_mapping(self._session_id)

        def replace(match):
            placeholder = match.group(0)
            return mapping.get(placeholder, placeholder)

        return COMPLETE_TAG_PATTERN.sub(replace, text)
