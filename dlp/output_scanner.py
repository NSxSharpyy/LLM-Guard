
"""Output Response DLP Scanner (Day 15).

Scans the final LLM response after legitimate placeholders have
been restored. Flags detected PII that does not belong to the
current session's known vault mappings.
"""


class OutputScanner:
    """Detect unexpected PII in final LLM responses."""

    def __init__(self, vault, engine):
        """Initialize the scanner with the existing DLP engine."""

        self._engine = engine
        self._vault = vault

    def scan(self, final_response: str, session_id: str):
        """Detect unexpected PII in a final response.

        Returns:
            tuple:
                is_clean (bool)
                findings (list[dict])
        """

        if not isinstance(final_response, str):
            raise TypeError("final_response must be a string")

        if not isinstance(session_id, str) or not session_id.strip():
            raise ValueError("session_id must be a non-empty string")

        if not final_response:
            return True, []

        # Reuse the existing DLP detection engine.
        _, entities_found = self._engine.redact(final_response)

        # Retrieve legitimate values belonging to this session.
        known_values = set(
            self._vault.get_mapping(session_id).values()
        )

        findings = []

        for entity in entities_found:
            value = entity["original_value"]

            # Legitimately restored session data is not a finding.
            if value in known_values:
                continue

            # Never expose the complete sensitive value.
            findings.append({
                "entity_type": entity["entity_type"],
                "value_sample": (
                    value[:4] + "..."
                    if len(value) > 4
                    else "***"
                ),
                "score": entity["score"],
            })

        is_clean = len(findings) == 0

        return is_clean, findings
