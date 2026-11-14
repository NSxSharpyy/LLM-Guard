
"""
Deterministic semantic placeholder management.

Assigns sequential placeholders to sensitive values while ensuring
repeated occurrences of the same value receive the same placeholder.
"""


class PlaceholderManager:
    """Manage deterministic placeholders for detected sensitive values."""

    def __init__(self):
        self.value_mapping = {}
        self.entity_counters = {}

    def get_placeholder(self, entity_type: str, original_value: str) -> str:
        """
        Return an existing placeholder or generate a new one.

        Placeholder numbering is maintained separately for each entity.
        """

        key = (entity_type, original_value)

        # Reuse the placeholder for repeated values.
        if key in self.value_mapping:
            return self.value_mapping[key]

        # Increment the counter for this entity type.
        count = self.entity_counters.get(entity_type, 0) + 1
        self.entity_counters[entity_type] = count

        # Convert entity names into readable placeholder prefixes.
        prefix_mapping = {
            "EMAIL_ADDRESS": "EMAIL",
            "PHONE_NUMBER": "PHONE",
            "AADHAAR_CARD": "AADHAAR",
            "PAN_CARD": "PAN",
            "AWS_ACCESS_KEY": "AWS_KEY",
            "AWS_SECRET_KEY": "AWS_SECRET",
            "JWT_TOKEN": "JWT",
        }

        prefix = prefix_mapping.get(entity_type, entity_type)

        placeholder = f"<{prefix}_{count}>"

        self.value_mapping[key] = placeholder

        return placeholder

    def get_mapping(self) -> dict:
        """
        Return a reverse mapping of placeholders to original values.

        Example:
            {
                "<EMAIL_1>": "john.doe@company.com",
                "<EMAIL_2>": "jane.smith@client.org"
            }
        """
        return {
            placeholder: original_value
            for (_, original_value), placeholder
            in self.value_mapping.items()
        }

    def reset(self):
        """Clear mappings and counters for a fresh masking operation."""
        self.value_mapping.clear()
        self.entity_counters.clear()
