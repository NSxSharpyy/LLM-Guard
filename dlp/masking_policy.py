
"""
Role-aware masking policy (Day 17).

This module contains only authorization policy configuration.
It does not perform detection, masking, or vault operations.

MOCK DATA — TEMPORARY:
Roles are currently supplied as plain strings.
M4's RBAC system will eventually provide the authenticated
user's resolved role.
"""

# Entity types allowed to pass through UNMASKED for each role.
# Anything not listed is masked by default.

ROLE_POLICIES = {
    "Finance": {
        "CREDIT_CARD",
        "US_SSN",
    },

    "Developer": {
        "AWS_ACCESS_KEY",
        "AWS_SECRET_KEY",
        "JWT_TOKEN",
        "DB_CONNECTION_STRING",
        "PRIVATE_KEY",
        "INTERNAL_IPV4",
    },

    "General": set(),
}

# Safest fallback: mask everything.
DEFAULT_ROLE = "General"


class MaskingPolicy:
    """Handles role-based entity visibility decisions."""

    def __init__(self, role_policies=None):
        self._policies = (
            role_policies
            if role_policies is not None
            else ROLE_POLICIES
        )

    def is_unmasked_for_role(
        self,
        entity_type: str,
        role: str
    ) -> bool:
        """
        Return True if an entity is allowed to remain unmasked.

        Unknown roles always fall back to General.
        """

        if role not in self._policies:
            role = DEFAULT_ROLE

        return entity_type in self._policies.get(role, set())

    def known_roles(self) -> list:
        """Return all configured role names."""
        return list(self._policies.keys())

    def allowed_entities_for_role(self, role: str) -> set:
        """Return entities permitted to remain unmasked."""

        if role not in self._policies:
            role = DEFAULT_ROLE

        return set(self._policies.get(role, set()))
