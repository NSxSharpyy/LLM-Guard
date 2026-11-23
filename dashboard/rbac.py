"""Role-based permissions for the LLM-Guard SOC dashboard."""

from collections.abc import Mapping

DASHBOARD_VIEW = "dashboard.view"
EVENTS_VIEW = "events.view"
ALERTS_DISMISS = "alerts.dismiss"
POLICIES_VIEW = "policies.view"
POLICIES_MANAGE = "policies.manage"
RBAC_VIEW = "rbac.view"
RBAC_MANAGE = "rbac.manage"

ROLE_PERMISSIONS: Mapping[str, frozenset[str]] = {
    "administrator": frozenset({
        DASHBOARD_VIEW,
        EVENTS_VIEW,
        ALERTS_DISMISS,
        POLICIES_VIEW,
        POLICIES_MANAGE,
        RBAC_VIEW,
        RBAC_MANAGE,
    }),
    "analyst": frozenset({
        DASHBOARD_VIEW,
        EVENTS_VIEW,
        ALERTS_DISMISS,
        POLICIES_VIEW,
        RBAC_VIEW,
    }),
    "viewer": frozenset({
        DASHBOARD_VIEW,
        EVENTS_VIEW,
        POLICIES_VIEW,
    }),
}


def permissions_for_role(role: str) -> frozenset[str]:
    """Return permissions for a role. Unknown roles receive no permissions."""
    if not isinstance(role, str):
        return frozenset()

    return ROLE_PERMISSIONS.get(role.strip().lower(), frozenset())


def has_permission(role: str, permission: str) -> bool:
    """Default-deny permission evaluation."""
    if not isinstance(permission, str) or not permission.strip():
        return False

    return permission in permissions_for_role(role)
