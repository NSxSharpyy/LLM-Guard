from dashboard.rbac import (
    ALERTS_DISMISS,
    DASHBOARD_VIEW,
    EVENTS_VIEW,
    POLICIES_MANAGE,
    POLICIES_VIEW,
    RBAC_MANAGE,
    RBAC_VIEW,
    has_permission,
    permissions_for_role,
)


def test_administrator_has_management_permissions():
    assert has_permission("administrator", POLICIES_MANAGE)
    assert has_permission("administrator", RBAC_MANAGE)


def test_analyst_can_view_and_dismiss_alerts():
    assert has_permission("analyst", DASHBOARD_VIEW)
    assert has_permission("analyst", EVENTS_VIEW)
    assert has_permission("analyst", ALERTS_DISMISS)
    assert has_permission("analyst", POLICIES_VIEW)
    assert has_permission("analyst", RBAC_VIEW)


def test_analyst_cannot_manage_policies_or_roles():
    assert not has_permission("analyst", POLICIES_MANAGE)
    assert not has_permission("analyst", RBAC_MANAGE)


def test_viewer_has_read_only_access():
    assert has_permission("viewer", DASHBOARD_VIEW)
    assert has_permission("viewer", EVENTS_VIEW)
    assert has_permission("viewer", POLICIES_VIEW)
    assert not has_permission("viewer", ALERTS_DISMISS)
    assert not has_permission("viewer", POLICIES_MANAGE)
    assert not has_permission("viewer", RBAC_MANAGE)
    assert not has_permission("viewer", RBAC_VIEW)


def test_unknown_role_is_denied():
    assert permissions_for_role("unknown") == frozenset()
    assert not has_permission("unknown", DASHBOARD_VIEW)


def test_role_names_are_case_normalized():
    assert has_permission("ADMINISTRATOR", DASHBOARD_VIEW)


def test_empty_permission_is_denied():
    assert not has_permission("administrator", "")
    assert not has_permission("administrator", "   ")


def test_non_string_role_is_denied():
    assert permissions_for_role(None) == frozenset()
