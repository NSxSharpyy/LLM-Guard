from dashboard.rbac_view import build_role_rows
from src.security.auth import DEFAULT_API_KEYS


def test_dashboard_displays_actual_backend_roles():
    rows = build_role_rows()

    expected = {
        (tenant.user_role, tenant.rpm_limit)
        for tenant in DEFAULT_API_KEYS.values()
    }

    actual = {
        (row["Current Role"], row["Requests Per Minute (RPM)"])
        for row in rows
    }

    assert actual == expected


def test_current_default_roles_are_present():
    roles = {row["Current Role"] for row in build_role_rows()}

    assert roles == {"free", "pro", "enterprise"}


def test_request_limits_match_backend_configuration():
    limits = {
        row["Current Role"]: row["Requests Per Minute (RPM)"]
        for row in build_role_rows()
    }

    assert limits == {
        "free": 5,
        "pro": 60,
        "enterprise": 10000,
    }


def test_token_limits_are_not_invented():
    for row in build_role_rows():
        assert row["Assigned Token Limit"] == "Not configured"


def test_model_access_is_not_misrepresented():
    for row in build_role_rows():
        assert (
            row["Model Access Permissions"]
            == "No role-specific model allowlist configured"
        )
