from dashboard.rbac_view import (
    build_policy_rows,
    build_role_matrix,
)


def test_role_matrix_contains_three_roles():
    rows = build_role_matrix()

    assert len(rows) == 3
    assert {row["Role"] for row in rows} == {
        "Administrator",
        "Security Analyst",
        "Viewer",
    }


def test_administrator_can_manage_policies():
    rows = build_role_matrix()
    admin = next(row for row in rows if row["Role"] == "Administrator")

    assert admin["Manage policies"] is True
    assert admin["Manage roles"] is True


def test_analyst_cannot_manage_policies():
    rows = build_role_matrix()
    analyst = next(row for row in rows if row["Role"] == "Security Analyst")

    assert analyst["Dismiss alerts"] is True
    assert analyst["Manage policies"] is False
    assert analyst["Manage roles"] is False


def test_viewer_has_read_only_permissions():
    rows = build_role_matrix()
    viewer = next(row for row in rows if row["Role"] == "Viewer")

    assert viewer["View dashboard"] is True
    assert viewer["View security events"] is True
    assert viewer["Dismiss alerts"] is False
    assert viewer["Manage policies"] is False


def test_policy_table_contains_eight_controls():
    assert len(build_policy_rows()) == 8


def test_policy_inventory_does_not_claim_runtime_configuration():
    for policy in build_policy_rows():
        assert policy["Runtime configurable"] == "No"
        assert policy["Implementation"] == "Implemented in code"


def test_policy_inventory_contains_sources():
    for policy in build_policy_rows():
        assert policy["Policy ID"]
        assert policy["Source"].startswith("src/security/")
