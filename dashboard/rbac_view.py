"""Read-only RBAC and security policy dashboard view."""

import streamlit as st

from dashboard.rbac import (
    ROLE_PERMISSIONS,
    DASHBOARD_VIEW,
    EVENTS_VIEW,
    ALERTS_DISMISS,
    POLICIES_VIEW,
    POLICIES_MANAGE,
    RBAC_VIEW,
    RBAC_MANAGE,
)
from dashboard.policy_catalog import list_policies


ROLE_LABELS = {
    "administrator": "Administrator",
    "analyst": "Security Analyst",
    "viewer": "Viewer",
}

PERMISSION_LABELS = {
    DASHBOARD_VIEW: "View dashboard",
    EVENTS_VIEW: "View security events",
    ALERTS_DISMISS: "Dismiss alerts",
    POLICIES_VIEW: "View policies",
    POLICIES_MANAGE: "Manage policies",
    RBAC_VIEW: "View RBAC matrix",
    RBAC_MANAGE: "Manage roles",
}


def build_role_matrix():
    """Build a presentation-friendly role and permission matrix."""
    rows = []

    for role, permissions in ROLE_PERMISSIONS.items():
        row = {"Role": ROLE_LABELS[role]}

        for permission, label in PERMISSION_LABELS.items():
            row[label] = permission in permissions

        rows.append(row)

    return rows


def build_policy_rows():
    """Build the security policy inventory for dashboard display."""
    return [
        {
            "Policy ID": policy.policy_id,
            "Component": policy.component,
            "Action": policy.action,
            "Description": policy.description,
            "Implementation": "Implemented in code",
            "Runtime configurable": "No",
            "Source": policy.source_file,
        }
        for policy in list_policies()
    ]


def render_rbac_policies():
    """Render the RBAC matrix and implemented security policy inventory."""

    st.header("RBAC & Security Policies")

    st.caption(
        "Role-based permissions and the implemented LLM-Guard "
        "security control inventory."
    )

    st.warning(
        "Dashboard authentication is not yet connected. "
        "The role matrix is currently a reference model, not "
        "enforced access control for authenticated dashboard users."
    )

    role_col, permission_col, policy_col = st.columns(3)

    role_col.metric("Dashboard Roles", len(ROLE_PERMISSIONS))
    permission_col.metric("Permission Types", len(PERMISSION_LABELS))
    policy_col.metric("Implemented Security Controls", len(list_policies()))

    st.divider()

    st.subheader("Role-Permission Matrix")

    st.dataframe(
        build_role_matrix(),
        hide_index=True,
        width="stretch",
    )

    st.caption(
        "True indicates that the role is assigned the permission "
        "in the current RBAC design."
    )

    st.divider()

    st.subheader("Security Policy Inventory")

    st.dataframe(
        build_policy_rows(),
        hide_index=True,
        width="stretch",
        column_config={
            "Description": st.column_config.TextColumn(width="large"),
            "Source": st.column_config.TextColumn(width="medium"),
        },
    )

    st.info(
        "Policy inventory is read-only. The listed controls are "
        "implemented in the existing security modules. "
        "Changing their runtime behavior is not supported yet."
    )
