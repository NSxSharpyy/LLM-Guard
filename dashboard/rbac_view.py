"""Day 15: Display current API roles, quotas and model access configuration."""

import streamlit as st

from src.security.auth import DEFAULT_API_KEYS


def build_role_rows():
    """Read actual roles and RPM quotas from the backend configuration."""
    configured_roles = {
        (tenant.user_role, tenant.rpm_limit)
        for tenant in DEFAULT_API_KEYS.values()
    }

    return [
        {
            "Current Role": role,
            "Requests Per Minute (RPM)": rpm_limit,
            "Assigned Token Limit": "Not configured",
            "Model Access Permissions": (
                "No role-specific model allowlist configured"
            ),
        }
        for role, rpm_limit in sorted(configured_roles)
    ]


def render_rbac_policies():
    """Render the assigned Day 15 RBAC role and policy view."""
    st.header("RBAC & Policies")

    st.caption(
        "Current API roles, configured request quotas, "
        "token limits and model access permissions."
    )

    rows = build_role_rows()

    st.metric("Current API Roles", len(rows))

    st.subheader("Role Configuration")

    st.dataframe(
        rows,
        hide_index=True,
        width="stretch",
    )

    st.info(
        "The backend currently configures requests-per-minute quotas. "
        "These are not token limits. Role-specific token limits and "
        "model access allowlists are not configured in the inspected "
        "backend."
    )
