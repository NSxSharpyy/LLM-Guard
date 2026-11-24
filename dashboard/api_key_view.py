"""Day 16: Client API key management screen."""

import streamlit as st
from redis.exceptions import RedisError

from src.security.api_key_store import (
    ROLE_RPM_LIMITS,
    create_client_api_key,
    list_active_client_api_keys,
)


def render_api_key_management():
    """Render client API key generation and active key listing."""
    st.header("Client API Key Management")

    st.caption(
        "Generate client API keys, assign corporate roles, "
        "and view active client keys."
    )

    st.subheader("Generate New Client API Key")

    with st.form("client_api_key_form", clear_on_submit=True):
        client_name = st.text_input(
            "Client Name",
            max_chars=80,
            placeholder="Enter client or application name",
        )

        user_role = st.selectbox(
            "Assigned Corporate Role",
            options=sorted(ROLE_RPM_LIMITS),
        )

        submitted = st.form_submit_button(
            "Generate API Key",
            type="primary",
        )

    if submitted:
        try:
            raw_key, metadata = create_client_api_key(
                client_name=client_name,
                user_role=user_role,
            )
            st.session_state["day16_generated_api_key"] = raw_key
            st.success(
                f"API key generated for {metadata['client_name']}."
            )
        except (ValueError, RuntimeError) as exc:
            st.error(str(exc))
        except RedisError:
            st.error("The API key registry is unavailable. Try again later.")

    # Reveal the raw key for this render only. Redis stores only its hash.
    revealed_key = st.session_state.pop("day16_generated_api_key", None)

    if revealed_key:
        st.warning(
            "Copy this API key now. It will not be displayed again."
        )
        st.code(revealed_key)

    st.divider()
    st.subheader("Active Client API Keys")

    try:
        active_keys = list_active_client_api_keys()
    except RedisError:
        st.error("Unable to retrieve active API keys from Redis.")
        return

    if active_keys:
        st.dataframe(
            active_keys,
            hide_index=True,
            width="stretch",
        )
    else:
        st.info("No generated client API keys are currently registered.")
