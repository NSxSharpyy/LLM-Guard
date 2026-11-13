"""Initial LLM-Guard SOC dashboard shell."""

import shutil
import subprocess
from datetime import datetime
from urllib.error import URLError
from urllib.request import urlopen

import streamlit as st


PROXY_HEALTH_URL = "http://127.0.0.1:8000/health"

STATUS_ICONS = {
    "Healthy": "🟢",
    "Running": "🟢",
    "Starting": "🟡",
    "Offline": "🔴",
    "Unhealthy": "🔴",
    "Unknown": "⚪",
}


def check_proxy():
    """Check the real HTTP health endpoint of the proxy."""
    try:
        with urlopen(PROXY_HEALTH_URL, timeout=2) as response:
            if response.status == 200:
                return "Healthy", "HTTP 200 from proxy health endpoint"
            return "Unhealthy", f"Unexpected HTTP status: {response.status}"
    except (URLError, TimeoutError, OSError) as exc:
        return "Offline", str(exc)[:180]


def check_container(container_name):
    """Inspect a Docker container without changing its state."""
    docker_path = shutil.which("docker")

    if not docker_path:
        return "Unknown", "Docker CLI is not available."

    command = [
        docker_path,
        "inspect",
        "--format",
        "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}}",
        container_name,
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "Unknown", str(exc)[:180]

    if result.returncode != 0:
        error = result.stderr.strip()
        if "connect" in error.lower() or "pipe" in error.lower():
            return "Unknown", "Docker engine is unavailable."
        return "Offline", error[:180] or "Container unavailable."

    parts = result.stdout.strip().split("|", maxsplit=1)
    if len(parts) != 2:
        return "Unknown", "Unexpected Docker inspection response."

    container_state, health_state = parts

    if container_state != "running":
        return "Offline", f"Container state: {container_state}"

    if health_state == "healthy":
        return "Healthy", "Docker healthcheck passed."
    if health_state == "unhealthy":
        return "Unhealthy", "Docker healthcheck failed."
    if health_state == "starting":
        return "Starting", "Docker healthcheck is starting."

    return "Running", "Container is running; no healthcheck configured."


def render_service(column, name, state, detail):
    """Render an individual service health indicator."""
    icon = STATUS_ICONS.get(state, "⚪")

    with column:
        st.subheader(name)
        st.markdown(f"### {icon} {state}")
        st.caption(detail)


# ---------------------- PAGE CONFIGURATION ----------------------

st.set_page_config(
    page_title="LLM-Guard | SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.title("🛡️ LLM-Guard SOC Dashboard")
st.caption("AI Security Posture Management | Security Operations Center")

st.sidebar.title("LLM-Guard")
st.sidebar.caption("Security Operations Dashboard")
st.sidebar.markdown("---")
st.sidebar.markdown("**Current module:** Overview")
st.sidebar.info(
    "Initial dashboard shell. Live telemetry integration is scheduled "
    "for Day 7."
)

st.markdown(
    """
    <div style="
        padding: 12px 16px;
        border-radius: 8px;
        background-color: rgba(128,128,128,0.12);
        border-left: 4px solid #D69E36;
        margin-bottom: 18px;">
        <strong>Dashboard shell:</strong>
        Telemetry counters are not connected yet.
        Service health indicators below use live checks.
    </div>
    """,
    unsafe_allow_html=True,
)

# ---------------------- KPI SECTION ----------------------

st.header("Security Overview")

total_col, blocked_col = st.columns(2)

with total_col:
    st.metric(
        label="Total Requests",
        value="—",
        help="Live request counts will be connected during Day 7.",
    )

with blocked_col:
    st.metric(
        label="Blocked Requests",
        value="—",
        help="Live block counts will be connected during Day 7.",
    )

st.caption(
    "Request KPIs are intentionally unavailable until a telemetry source "
    "is connected. A dash is not a zero count."
)

st.divider()

# ---------------------- SYSTEM HEALTH SECTION ----------------------

st.header("System Health")

proxy_state, proxy_detail = check_proxy()
redis_state, redis_detail = check_container("llm-guard-redis")
mock_state, mock_detail = check_container("llm-guard-mock-llm")

health_col1, health_col2, health_col3 = st.columns(3)

render_service(health_col1, "Proxy", proxy_state, proxy_detail)
render_service(health_col2, "Redis", redis_state, redis_detail)
render_service(health_col3, "Mock LLM", mock_state, mock_detail)

st.divider()

checked_at = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")

st.caption(f"Health checks last performed: {checked_at}")
st.caption(
    "LLM-Guard | Member 6 — DevOps, SIEM Logging and SOC Dashboard"
)
