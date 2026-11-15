"""LLM-Guard SOC dashboard with live JSONL telemetry."""


# Make the repository root available for project package imports.
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import shutil
import subprocess
from datetime import datetime
from urllib.error import URLError
from urllib.request import urlopen

import streamlit as st

from dashboard.event_reader import JsonlEventTailReader
from telemetry.telemetry_logger import DEFAULT_LOG_PATH


PROXY_HEALTH_URL = "http://127.0.0.1:8000/healthz"
MOCK_LLM_HEALTH_URL = "http://127.0.0.1:8001/healthz"

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



def check_mock_llm():
    """Check the locally running mock LLM HTTP health endpoint."""
    try:
        with urlopen(MOCK_LLM_HEALTH_URL, timeout=2) as response:
            if response.status == 200:
                return "Healthy", "HTTP 200 from mock LLM health endpoint"
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
st.sidebar.markdown("**Current module:** Live Security Overview")
st.sidebar.info(
    "Live telemetry is read from the local JSONL security event stream. "
    "The dashboard refreshes this panel every two seconds."
)

st.header("Security Overview")


# Keep one reader per Streamlit browser session so file offsets and
# cumulative counters survive periodic fragment reruns.
if "event_reader" not in st.session_state:
    st.session_state.event_reader = JsonlEventTailReader(
        path=DEFAULT_LOG_PATH,
        max_recent=100,
    )


@st.fragment(run_every="2s")
def render_live_telemetry():
    """Poll the log and refresh telemetry metrics and the event table."""
    snapshot = st.session_state.event_reader.poll()

    total_col, allowed_col, blocked_col, malformed_col = st.columns(4)

    if snapshot.available:
        total_value = snapshot.total
        allowed_value = snapshot.allowed
        blocked_value = snapshot.blocked
        malformed_value = snapshot.malformed
    else:
        total_value = "—"
        allowed_value = "—"
        blocked_value = "—"
        malformed_value = "—"

    total_col.metric("Total Events", total_value)
    allowed_col.metric("Allowed Events", allowed_value)
    blocked_col.metric("Blocked Events", blocked_value)
    malformed_col.metric("Malformed Records", malformed_value)

    st.caption(snapshot.message)
    st.caption(f"Telemetry source: `{DEFAULT_LOG_PATH}`")

    if not snapshot.available:
        st.info(
            "The security event log is not available yet. "
            "Start the telemetry producer to create it."
        )
    elif not snapshot.recent_events:
        st.info("No valid security events have been recorded yet.")
    else:
        st.subheader("Recent Security Events")

        # Newest events appear first in the dashboard.
        recent = list(reversed(snapshot.recent_events))

        st.dataframe(
            recent,
            hide_index=True,
            width="stretch",
        )

    if snapshot.malformed:
        st.warning(
            f"{snapshot.malformed} malformed or schema-invalid "
            "records were skipped."
        )


render_live_telemetry()

st.divider()

st.header("System Health")

proxy_state, proxy_detail = check_proxy()
redis_state, redis_detail = check_container("llm-guard-redis")
mock_state, mock_detail = check_mock_llm()

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
