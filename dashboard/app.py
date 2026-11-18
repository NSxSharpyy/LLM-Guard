"""LLM-Guard SOC dashboard with live JSONL telemetry."""


# Make the repository root available for project package imports.
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import shutil
import subprocess
from datetime import datetime, time
from zoneinfo import ZoneInfo
from urllib.error import URLError
from urllib.request import urlopen

import altair as alt
import streamlit as st

from dashboard.event_reader import JsonlEventTailReader
from dashboard.event_filters import filter_events
from dashboard.alerts import HighSeverityAlertTracker
from dashboard.event_table import SORTABLE_FIELDS, paginate_events, sort_events, status_badge
from dashboard.analytics import action_distribution, hourly_volume, top_rule_counts
from telemetry.telemetry_logger import DEFAULT_LOG_PATH


PROXY_HEALTH_URL = "http://127.0.0.1:8000/healthz"
MOCK_LLM_HEALTH_URL = "http://127.0.0.1:8101/healthz"

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


def render_analytics(snapshot):
    """Render cumulative security analytics from the complete reader snapshot."""
    st.subheader("Visual Security Analytics")

    action_rows = action_distribution(
        snapshot.allowed,
        snapshot.blocked,
    )
    rule_rows = top_rule_counts(snapshot.rule_counts, limit=10)
    hourly_rows = hourly_volume(snapshot.hourly_counts)

    distribution_col, rules_col = st.columns(2)

    with distribution_col:
        st.markdown("#### Allowed vs Blocked Traffic")

        if snapshot.total:
            pie_chart = (
                alt.Chart(alt.Data(values=action_rows))
                .mark_arc(innerRadius=55, outerRadius=110)
                .encode(
                    theta=alt.Theta(
                        field="events",
                        type="quantitative",
                        title="Events",
                    ),
                    color=alt.Color(
                        field="action",
                        type="nominal",
                        title="Action",
                        scale=alt.Scale(
                            domain=["ALLOW", "BLOCK"],
                            range=["#22c55e", "#ef4444"],
                        ),
                    ),
                    tooltip=[
                        alt.Tooltip("action:N", title="Action"),
                        alt.Tooltip("events:Q", title="Events"),
                    ],
                )
                .properties(
                    title="Allowed vs Blocked Traffic",
                    height=280,
                )
            )
            st.altair_chart(pie_chart, width="stretch")
        else:
            st.info("No traffic data is available yet.")

    with rules_col:
        st.markdown("#### Top 10 Triggered Firewall Rules")

        if rule_rows:
            rule_chart = (
                alt.Chart(alt.Data(values=rule_rows))
                .mark_bar(color="#60a5fa")
                .encode(
                    x=alt.X(
                        "events:Q",
                        title="Number of events",
                    ),
                    y=alt.Y(
                        "rule_id:N",
                        title="Firewall rule",
                        axis=alt.Axis(labelLimit=320, labelOverlap=False),
                        sort=alt.SortField(
                            field="events",
                            order="descending",
                        ),
                    ),
                    tooltip=[
                        alt.Tooltip("rule_id:N", title="Rule ID"),
                        alt.Tooltip("events:Q", title="Events"),
                    ],
                )
                .properties(
                    title="Most Frequently Triggered Rules",
                    height=max(280, 34 * len(rule_rows)),
                )
            )
            st.altair_chart(rule_chart, width="stretch")
        else:
            st.info("No firewall-rule data is available yet.")

    st.markdown("#### Hourly Request Volume (UTC)")

    if hourly_rows:
        hourly_chart = (
            alt.Chart(alt.Data(values=hourly_rows))
            .mark_line(
                point=True,
                color="#38bdf8",
            )
            .encode(
                x=alt.X(
                    "hour:T",
                    title="Hour (UTC)",
                    scale=alt.Scale(type="utc"),
                    axis=alt.Axis(format="%b %d %H:%M", labelAngle=-35),
                ),
                y=alt.Y(
                    "events:Q",
                    title="Number of requests",
                ),
                tooltip=[
                    alt.Tooltip(
                        "hour:T",
                        title="Hour (UTC)",
                        format="%Y-%m-%d %H:%M",
                    ),
                    alt.Tooltip("events:Q", title="Requests"),
                ],
            )
            .properties(
                title="Request Volume by Hour",
                height=300,
            )
        )
        st.altair_chart(hourly_chart, width="stretch")
    else:
        st.info("No hourly request data is available yet.")


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

if "alert_tracker" not in st.session_state:
    st.session_state.alert_tracker = HighSeverityAlertTracker()


def poll_security_events():
    """Poll telemetry and pass newly appended events to the alert tracker."""
    snapshot = st.session_state.event_reader.poll()
    st.session_state.alert_tracker.ingest(snapshot.new_events)
    return snapshot


# Establish the initial reader baseline without alerting on historical records.
filter_initial_snapshot = poll_security_events()

recent_datetimes = [
    datetime.fromisoformat(
        event["timestamp"].replace("Z", "+00:00")
    ).astimezone(ZoneInfo("Asia/Kolkata"))
    for event in filter_initial_snapshot.recent_events
]

if recent_datetimes:
    default_start_date = min(recent_datetimes).date()
    default_end_date = max(recent_datetimes).date()
else:
    default_start_date = datetime.now().astimezone().date()
    default_end_date = default_start_date

local_timezone = ZoneInfo("Asia/Kolkata")

st.sidebar.divider()
st.sidebar.subheader("Event Search & Filters")
st.sidebar.caption(
    "Filters apply to the latest 100 validated events. "
    "Global KPIs and charts remain unfiltered."
)

filter_rule_id = st.sidebar.text_input(
    "Firewall Rule ID",
    placeholder="Search rule ID",
    key="event_filter_rule_id",
)

filter_client_ip = st.sidebar.text_input(
    "Client IP (exact match)",
    placeholder="e.g. 192.0.2.10",
    key="event_filter_client_ip",
)

filter_user_id = st.sidebar.text_input(
    "User ID",
    placeholder="Search user ID",
    key="event_filter_user_id",
)

severity_label = st.sidebar.selectbox(
    "Severity",
    options=["All", "High", "Other"],
    index=0,
    key="event_filter_severity",
)

st.sidebar.caption(
    "High = BLOCK with ML score above 0.90. "
    "Other = events not meeting that rule. "
    "This follows the existing telemetry audit policy."
)

filter_date_enabled = st.sidebar.checkbox(
    "Enable date/time range",
    value=False,
    key="event_filter_date_enabled",
)

filter_start_datetime = None
filter_end_datetime = None

if filter_date_enabled:
    filter_start_date = st.sidebar.date_input(
        "Start date (IST)",
        value=default_start_date,
        key="event_filter_start_date",
    )
    filter_start_time = st.sidebar.time_input(
        "Start time (IST)",
        value=time(0, 0),
        key="event_filter_start_time",
    )

    filter_end_date = st.sidebar.date_input(
        "End date (IST)",
        value=default_end_date,
        key="event_filter_end_date",
    )
    filter_end_time = st.sidebar.time_input(
        "End time (IST)",
        value=time(23, 59, 59),
        key="event_filter_end_time",
    )

    filter_start_datetime = datetime.combine(
        filter_start_date,
        filter_start_time,
    ).replace(tzinfo=local_timezone)

    filter_end_datetime = datetime.combine(
        filter_end_date,
        filter_end_time,
    ).replace(
        tzinfo=local_timezone,
        microsecond=999999,
    )


@st.fragment(run_every="2s")
def render_live_telemetry():
    """Poll the log and refresh telemetry metrics and the event table."""
    snapshot = poll_security_events()

    alert_tracker = st.session_state.alert_tracker

    # Toast notifications are consumed once; persistent banners remain visible.
    for event in alert_tracker.consume_notifications():
        st.toast(
            f"High-severity attack: {event['rule_id']} "
            f"(confidence {float(event['ml_score']) * 100:.1f}%)",
            icon="🚨",
            duration="long",
        )

    if alert_tracker.alerts:
        st.subheader("🚨 High-Severity Threat Alerts")

        if st.button("Dismiss visible alerts", key="dismiss_threat_alerts"):
            alert_tracker.clear()

        for event in list(alert_tracker.alerts):
            st.error(
                "**HIGH-SEVERITY ATTACK DETECTED**\n\n"
                f"**Rule:** {event['rule_id']}  |  "
                f"**Confidence:** {float(event['ml_score']) * 100:.1f}%\n\n"
                f"**Client IP:** {event['client_ip']}  |  "
                f"**User:** {event['user_id']} ({event['user_role']})\n\n"
                f"**Timestamp:** {event['timestamp']}\n\n"
                f"**Trace ID:** `{event['trace_id']}`",
                icon="🚨",
            )

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

    if snapshot.available and snapshot.total:
        render_analytics(snapshot)

    if not snapshot.available:
        st.info(
            "The security event log is not available yet. "
            "Start the telemetry producer to create it."
        )
    elif not snapshot.recent_events:
        st.info("No valid security events have been recorded yet.")
    else:
        st.subheader("Security Event Table")

        # Sorting and page-size controls.
        sort_col, order_col, size_col = st.columns([2, 1, 1])

        with sort_col:
            sort_label = st.selectbox(
                "Sort by",
                options=list(SORTABLE_FIELDS.keys()),
                key="event_table_sort_by",
            )

        with order_col:
            sort_order = st.selectbox(
                "Order",
                options=["Descending", "Ascending"],
                key="event_table_sort_order",
            )

        with size_col:
            page_size = st.selectbox(
                "Rows per page",
                options=[10, 25, 50],
                key="event_table_page_size",
            )

        sort_field = SORTABLE_FIELDS[sort_label]
        descending = sort_order == "Descending"

        severity_value = {
            "All": "ALL",
            "High": "HIGH",
            "Other": "OTHER",
        }[severity_label]

        filter_signature = (
            filter_rule_id.strip(),
            filter_client_ip.strip(),
            filter_user_id.strip(),
            severity_value,
            filter_date_enabled,
            filter_start_datetime,
            filter_end_datetime,
        )

        # Reset pagination when filters, sorting or page size change.
        view_signature = (
            sort_field,
            descending,
            page_size,
            filter_signature,
        )

        if st.session_state.get("event_table_view_signature") != view_signature:
            st.session_state["event_table_view_signature"] = view_signature
            st.session_state["event_table_page"] = 1

        try:
            filtered_events = filter_events(
                snapshot.recent_events,
                rule_id=filter_rule_id,
                client_ip=filter_client_ip,
                user_id=filter_user_id,
                severity=severity_value,
                start_datetime=filter_start_datetime,
                end_datetime=filter_end_datetime,
            )
        except ValueError as exc:
            st.sidebar.error(str(exc))
            filtered_events = []

        sorted_events = sort_events(
            filtered_events,
            sort_by=sort_field,
            descending=descending,
        )

        st.caption(
            f"{len(filtered_events)} matching events out of "
            f"{len(snapshot.recent_events)} recent validated events."
        )

        total_items = len(sorted_events)
        total_pages = max(
            1,
            (total_items + page_size - 1) // page_size,
        )

        current_page = int(
            st.session_state.get("event_table_page", 1)
        )
        current_page = min(max(current_page, 1), total_pages)

        # Pagination controls.
        previous_col, page_col, next_col = st.columns([1, 1, 1])

        if previous_col.button(
            "← Previous",
            disabled=current_page <= 1,
            key="event_table_previous",
        ):
            current_page -= 1

        if next_col.button(
            "Next →",
            disabled=current_page >= total_pages,
            key="event_table_next",
        ):
            current_page += 1

        st.session_state["event_table_page"] = current_page
        page_col.markdown(
            f"**Page {current_page} of {total_pages}**"
        )

        page_events, current_page, total_pages = paginate_events(
            sorted_events,
            page=current_page,
            page_size=page_size,
        )

        st.session_state["event_table_page"] = current_page

        if total_items:
            start_item = (current_page - 1) * page_size + 1
            end_item = min(current_page * page_size, total_items)

            st.caption(
                f"Showing {start_item}–{end_item} of {total_items} "
                "matching events in the recent-event window."
            )
        else:
            st.info("No events match the selected filters.")

        # Presentation-only rows. Original SIEM events remain unchanged.
        display_rows = []

        for event in page_events:
            display_rows.append(
                {
                    "Timestamp": event["timestamp"],
                    "Trace ID": event["trace_id"],
                    "Client IP": event["client_ip"],
                    "User": event["user_id"],
                    "Role": event["user_role"],
                    "Status": status_badge(event["action"]),
                    "Rule ID": event["rule_id"],
                    "ML Score": event["ml_score"],
                    "Latency (ms)": event["latency_ms"],
                }
            )

        if display_rows:
            st.dataframe(
                display_rows,
                hide_index=True,
                width="stretch",
                height=480,
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
