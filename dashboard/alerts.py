"""High-severity security alert tracking for the SOC dashboard."""

from collections import deque
from collections.abc import Iterable
from typing import Any

from dashboard.event_filters import severity_for_event


CANARY_RULE_PREFIX = "CANARY-"


def is_canary_token_exfiltration_event(event: dict[str, Any]) -> bool:
    """Return whether an event is a blocked canary-token event."""
    rule_id = event.get("rule_id")
    return (
        event.get("action") == "BLOCK"
        and isinstance(rule_id, str)
        and rule_id.startswith(CANARY_RULE_PREFIX)
    )


class HighSeverityAlertTracker:
    """Track newly detected high-severity events without duplicate alerts."""

    def __init__(self, max_alerts: int = 5, max_seen: int = 1000) -> None:
        if max_alerts < 1:
            raise ValueError("max_alerts must be at least 1")
        if max_seen < 1:
            raise ValueError("max_seen must be at least 1")

        self.alerts: deque[dict[str, Any]] = deque(maxlen=max_alerts)
        self._pending_notifications: deque[dict[str, Any]] = deque(
            maxlen=max_alerts
        )
        self._seen_trace_ids: set[str] = set()
        self._seen_order: deque[str] = deque()
        self.max_seen = max_seen

    def ingest(
        self,
        events: Iterable[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Record each new high-severity BLOCK event once."""
        new_alerts = []

        for event in events:
            if (
                is_canary_token_exfiltration_event(event)
                or severity_for_event(event) != "HIGH"
            ):
                continue

            trace_id = str(event.get("trace_id", "")).strip()
            if not trace_id or trace_id in self._seen_trace_ids:
                continue

            if len(self._seen_order) >= self.max_seen:
                oldest_trace_id = self._seen_order.popleft()
                self._seen_trace_ids.discard(oldest_trace_id)

            self._seen_order.append(trace_id)
            self._seen_trace_ids.add(trace_id)

            alert = dict(event)
            self.alerts.appendleft(alert)
            self._pending_notifications.append(alert)
            new_alerts.append(alert)

        return new_alerts

    def consume_notifications(self) -> list[dict[str, Any]]:
        """Return pending popup notifications exactly once."""
        notifications = list(self._pending_notifications)
        self._pending_notifications.clear()
        return notifications

    def clear(self) -> None:
        """Dismiss visible alerts without forgetting deduplication history."""
        self.alerts.clear()
        self._pending_notifications.clear()


class CanaryTokenAlertTracker:
    """Track canary-token BLOCK events without duplicate alerts."""

    def __init__(self, max_alerts: int = 5, max_seen: int = 1000) -> None:
        if max_alerts < 1:
            raise ValueError("max_alerts must be at least 1")
        if max_seen < 1:
            raise ValueError("max_seen must be at least 1")

        self.alerts: deque[dict[str, Any]] = deque(maxlen=max_alerts)
        self._pending_notifications: deque[dict[str, Any]] = deque(
            maxlen=max_alerts
        )
        self._seen_trace_ids: set[str] = set()
        self._seen_order: deque[str] = deque()
        self.max_seen = max_seen

    def ingest(
        self,
        events: Iterable[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Record new canary-token BLOCK events once."""
        new_alerts = []

        for event in events:
            if not is_canary_token_exfiltration_event(event):
                continue

            trace_id = str(event.get("trace_id", "")).strip()
            if not trace_id or trace_id in self._seen_trace_ids:
                continue

            if len(self._seen_order) >= self.max_seen:
                oldest_trace_id = self._seen_order.popleft()
                self._seen_trace_ids.discard(oldest_trace_id)

            self._seen_order.append(trace_id)
            self._seen_trace_ids.add(trace_id)

            alert = dict(event)
            self.alerts.appendleft(alert)
            self._pending_notifications.append(alert)
            new_alerts.append(alert)

        return new_alerts

    def consume_notifications(self) -> list[dict[str, Any]]:
        """Return pending notifications exactly once."""
        notifications = list(self._pending_notifications)
        self._pending_notifications.clear()
        return notifications

    def clear(self) -> None:
        """Dismiss visible alerts but preserve deduplication history."""
        self.alerts.clear()
        self._pending_notifications.clear()
