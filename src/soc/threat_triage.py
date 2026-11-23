from collections import Counter
from typing import Any


def filter_security_alerts(
    events: list[dict[str, Any]],
    min_ml_score: float = 0.75,
) -> list[dict[str, Any]]:
    """Return events that were BLOCKed or crossed the ML risk threshold."""
    alerts: list[dict[str, Any]] = []
    for ev in events:
        action = str(ev.get("action", "")).upper()
        try:
            score = float(ev.get("ml_score", 0.0))
        except (TypeError, ValueError):
            score = 0.0

        if action == "BLOCK" or score >= min_ml_score:
            alerts.append(ev)
    return alerts


def detect_actor_bursts(
    events: list[dict[str, Any]],
    block_threshold: int = 3,
) -> list[dict[str, Any]]:
    """Identify users or client IPs with repeated BLOCK events above threshold."""
    blocked_by_user: Counter[str] = Counter()
    blocked_by_ip: Counter[str] = Counter()

    for ev in events:
        if str(ev.get("action", "")).upper() != "BLOCK":
            continue
        user_id = str(ev.get("user_id", "unknown"))
        client_ip = str(ev.get("client_ip", "0.0.0.0"))
        blocked_by_user[user_id] += 1
        blocked_by_ip[client_ip] += 1

    findings: list[dict[str, Any]] = []

    for user_id, count in blocked_by_user.items():
        if count >= block_threshold:
            findings.append(
                {
                    "actor_type": "user_id",
                    "actor": user_id,
                    "blocked_count": count,
                    "severity": "HIGH",
                }
            )

    for client_ip, count in blocked_by_ip.items():
        if count >= block_threshold:
            findings.append(
                {
                    "actor_type": "client_ip",
                    "actor": client_ip,
                    "blocked_count": count,
                    "severity": "HIGH",
                }
            )

    return findings
