import json
from collections import Counter
from pathlib import Path
from typing import Any

FROZEN_FIELDS = (
    "timestamp",
    "trace_id",
    "client_ip",
    "user_id",
    "user_role",
    "action",
    "rule_id",
    "ml_score",
    "latency_ms",
)


def load_siem_events(log_path: str | Path, limit: int | None = None) -> list[dict[str, Any]]:
    """Read valid frozen-schema JSONL events from disk, skipping malformed lines."""
    path = Path(log_path)
    if not path.exists():
        return []

    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            if not isinstance(record, dict):
                continue
            if not set(FROZEN_FIELDS).issubset(record.keys()):
                continue

            events.append(record)

    if limit is not None and limit >= 0:
        return events[-limit:]
    return events


def summarize_siem_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute high-level SOC counters and mean latency from parsed SIEM events."""
    total = len(events)
    if total == 0:
        return {
            "total_events": 0,
            "allow_count": 0,
            "block_count": 0,
            "avg_latency_ms": 0.0,
            "top_rules": {},
        }

    action_counts = Counter(str(ev.get("action", "")).upper() for ev in events)
    rule_counts = Counter(str(ev.get("rule_id", "UNKNOWN")) for ev in events)

    latencies: list[float] = []
    for ev in events:
        try:
            latencies.append(float(ev["latency_ms"]))
        except (TypeError, ValueError, KeyError):
            continue

    avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else 0.0

    return {
        "total_events": total,
        "allow_count": action_counts.get("ALLOW", 0),
        "block_count": action_counts.get("BLOCK", 0),
        "avg_latency_ms": avg_latency,
        "top_rules": dict(rule_counts.most_common(5)),
    }
