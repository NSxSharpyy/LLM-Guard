import json
from pathlib import Path

from src.soc.siem_reader import load_siem_events, summarize_siem_events


def test_load_and_summarize_siem_events(tmp_path: Path) -> None:
    log_file = tmp_path / "security_events.jsonl"

    valid_1 = {
        "timestamp": "2026-11-22T14:00:00Z",
        "trace_id": "trc-1",
        "client_ip": "127.0.0.1",
        "user_id": "u-1",
        "user_role": "analyst",
        "action": "ALLOW",
        "rule_id": "PASS-ALL-CHECKS",
        "ml_score": 0.01,
        "latency_ms": 12.5,
    }
    valid_2 = {
        "timestamp": "2026-11-22T14:00:01Z",
        "trace_id": "trc-2",
        "client_ip": "127.0.0.1",
        "user_id": "u-1",
        "user_role": "analyst",
        "action": "BLOCK",
        "rule_id": "PI-001-INSTRUCTION-OVERRIDE",
        "ml_score": 0.96,
        "latency_ms": 7.5,
    }

    log_file.write_text(
        json.dumps(valid_1)
        + "\n"
        + "{corrupted-partial-line\n"
        + json.dumps({"trace_id": "missing-schema"})
        + "\n"
        + json.dumps(valid_2)
        + "\n",
        encoding="utf-8",
    )

    events = load_siem_events(log_file)
    assert len(events) == 2

    summary = summarize_siem_events(events)
    assert summary["total_events"] == 2
    assert summary["allow_count"] == 1
    assert summary["block_count"] == 1
    assert summary["avg_latency_ms"] == 10.0
    assert summary["top_rules"]["PI-001-INSTRUCTION-OVERRIDE"] == 1
