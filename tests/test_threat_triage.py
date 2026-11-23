from src.soc.threat_triage import detect_actor_bursts, filter_security_alerts


def test_filter_alerts_and_detect_bursts() -> None:
    events = [
        {
            "trace_id": "trc-1",
            "client_ip": "10.0.0.5",
            "user_id": "u-attacker",
            "action": "BLOCK",
            "rule_id": "PI-001-INSTRUCTION-OVERRIDE",
            "ml_score": 0.95,
        },
        {
            "trace_id": "trc-2",
            "client_ip": "10.0.0.5",
            "user_id": "u-attacker",
            "action": "BLOCK",
            "rule_id": "DLP-001-SECRET-EXFILTRATION",
            "ml_score": 0.99,
        },
        {
            "trace_id": "trc-3",
            "client_ip": "10.0.0.5",
            "user_id": "u-attacker",
            "action": "BLOCK",
            "rule_id": "PI-002-JAILBREAK",
            "ml_score": 0.88,
        },
        {
            "trace_id": "trc-4",
            "client_ip": "10.0.0.9",
            "user_id": "u-clean",
            "action": "ALLOW",
            "rule_id": "PASS-ALL-CHECKS",
            "ml_score": 0.02,
        },
    ]

    alerts = filter_security_alerts(events)
    assert len(alerts) == 3

    bursts = detect_actor_bursts(events, block_threshold=3)
    assert len(bursts) == 2
    actors = {(b["actor_type"], b["actor"], b["blocked_count"]) for b in bursts}
    assert ("user_id", "u-attacker", 3) in actors
    assert ("client_ip", "10.0.0.5", 3) in actors
