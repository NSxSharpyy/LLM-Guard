
from typing import Any


def evaluate_rule_actions(matched_rules: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Evaluate matched firewall rules and determine the request action.

    CRITICAL rules block the request with HTTP 403.
    WARN rules allow the request but add a warning header and log event.
    """

    critical_rules = [
        rule
        for rule in matched_rules
        if rule.get("severity") == "CRITICAL"
    ]

    warning_rules = [
        rule
        for rule in matched_rules
        if rule.get("severity") == "WARN"
    ]

    if critical_rules:
        triggered_rule = critical_rules[0]

        return {
            "is_blocked": True,
            "status_code": 403,
            "triggered_rule": triggered_rule.get("rule_id"),
            "severity": "CRITICAL",
            "headers": {},
            "log_event": {
                "event": "CRITICAL_RULE_TRIGGERED",
                "rule_id": triggered_rule.get("rule_id"),
                "severity": "CRITICAL",
            },
        }

    if warning_rules:
        triggered_rule = warning_rules[0]

        return {
            "is_blocked": False,
            "status_code": 200,
            "triggered_rule": triggered_rule.get("rule_id"),
            "severity": "WARN",
            "headers": {
                "X-LLM-Guard-Warning": triggered_rule.get("rule_id", "WARNING")
            },
            "log_event": {
                "event": "WARNING_RULE_TRIGGERED",
                "rule_id": triggered_rule.get("rule_id"),
                "severity": "WARN",
            },
        }

    return {
        "is_blocked": False,
        "status_code": 200,
        "triggered_rule": None,
        "severity": None,
        "headers": {},
        "log_event": None,
    }

