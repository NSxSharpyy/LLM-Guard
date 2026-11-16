
import pytest

from action_evaluator import evaluate_rule_actions


def test_critical_rule_blocks_request():
    matched_rules = [
        {
            "rule_id": "SEC-001",
            "severity": "CRITICAL",
            "action": "DROP",
        }
    ]

    result = evaluate_rule_actions(matched_rules)

    assert result["is_blocked"] is True
    assert result["status_code"] == 403
    assert result["severity"] == "CRITICAL"
    assert result["triggered_rule"] == "SEC-001"
    assert result["headers"] == {}


def test_warning_rule_allows_request_with_header():
    matched_rules = [
        {
            "rule_id": "SEC-002",
            "severity": "WARN",
            "action": "ALERT",
        }
    ]

    result = evaluate_rule_actions(matched_rules)

    assert result["is_blocked"] is False
    assert result["status_code"] == 200
    assert result["severity"] == "WARN"
    assert result["headers"]["X-LLM-Guard-Warning"] == "SEC-002"
    assert result["log_event"]["event"] == "WARNING_RULE_TRIGGERED"


def test_no_matched_rules_allows_request():
    result = evaluate_rule_actions([])

    assert result["is_blocked"] is False
    assert result["status_code"] == 200
    assert result["triggered_rule"] is None
    assert result["headers"] == {}
    assert result["log_event"] is None


def test_critical_rule_has_priority_over_warning():
    matched_rules = [
        {
            "rule_id": "SEC-002",
            "severity": "WARN",
            "action": "ALERT",
        },
        {
            "rule_id": "SEC-001",
            "severity": "CRITICAL",
            "action": "DROP",
        },
    ]

    result = evaluate_rule_actions(matched_rules)

    assert result["is_blocked"] is True
    assert result["status_code"] == 403
    assert result["severity"] == "CRITICAL"
    assert result["triggered_rule"] == "SEC-001"


def test_warning_rule_logs_event():
    matched_rules = [
        {
            "rule_id": "SEC-003",
            "severity": "WARN",
            "action": "ALERT",
        }
    ]

    result = evaluate_rule_actions(matched_rules)

    assert result["log_event"]["rule_id"] == "SEC-003"
    assert result["log_event"]["severity"] == "WARN"


def test_critical_rule_logs_event():
    matched_rules = [
        {
            "rule_id": "SEC-004",
            "severity": "CRITICAL",
            "action": "DROP",
        }
    ]

    result = evaluate_rule_actions(matched_rules)

    assert result["log_event"]["event"] == "CRITICAL_RULE_TRIGGERED"
    assert result["log_event"]["rule_id"] == "SEC-004"
