
import pytest

from scripts.mid_project_audit import (
    adversarial_chunks,
    evaluate_zero_pii_report,
    percentile,
    summarize_timings,
)


def make_valid_report():
    return {
        "run_id": "day14-test",
        "generated_at": "2026-11-22T00:00:00+00:00",
        "expected_payloads": 500,
        "successful_proxy_requests": 500,
        "matched_upstream_records": 500,
        "missing_upstream_records": 0,
        "duplicate_upstream_records": 0,
        "unexpected_upstream_records": 0,
        "leak_count": 0,
        "request_failure_count": 0,
        "entity_mismatch_count": 0,
        "log_error_count": 0,
        "positive_audit_pass": True,
        "negative_test": {
            "attempted": True,
            "request_success": True,
            "log_record_found": True,
            "leak_detected": True,
            "pass": True,
        },
        "overall_pass": True,
    }


def test_nearest_rank_percentile():
    assert percentile([1, 2, 3, 4, 5], 95) == 5
    assert percentile([1, 2, 3, 4, 5], 50) == 3


def test_percentile_rejects_empty_input():
    with pytest.raises(ValueError):
        percentile([], 95)


def test_timing_summary_calculates_metrics_in_milliseconds():
    result = summarize_timings([0.001, 0.002, 0.003])

    assert result["sample_count"] == 3
    assert result["mean_ms"] == pytest.approx(2.0)
    assert result["min_ms"] == pytest.approx(1.0)
    assert result["max_ms"] == pytest.approx(3.0)
    assert result["p95_ms"] == pytest.approx(3.0)


def test_timing_summary_rejects_empty_input():
    with pytest.raises(ValueError):
        summarize_timings([])


def test_adversarial_chunks_split_inside_placeholder():
    text = "Contact <EMAIL_1> now"
    chunks = adversarial_chunks(text, chunk_size=5)

    assert "".join(chunks) == text
    assert any("<" in chunk and ">" not in chunk for chunk in chunks)


def test_adversarial_chunks_reject_nonpositive_size():
    with pytest.raises(ValueError):
        adversarial_chunks("hello", chunk_size=0)


def test_valid_zero_pii_report_passes():
    result = evaluate_zero_pii_report(make_valid_report())

    assert result["pass"] is True
    assert result["leak_count"] == 0
    assert result["leak_rate_percent"] == 0.0
    assert all(result["checks"].values())


def test_zero_pii_report_fails_when_a_leak_is_found():
    report = make_valid_report()
    report["leak_count"] = 1

    result = evaluate_zero_pii_report(report)

    assert result["pass"] is False
    assert result["checks"]["zero_raw_pii_leaks"] is False
    assert result["leak_rate_percent"] == pytest.approx(0.2)


def test_zero_pii_report_fails_when_records_are_missing():
    report = make_valid_report()
    report["missing_upstream_records"] = 1

    result = evaluate_zero_pii_report(report)

    assert result["pass"] is False
    assert result["checks"]["zero_missing_records"] is False


def test_zero_pii_report_fails_when_negative_control_fails():
    report = make_valid_report()
    report["negative_test"]["leak_detected"] = False

    result = evaluate_zero_pii_report(report)

    assert result["pass"] is False
    assert result["checks"]["negative_leak_detection_pass"] is False


def test_zero_pii_report_fails_when_overall_audit_is_not_passed():
    report = make_valid_report()
    report["overall_pass"] = False

    result = evaluate_zero_pii_report(report)

    assert result["pass"] is False
    assert result["checks"]["overall_audit_pass"] is False
