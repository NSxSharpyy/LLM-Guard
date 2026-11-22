import json

from dashboard.batch_reader import BatchProgressReader


def sample_progress():
    return {
        "schema_version": 1,
        "source": "synthetic",
        "batch_id": "day14-test-001",
        "status": "running",
        "updated_at": "2026-11-22T07:30:00Z",
        "expected_attacks": 1000,
        "expected_benign": 100,
        "expected_total": 1100,
        "completed_attacks": 10,
        "completed_benign": 5,
        "completed_total": 15,
        "completion_pct": 1.36,
        "attack_blocked": 10,
        "attack_correct_rule_matches": 10,
        "attack_missed": 0,
        "wrong_rule_blocks": 0,
        "attack_detection_rate_pct": 100.0,
        "attack_rule_match_rate_pct": 100.0,
        "benign_allowed": 5,
        "benign_false_positives": 0,
        "benign_false_positive_rate_pct": 0.0,
        "error_count": 0,
        "requests_per_second": 45.0,
        "latency_avg_ms": 2.7,
        "latency_p95_ms": 4.0,
        "category_stats": {
            "PI-001-INSTRUCTION-OVERRIDE": {
                "total": 250,
                "completed": 10,
                "blocked": 10,
                "correct_rule_matches": 10,
                "missed": 0,
                "wrong_rule_blocks": 0,
                "errors": 0,
            }
        },
    }


def test_missing_progress_file(tmp_path):
    snapshot = BatchProgressReader(tmp_path / "missing.json").poll()

    assert not snapshot.available
    assert snapshot.data is None


def test_reads_valid_progress(tmp_path):
    path = tmp_path / "progress.json"
    path.write_text(json.dumps(sample_progress()), encoding="utf-8")

    snapshot = BatchProgressReader(path).poll()

    assert snapshot.available
    assert snapshot.data["batch_id"] == "day14-test-001"
    assert snapshot.data["completed_total"] == 15


def test_rejects_invalid_completion_percentage(tmp_path):
    path = tmp_path / "progress.json"
    data = sample_progress()
    data["completion_pct"] = 150
    path.write_text(json.dumps(data), encoding="utf-8")

    snapshot = BatchProgressReader(path).poll()

    assert not snapshot.available
    assert "Completion percentage" in snapshot.message


def test_rejects_inconsistent_completed_total(tmp_path):
    path = tmp_path / "progress.json"
    data = sample_progress()
    data["completed_total"] = 20
    path.write_text(json.dumps(data), encoding="utf-8")

    snapshot = BatchProgressReader(path).poll()

    assert not snapshot.available
    assert "Completed total" in snapshot.message


def test_rejects_malformed_json(tmp_path):
    path = tmp_path / "progress.json"
    path.write_text("{broken", encoding="utf-8")

    snapshot = BatchProgressReader(path).poll()

    assert not snapshot.available
    assert "Invalid batch progress" in snapshot.message
