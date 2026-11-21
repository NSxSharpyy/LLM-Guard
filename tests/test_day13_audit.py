import json

from scripts.zero_pii_audit import (
    evaluate_upstream_records,
    read_new_log_entries,
    validate_payloads,
)


def make_payload(audit_id="DAY13-0001", raw_value="user@example.com"):
    return {
        "audit_id": audit_id,
        "entity_type": "EMAIL_ADDRESS",
        "raw_value": raw_value,
        "prompt": f"AUDIT_ID={audit_id}. Contact email: {raw_value}",
    }


def make_entry(prompt):
    return {
        "timestamp": "2026-11-21T00:00:00+00:00",
        "prompt": prompt,
    }


def test_valid_payload_structure_passes():
    payloads = [
        make_payload("DAY13-0001", "one@example.com"),
        make_payload("DAY13-0002", "two@example.com"),
    ]

    assert validate_payloads(payloads) == []


def test_duplicate_audit_ids_fail_validation():
    payloads = [
        make_payload("DAY13-0001", "one@example.com"),
        make_payload("DAY13-0001", "two@example.com"),
    ]

    assert "Payload audit IDs are not unique" in validate_payloads(payloads)


def test_missing_upstream_record_is_reported():
    payloads = [make_payload()]

    result = evaluate_upstream_records(payloads, [])

    assert result["matched_audit_ids"] == []
    assert result["missing_audit_ids"] == ["DAY13-0001"]
    assert result["leaks"] == []


def test_masked_upstream_record_has_no_leak():
    payload = make_payload()
    entry = make_entry("AUDIT_ID=DAY13-0001. Contact email: <EMAIL_1>")

    result = evaluate_upstream_records([payload], [entry])

    assert result["matched_audit_ids"] == ["DAY13-0001"]
    assert result["missing_audit_ids"] == []
    assert result["leaks"] == []
    assert result["unexpected_records"] == []


def test_raw_value_in_upstream_record_is_detected():
    payload = make_payload()
    entry = make_entry(payload["prompt"])

    result = evaluate_upstream_records([payload], [entry])

    assert len(result["leaks"]) == 1
    assert result["leaks"][0]["audit_id"] == "DAY13-0001"
    assert result["leaks"][0]["leaked_payload_id"] == "DAY13-0001"
    assert "raw_value" not in result["leaks"][0]


def test_cross_payload_raw_value_is_detected():
    first = make_payload("DAY13-0001", "one@example.com")
    second = make_payload("DAY13-0002", "two@example.com")

    entry = make_entry(
        "AUDIT_ID=DAY13-0001. Unexpected value: two@example.com"
    )

    result = evaluate_upstream_records([first, second], [entry])

    assert result["matched_audit_ids"] == ["DAY13-0001"]
    assert result["missing_audit_ids"] == ["DAY13-0002"]
    assert any(
        leak["leaked_payload_id"] == "DAY13-0002"
        for leak in result["leaks"]
    )


def test_duplicate_upstream_marker_is_reported():
    payload = make_payload()
    entries = [
        make_entry("AUDIT_ID=DAY13-0001. <EMAIL_1>"),
        make_entry("AUDIT_ID=DAY13-0001. <EMAIL_2>"),
    ]

    result = evaluate_upstream_records([payload], entries)

    assert result["duplicate_audit_ids"] == [{
        "audit_id": "DAY13-0001",
        "record_count": 2,
    }]


def test_unexpected_upstream_record_is_reported():
    payload = make_payload()
    entries = [
        make_entry("AUDIT_ID=DAY13-0001. <EMAIL_1>"),
        make_entry("UNRELATED UPSTREAM PROMPT"),
    ]

    result = evaluate_upstream_records([payload], entries)

    assert len(result["matched_audit_ids"]) == 1
    assert len(result["unexpected_records"]) == 1
    assert "prompt_sha256" in result["unexpected_records"][0]


def test_log_reader_only_reads_appended_records(tmp_path):
    log_path = tmp_path / "mock_llm_received.jsonl"

    historical = make_entry("historical prompt")
    new_entry = make_entry("AUDIT_ID=DAY13-0001. <EMAIL_1>")

    log_path.write_text(
        json.dumps(historical) + "\n",
        encoding="utf-8",
    )
    starting_offset = log_path.stat().st_size

    with log_path.open("a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(new_entry) + "\n")

    entries, errors = read_new_log_entries(log_path, starting_offset)

    assert entries == [new_entry]
    assert errors == []
