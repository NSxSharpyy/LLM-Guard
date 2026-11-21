"""Day 13: verify that raw synthetic PII never reaches the mock LLM."""

import argparse
import hashlib
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import requests


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PAYLOADS = ROOT / "data" / "pii_audit_payloads.json"
DEFAULT_REPORT = ROOT / "logs" / "zero_pii_audit_report.json"
DEFAULT_UPSTREAM_LOG = ROOT / "logs" / "mock_llm_received.jsonl"

PROXY_URL = "http://127.0.0.1:6001"
LLM_URL = "http://127.0.0.1:6002"
REQUEST_TIMEOUT = 15


def sha256_text(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def read_new_log_entries(log_path, starting_offset):
    """Read only complete JSONL records appended after starting_offset."""
    entries = []
    errors = []

    with log_path.open("rb") as log_file:
        log_file.seek(starting_offset)

        for line_number, raw_line in enumerate(log_file, start=1):
            if not raw_line.strip():
                continue

            try:
                entry = json.loads(raw_line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                errors.append(f"Malformed appended log line {line_number}")
                continue

            if not isinstance(entry, dict) or not isinstance(
                entry.get("prompt"), str
            ):
                errors.append(f"Invalid appended log record {line_number}")
                continue

            entries.append(entry)

    return entries, errors


def evaluate_upstream_records(payloads, entries):
    """Correlate every payload and scan matched upstream prompts for leaks."""
    missing = []
    duplicates = []
    matched = []
    unexpected = []
    leaks = []

    raw_values = [
        {
            "audit_id": payload["audit_id"],
            "entity_type": payload["entity_type"],
            "raw_value": payload["raw_value"],
        }
        for payload in payloads
    ]

    used_entry_indexes = set()

    for payload in payloads:
        marker = f"AUDIT_ID={payload['audit_id']}"
        matches = [
            (index, entry)
            for index, entry in enumerate(entries)
            if marker in entry["prompt"]
        ]

        if not matches:
            missing.append(payload["audit_id"])
            continue

        if len(matches) > 1:
            duplicates.append({
                "audit_id": payload["audit_id"],
                "record_count": len(matches),
            })
            continue

        index, entry = matches[0]
        used_entry_indexes.add(index)
        matched.append(payload["audit_id"])

        # Scan against every generated raw value, not just this request's
        # expected value. This catches cross-payload leakage too.
        for candidate in raw_values:
            if candidate["raw_value"] in entry["prompt"]:
                leaks.append({
                    "audit_id": payload["audit_id"],
                    "leaked_payload_id": candidate["audit_id"],
                    "entity_type": candidate["entity_type"],
                    "value_sha256": sha256_text(candidate["raw_value"]),
                })

    for index, entry in enumerate(entries):
        if index not in used_entry_indexes:
            unexpected.append({
                "record_index": index,
                "prompt_sha256": sha256_text(entry["prompt"]),
            })

    return {
        "matched_audit_ids": matched,
        "missing_audit_ids": missing,
        "duplicate_audit_ids": duplicates,
        "unexpected_records": unexpected,
        "leaks": leaks,
    }


def validate_payloads(payloads):
    errors = []

    if not isinstance(payloads, list) or not payloads:
        return ["Payload file must contain a non-empty JSON list"]

    audit_ids = []
    raw_values = []

    for index, payload in enumerate(payloads):
        if not isinstance(payload, dict):
            errors.append(f"Record {index} is not an object")
            continue

        for field in ("audit_id", "entity_type", "raw_value", "prompt"):
            if not isinstance(payload.get(field), str) or not payload[field]:
                errors.append(f"Record {index} has invalid {field}")

        if all(isinstance(payload.get(field), str) for field in (
            "audit_id", "entity_type", "raw_value", "prompt"
        )):
            audit_ids.append(payload["audit_id"])
            raw_values.append(payload["raw_value"])

    if len(audit_ids) != len(set(audit_ids)):
        errors.append("Payload audit IDs are not unique")

    if len(raw_values) != len(set(raw_values)):
        errors.append("Payload raw values are not unique")

    return errors


def run_negative_test(payload, llm_url, log_path):
    """Intentionally send one synthetic raw value directly to the mock LLM."""
    starting_offset = log_path.stat().st_size
    negative_id = f"DAY13-NEGATIVE-{uuid.uuid4().hex[:12]}"

    raw_value = payload["raw_value"]
    prompt = (
        f"AUDIT_ID={negative_id}. "
        f"Deliberately unmasked {payload['entity_type']}: {raw_value}"
    )

    result = {
        "attempted": True,
        "request_success": False,
        "log_record_found": False,
        "leak_detected": False,
        "audit_id": negative_id,
        "entity_type": payload["entity_type"],
        "value_sha256": sha256_text(raw_value),
    }

    try:
        response = requests.post(
            f"{llm_url}/generate",
            json={"prompt": prompt},
            timeout=REQUEST_TIMEOUT,
        )
        result["request_success"] = response.status_code == 200
    except requests.RequestException as exc:
        result["error"] = type(exc).__name__
        return result

    entries, errors = read_new_log_entries(log_path, starting_offset)
    result["log_errors"] = errors

    matches = [
        entry for entry in entries
        if f"AUDIT_ID={negative_id}" in entry["prompt"]
    ]

    result["log_record_found"] = len(matches) == 1

    if len(matches) == 1:
        result["leak_detected"] = raw_value in matches[0]["prompt"]

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Run the Day 13 zero-PII upstream audit."
    )
    parser.add_argument("--payloads", type=Path, default=DEFAULT_PAYLOADS)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--proxy-url", default=PROXY_URL)
    parser.add_argument("--llm-url", default=LLM_URL)
    parser.add_argument("--log", type=Path, default=DEFAULT_UPSTREAM_LOG)
    args = parser.parse_args()

    if not args.payloads.is_file():
        parser.error(f"Payload file not found: {args.payloads}")

    if not args.log.is_file():
        parser.error(f"Upstream log not found: {args.log}")

    payloads = json.loads(args.payloads.read_text(encoding="utf-8"))
    validation_errors = validate_payloads(payloads)

    if validation_errors:
        parser.error("; ".join(validation_errors))

    # Confirm both services before taking the log snapshot.
    try:
        proxy_health = requests.get(
            f"{args.proxy_url}/health", timeout=5
        )
        llm_health = requests.get(
            f"{args.llm_url}/health", timeout=5
        )
        proxy_health.raise_for_status()
        llm_health.raise_for_status()
    except requests.RequestException as exc:
        parser.error(
            f"Mock services are not healthy: {type(exc).__name__}"
        )

    # Existing historical records are excluded from this run.
    starting_offset = args.log.stat().st_size
    run_id = uuid.uuid4().hex
    session_id = f"day13-audit-{run_id}"

    successful_requests = 0
    request_failures = []
    entity_mismatches = []

    print(f"Starting Day 13 audit: {len(payloads)} payloads")
    print(f"Session: {session_id}")
    print("Sending requests sequentially through the mock proxy...")

    try:
        for number, payload in enumerate(payloads, start=1):
            try:
                response = requests.post(
                    f"{args.proxy_url}/chat",
                    json={
                        "session_id": session_id,
                        "prompt": payload["prompt"],
                    },
                    timeout=REQUEST_TIMEOUT,
                )

                if response.status_code != 200:
                    request_failures.append({
                        "audit_id": payload["audit_id"],
                        "status_code": response.status_code,
                    })
                    continue

                try:
                    response_data = response.json()
                except ValueError:
                    request_failures.append({
                        "audit_id": payload["audit_id"],
                        "error": "Invalid JSON response",
                    })
                    continue

                entities = response_data.get("entities", [])
                detected_types = {
                    item.get("entity_type")
                    for item in entities
                    if isinstance(item, dict)
                }

                if payload["entity_type"] not in detected_types:
                    entity_mismatches.append({
                        "audit_id": payload["audit_id"],
                        "expected": payload["entity_type"],
                        "detected": sorted(
                            str(item) for item in detected_types
                        ),
                    })

                successful_requests += 1

            except requests.RequestException as exc:
                request_failures.append({
                    "audit_id": payload["audit_id"],
                    "error": type(exc).__name__,
                })

            if number % 50 == 0:
                print(f"  Progress: {number}/{len(payloads)}")

    finally:
        try:
            requests.post(
                f"{args.proxy_url}/end-session",
                json={"session_id": session_id},
                timeout=5,
            )
        except requests.RequestException:
            print("[WARNING] Could not confirm proxy session cleanup.")

    # Read positive-run log records before running the intentional leak test.
    positive_entries, log_errors = read_new_log_entries(
        args.log, starting_offset
    )
    positive = evaluate_upstream_records(payloads, positive_entries)

    # Deliberately bypass the proxy with one synthetic value. This must be
    # detected by the same raw-value inspection logic.
    negative = run_negative_test(
        payloads[0], args.llm_url, args.log
    )

    expected_count = len(payloads)
    positive_pass = (
        successful_requests == expected_count
        and len(positive_entries) == expected_count
        and len(positive["matched_audit_ids"]) == expected_count
        and not positive["missing_audit_ids"]
        and not positive["duplicate_audit_ids"]
        and not positive["unexpected_records"]
        and not positive["leaks"]
        and not request_failures
        and not entity_mismatches
        and not log_errors
    )

    negative_pass = (
        negative["request_success"]
        and negative["log_record_found"]
        and negative["leak_detected"]
        and not negative.get("log_errors")
    )

    report = {
        "audit": "Day 13 Zero-PII Upstream Verification",
        "run_id": run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "payload_file": str(args.payloads.relative_to(ROOT))
        if args.payloads.is_relative_to(ROOT)
        else args.payloads.name,
        "expected_payloads": expected_count,
        "successful_proxy_requests": successful_requests,
        "upstream_records_appended": len(positive_entries),
        "matched_upstream_records": len(positive["matched_audit_ids"]),
        "missing_upstream_records": len(positive["missing_audit_ids"]),
        "duplicate_upstream_records": len(
            positive["duplicate_audit_ids"]
        ),
        "unexpected_upstream_records": len(
            positive["unexpected_records"]
        ),
        "leak_count": len(positive["leaks"]),
        "request_failure_count": len(request_failures),
        "entity_mismatch_count": len(entity_mismatches),
        "log_error_count": len(log_errors),
        "positive_audit_pass": positive_pass,
        "negative_test": {
            "attempted": negative["attempted"],
            "request_success": negative["request_success"],
            "log_record_found": negative["log_record_found"],
            "leak_detected": negative["leak_detected"],
            "entity_type": negative["entity_type"],
            "value_sha256": negative["value_sha256"],
            "pass": negative_pass,
        },
        "details": {
            "missing_audit_ids": positive["missing_audit_ids"],
            "duplicate_audit_ids": positive["duplicate_audit_ids"],
            "unexpected_records": positive["unexpected_records"],
            "leaks": positive["leaks"],
            "request_failures": request_failures,
            "entity_mismatches": entity_mismatches,
            "log_errors": log_errors,
        },
        "overall_pass": positive_pass and negative_pass,
    }

    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        json.dumps(report, indent=2) + "\n",
        encoding="utf-8",
    )

    print("\n===== DAY 13 AUDIT RESULTS =====")
    print(f"Expected payloads:          {expected_count}")
    print(f"Successful proxy requests:  {successful_requests}")
    print(f"New upstream records:       {len(positive_entries)}")
    print(f"Matched upstream records:   {len(positive['matched_audit_ids'])}")
    print(f"Missing records:            {len(positive['missing_audit_ids'])}")
    print(f"Duplicate records:          {len(positive['duplicate_audit_ids'])}")
    print(f"Unexpected records:         {len(positive['unexpected_records'])}")
    print(f"Raw PII leaks:              {len(positive['leaks'])}")
    print(f"Request failures:           {len(request_failures)}")
    print(f"Entity mismatches:          {len(entity_mismatches)}")
    print(f"Malformed log records:      {len(log_errors)}")
    print(f"Positive audit:             {'PASS' if positive_pass else 'FAIL'}")
    print(
        "Negative leak detection:   "
        f"{'PASS' if negative_pass else 'FAIL'}"
    )
    print(f"Report: {args.report}")

    if report["overall_pass"]:
        print("\nDAY 13 ZERO-PII AUDIT: PASS")
        return 0

    print("\nDAY 13 ZERO-PII AUDIT: FAIL")
    return 1


if __name__ == "__main__":
    sys.exit(main())
