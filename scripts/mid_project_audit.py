
"""Day 14: Mid-project performance and zero-PII audit."""

import json
import math
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dlp.dlp_engine import DLPEngine
from dlp.redis_vault import RedisVault
from dlp.stream_unmasker import StreamUnmasker


MASKING_THRESHOLD_MS = 15.0
STREAMING_THRESHOLD_MS = 5.0

PAYLOAD_FILE = ROOT / "data" / "pii_audit_payloads.json"
REPORT_FILE = ROOT / "logs" / "mid_project_audit_report.json"
UPSTREAM_REPORT = ROOT / "logs" / "day14_zero_pii_audit_report.json"

MASKING_ENTITY_TYPES = [
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "US_SSN",
    "AADHAAR_CARD",
    "PAN_CARD",
]

CLEAN_PROMPTS = [
    "Explain how a reverse proxy works in a distributed system.",
    "The deployment completed successfully at 14:30 UTC.",
    "Please summarize the quarterly infrastructure report.",
    "The application returned HTTP status code 200.",
]


def percentile(values, percentile_value):
    """Calculate a nearest-rank percentile."""
    if not values:
        raise ValueError("Cannot calculate percentile of empty data")

    ordered = sorted(values)
    rank = math.ceil((percentile_value / 100) * len(ordered))
    return ordered[max(0, rank - 1)]


def summarize_timings(timings):
    """Return timing statistics in milliseconds."""
    if not timings:
        raise ValueError("No timing measurements collected")

    timings_ms = [value * 1000 for value in timings]

    return {
        "sample_count": len(timings_ms),
        "mean_ms": sum(timings_ms) / len(timings_ms),
        "p95_ms": percentile(timings_ms, 95),
        "max_ms": max(timings_ms),
        "min_ms": min(timings_ms),
    }


def load_masking_prompts():
    """Build ten realistic prompts from validated Day 13 payloads."""
    records = json.loads(PAYLOAD_FILE.read_text(encoding="utf-8"))

    selected = {}

    for record in records:
        entity_type = record["entity_type"]

        if entity_type in MASKING_ENTITY_TYPES and entity_type not in selected:
            selected[entity_type] = record["prompt"]

    missing = set(MASKING_ENTITY_TYPES) - set(selected)

    if missing:
        raise RuntimeError(
            f"Missing Day 13 payload types: {sorted(missing)}"
        )

    return list(selected.values()) + CLEAN_PROMPTS


def measure_masking():
    """Measure DLPEngine.redact() over exactly 100 prompt calls."""
    engine = DLPEngine()
    prompts = load_masking_prompts()

    # Warm up each prompt once; warm-up calls are excluded.
    for prompt in prompts:
        engine.redact(prompt)

    timings = []

    for iteration in range(10):
        for prompt in prompts:
            start = time.perf_counter()
            engine.redact(prompt)
            timings.append(time.perf_counter() - start)

    metrics = summarize_timings(timings)
    metrics["prompts_per_cycle"] = len(prompts)
    metrics["measurement_cycles"] = 10
    metrics["threshold_ms"] = MASKING_THRESHOLD_MS
    metrics["pass"] = metrics["mean_ms"] < MASKING_THRESHOLD_MS

    return metrics


def adversarial_chunks(text, chunk_size=5):
    """Split text at fixed boundaries, including inside placeholder tags."""
    if chunk_size < 1:
        raise ValueError("chunk_size must be positive")

    return [
        text[index:index + chunk_size]
        for index in range(0, len(text), chunk_size)
    ]


def measure_streaming():
    """Measure StreamUnmasker.feed() using a Redis-backed vault."""
    vault = RedisVault(db=15, ttl_seconds=900)

    if not vault.ping():
        raise RuntimeError("Redis DB 15 is not reachable")

    session_id = f"day14_{uuid.uuid4().hex}"

    mapping = {
        "<EMAIL_1>": "audit.user@example.com",
        "<PHONE_1>": "+12025550123",
        "<PAN_1>": "ABCDE1234F",
    }

    response = (
        "Contact <EMAIL_1> or call <PHONE_1>. "
        "The account PAN is <PAN_1>. "
        "Please keep this information confidential."
    )

    expected = response

    for placeholder, original_value in mapping.items():
        expected = expected.replace(placeholder, original_value)

    chunks = adversarial_chunks(response, chunk_size=5)

    timings = []
    total_chunks = 0

    try:
        vault.store(session_id, mapping)

        for _ in range(20):
            stream = StreamUnmasker(vault, session_id)
            output_parts = []

            for chunk in chunks:
                start = time.perf_counter()
                output = stream.feed(chunk)
                timings.append(time.perf_counter() - start)

                output_parts.append(output)
                total_chunks += 1

            output_parts.append(stream.flush())

            reconstructed = "".join(output_parts)

            if reconstructed != expected:
                raise AssertionError(
                    "Streaming output did not match expected unmasked text"
                )

        metrics = summarize_timings(timings)
        metrics["streaming_passes"] = 20
        metrics["chunks_per_pass"] = len(chunks)
        metrics["total_feed_calls"] = total_chunks
        metrics["chunk_size_characters"] = 5
        metrics["threshold_ms"] = STREAMING_THRESHOLD_MS
        metrics["output_validation"] = "PASS"
        metrics["pass"] = metrics["mean_ms"] < STREAMING_THRESHOLD_MS

        return metrics

    finally:
        vault.clear_session(session_id)


def evaluate_zero_pii_report(audit):
    """Validate a zero-PII report without running the live audit."""
    expected = audit.get("expected_payloads", 0)
    leaks = audit.get("leak_count", -1)
    negative_test = audit.get("negative_test", {})

    if not isinstance(negative_test, dict):
        negative_test = {}

    checks = {
        "expected_payloads_500": expected == 500,
        "successful_proxy_requests": (
            audit.get("successful_proxy_requests") == 500
        ),
        "matched_upstream_records": (
            audit.get("matched_upstream_records") == 500
        ),
        "zero_missing_records": (
            audit.get("missing_upstream_records") == 0
        ),
        "zero_duplicate_records": (
            audit.get("duplicate_upstream_records") == 0
        ),
        "zero_unexpected_records": (
            audit.get("unexpected_upstream_records") == 0
        ),
        "zero_raw_pii_leaks": leaks == 0,
        "zero_request_failures": (
            audit.get("request_failure_count") == 0
        ),
        "zero_entity_mismatches": (
            audit.get("entity_mismatch_count") == 0
        ),
        "zero_log_errors": audit.get("log_error_count") == 0,
        "positive_audit_pass": (
            audit.get("positive_audit_pass") is True
        ),
        "negative_leak_detection_pass": (
            negative_test.get("pass") is True
            and negative_test.get("leak_detected") is True
        ),
        "overall_audit_pass": audit.get("overall_pass") is True,
    }

    leak_rate_percent = (
        (leaks / expected) * 100 if expected > 0 else None
    )

    return {
        "run_id": audit.get("run_id"),
        "generated_at": audit.get("generated_at"),
        "expected_payloads": expected,
        "successful_proxy_requests": (
            audit.get("successful_proxy_requests")
        ),
        "matched_upstream_records": (
            audit.get("matched_upstream_records")
        ),
        "leak_count": leaks,
        "leak_rate_percent": leak_rate_percent,
        "negative_test": negative_test,
        "checks": checks,
        "pass": all(checks.values()),
        "source_report": str(UPSTREAM_REPORT.relative_to(ROOT)),
    }


def run_zero_pii_audit():
    """Run a fresh Day 13 audit and validate its actual report schema."""
    UPSTREAM_REPORT.parent.mkdir(parents=True, exist_ok=True)

    # Remove any previous result so stale data cannot be accepted.
    if UPSTREAM_REPORT.exists():
        UPSTREAM_REPORT.unlink()

    command = [
        sys.executable,
        str(ROOT / "scripts" / "zero_pii_audit.py"),
        "--report",
        str(UPSTREAM_REPORT),
    ]

    result = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            "Fresh zero-PII audit failed.\n"
            f"Exit code: {result.returncode}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )

    if not UPSTREAM_REPORT.exists():
        raise RuntimeError("Zero-PII audit did not generate its report")

    audit = json.loads(UPSTREAM_REPORT.read_text(encoding="utf-8"))

    return evaluate_zero_pii_report(audit)

def main():
    print("=== DAY 14 MID-PROJECT AUDIT ===")

    print("\n[1/3] Measuring masking latency...")
    masking = measure_masking()
    print(json.dumps(masking, indent=2))

    print("\n[2/3] Measuring streaming overhead...")
    streaming = measure_streaming()
    print(json.dumps(streaming, indent=2))

    print("\n[3/3] Running fresh 500-payload zero-PII audit...")
    zero_pii = run_zero_pii_audit()
    print(json.dumps(zero_pii, indent=2))

    overall_pass = (
        masking["pass"]
        and streaming["pass"]
        and zero_pii["pass"]
    )

    report = {
        "audit": "Day 14 Mid-Project Audit",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "masking": masking,
        "streaming": streaming,
        "zero_pii": zero_pii,
        "thresholds": {
            "masking_mean_ms": MASKING_THRESHOLD_MS,
            "streaming_mean_ms": STREAMING_THRESHOLD_MS,
            "zero_leakage_required": True,
        },
        "overall_pass": overall_pass,
    }

    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    REPORT_FILE.write_text(
        json.dumps(report, indent=2) + "\n",
        encoding="utf-8",
    )

    print("\n=== DAY 14 RESULT ===")
    print(f"Masking:  {'PASS' if masking['pass'] else 'FAIL'}")
    print(f"Streaming: {'PASS' if streaming['pass'] else 'FAIL'}")
    print(f"Zero-PII: {'PASS' if zero_pii['pass'] else 'FAIL'}")
    print(f"Report: {REPORT_FILE.relative_to(ROOT)}")
    print(f"Overall: {'PASS' if overall_pass else 'FAIL'}")

    return 0 if overall_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
