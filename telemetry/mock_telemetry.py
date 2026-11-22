"""Generate realistic mock security telemetry for LLM-Guard testing."""

import argparse
import math
import random
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from telemetry.telemetry_logger import (
    DEFAULT_AUDIT_LOG_PATH,
    DEFAULT_LOG_PATH,
    SecurityTelemetryLogger,
)


USER_ROLES = ("analyst", "developer", "admin", "service")

CLIENT_IPS = (
    "192.0.2.10",
    "192.0.2.20",
    "198.51.100.15",
    "198.51.100.25",
    "203.0.113.10",
    "203.0.113.20",
)

BLOCK_RULES = (
    "PROMPT_INJECTION_001",
    "JAILBREAK_DETECTION_001",
    "PII_EXFILTRATION_001",
    "SENSITIVE_DATA_ACCESS_001",
)

ALLOW_RULE = "POLICY_ALLOW_001"


def build_mock_event(
    sequence: int,
    rng: random.Random,
    timestamp: datetime | None = None,
) -> dict[str, Any]:
    """Build one event matching the frozen Day 1 SIEM schema."""

    if sequence < 1:
        raise ValueError("Event sequence must be greater than zero")

    action = rng.choices(
        population=("ALLOW", "BLOCK"),
        weights=(70, 30),
        k=1,
    )[0]

    if action == "ALLOW":
        rule_id = ALLOW_RULE
        ml_score = round(rng.uniform(0.05, 0.89), 3)
        latency_ms = round(rng.uniform(8, 180), 2)
    else:
        rule_id = rng.choice(BLOCK_RULES)
        ml_score = round(rng.uniform(0.65, 0.999), 3)
        latency_ms = round(rng.uniform(5, 85), 2)

    event_time = timestamp or datetime.now(timezone.utc)

    if event_time.tzinfo is None or event_time.utcoffset() is None:
        raise ValueError("Event timestamp must include a timezone")

    formatted_timestamp = (
        event_time.astimezone(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )

    return {
        "timestamp": formatted_timestamp,
        "trace_id": f"mock-{sequence:06d}",
        "client_ip": rng.choice(CLIENT_IPS),
        "user_id": f"user-{rng.randint(1001, 1010)}",
        "user_role": rng.choice(USER_ROLES),
        "action": action,
        "rule_id": rule_id,
        "ml_score": ml_score,
        "latency_ms": latency_ms,
    }


def positive_count(value: str) -> int:
    """Validate a positive event count."""
    try:
        count = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Count must be an integer") from exc

    if count < 1:
        raise argparse.ArgumentTypeError("Count must be at least 1")

    return count


def non_negative_interval(value: str) -> float:
    """Validate a non-negative event interval."""
    try:
        interval = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "Interval must be a number"
        ) from exc

    if not math.isfinite(interval) or interval < 0:
        raise argparse.ArgumentTypeError(
            "Interval must be finite and non-negative"
        )

    return interval


def run_generator(
    count: int,
    interval: float,
    seed: int | None,
    continuous: bool,
    log_path: Path,
    audit_log_path: Path,
) -> dict[str, int]:
    """Generate events and send them through the production logger."""

    rng = random.Random(seed)
    session_id = uuid.uuid4().hex[:12]

    summary = {
        "total": 0,
        "allowed": 0,
        "blocked": 0,
        "high_severity": 0,
    }

    try:
        with SecurityTelemetryLogger(
            log_path=log_path,
            audit_log_path=audit_log_path,
        ) as telemetry:

            while continuous or summary["total"] < count:
                sequence = summary["total"] + 1

                event = build_mock_event(sequence, rng)
                event["trace_id"] = f"mock-{session_id}-{sequence:06d}"

                telemetry.log_event(event)

                summary["total"] += 1

                if event["action"] == "ALLOW":
                    summary["allowed"] += 1
                else:
                    summary["blocked"] += 1

                if telemetry.is_high_severity(event):
                    summary["high_severity"] += 1

                if continuous or summary["total"] < count:
                    if interval > 0:
                        time.sleep(interval)

    except KeyboardInterrupt:
        print("\nGeneration interrupted. Flushing queued events...")

    return summary


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate mock LLM-Guard security telemetry."
    )

    parser.add_argument(
        "--count",
        type=positive_count,
        default=50,
        help="Number of events to generate (default: 50).",
    )

    parser.add_argument(
        "--interval",
        type=non_negative_interval,
        default=0.2,
        help="Delay between events in seconds (default: 0.2).",
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Random seed for repeatable event distributions.",
    )

    parser.add_argument(
        "--continuous",
        action="store_true",
        help="Generate events until interrupted with Ctrl+C.",
    )

    parser.add_argument(
        "--log-path",
        type=Path,
        default=DEFAULT_LOG_PATH,
        help="Normal telemetry JSONL output path.",
    )

    parser.add_argument(
        "--audit-log-path",
        type=Path,
        default=DEFAULT_AUDIT_LOG_PATH,
        help="High-severity audit JSONL output path.",
    )

    args = parser.parse_args()

    print("========== LLM-GUARD MOCK TELEMETRY ==========")
    print("Mode:", "Continuous" if args.continuous else "Finite")
    print("Count:", "Unlimited" if args.continuous else args.count)
    print("Interval:", args.interval, "seconds")
    print("Random seed:", args.seed)

    summary = run_generator(
        count=args.count,
        interval=args.interval,
        seed=args.seed,
        continuous=args.continuous,
        log_path=args.log_path,
        audit_log_path=args.audit_log_path,
    )

    print("\n========== GENERATION SUMMARY ==========")
    print("Total events:", summary["total"])
    print("Allowed:", summary["allowed"])
    print("Blocked:", summary["blocked"])
    print("High-severity audit events:", summary["high_severity"])
    print("Normal log:", args.log_path)
    print("Audit log:", args.audit_log_path)


if __name__ == "__main__":
    main()
