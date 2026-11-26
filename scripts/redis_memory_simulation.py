#!/usr/bin/env python3
"""Measure Redis memory usage and TTL cleanup for synthetic DLP sessions."""

import argparse
import json
import time
import uuid
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from datetime import datetime, timezone

import redis

from dlp.redis_vault import RedisVault


REDIS_HOST = "127.0.0.1"
REDIS_PORT = 6380
REDIS_DB = 14
EXPECTED_MAXMEMORY = 256 * 1024 * 1024
EXPECTED_POLICY = "volatile-lru"

PLACEHOLDER_TYPES = [
    "EMAIL",
    "PHONE",
    "AADHAAR",
    "PAN",
    "AWS_ACCESS_KEY",
]


def count_namespace_keys(client, run_prefix):
    """Count only keys created by this simulation run."""
    patterns = [
        f"vault:{run_prefix}_session_*:*",
        f"vaultmeta:{run_prefix}_session_*:keys",
    ]

    keys = set()
    for pattern in patterns:
        keys.update(client.scan_iter(match=pattern))

    return len(keys)


def delete_namespace_keys(client, run_prefix):
    """Delete only keys belonging to this simulation run."""
    patterns = [
        f"vault:{run_prefix}_session_*:*",
        f"vaultmeta:{run_prefix}_session_*:keys",
    ]

    keys = []
    for pattern in patterns:
        keys.extend(client.scan_iter(match=pattern))

    if keys:
        for start in range(0, len(keys), 500):
            client.delete(*keys[start:start + 500])

    return len(keys)


def memory_snapshot(client):
    """Capture Redis memory and database statistics."""
    memory = client.info("memory")
    return {
        "used_memory_bytes": memory["used_memory"],
        "used_memory_human": memory["used_memory_human"],
        "used_memory_rss_bytes": memory.get("used_memory_rss"),
        "dbsize": client.dbsize(),
    }


def build_mapping(session_number, mapping_count):
    """Create deterministic synthetic values, never real personal data."""
    mapping = {}

    for index in range(mapping_count):
        placeholder_type = PLACEHOLDER_TYPES[index]
        placeholder = f"<{placeholder_type}_{index + 1}>"
        original_value = (
            f"synthetic_{placeholder_type.lower()}_"
            f"{session_number:05d}_{index + 1}"
        )
        mapping[placeholder] = original_value

    return mapping


def main():
    parser = argparse.ArgumentParser(
        description="Simulate Redis memory usage across DLP sessions."
    )
    parser.add_argument("--sessions", type=int, default=10_000)
    parser.add_argument("--ttl", type=int, default=5)
    parser.add_argument("--wait", type=int, default=7)
    parser.add_argument(
        "--output",
        default="reports/day18-redis-memory-simulation.json",
    )
    args = parser.parse_args()

    if args.sessions <= 0:
        parser.error("--sessions must be greater than zero")
    if args.ttl <= 0:
        parser.error("--ttl must be greater than zero")
    if args.wait < args.ttl:
        parser.error("--wait must be at least as long as --ttl")

    client = redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        db=REDIS_DB,
        decode_responses=True,
    )
    client.ping()

    policy = client.config_get("maxmemory-policy")["maxmemory-policy"]
    maxmemory = int(client.config_get("maxmemory")["maxmemory"])

    if policy != EXPECTED_POLICY:
        raise RuntimeError(
            f"Expected {EXPECTED_POLICY}, found {policy}"
        )
    if maxmemory != EXPECTED_MAXMEMORY:
        raise RuntimeError(
            f"Expected maxmemory {EXPECTED_MAXMEMORY}, found {maxmemory}"
        )

    run_prefix = f"day18_{uuid.uuid4().hex}"
    vault = RedisVault(
        host=REDIS_HOST,
        port=REDIS_PORT,
        db=REDIS_DB,
        ttl_seconds=args.ttl,
    )

    print("Redis connection: PASS")
    print(f"Redis target: {REDIS_HOST}:{REDIS_PORT}, DB {REDIS_DB}")
    print(f"Eviction policy: {policy}")
    print(f"Max memory: {maxmemory} bytes")
    print(f"Simulation namespace: {run_prefix}")

    baseline = memory_snapshot(client)
    print(f"Baseline memory: {baseline['used_memory_human']}")

    total_mappings = 0

    try:
        start_time = time.perf_counter()

        for session_number in range(1, args.sessions + 1):
            mapping_count = 3 + ((session_number - 1) % 3)
            session_id = f"{run_prefix}_session_{session_number:05d}"
            mapping = build_mapping(session_number, mapping_count)

            vault.store(session_id, mapping)
            total_mappings += mapping_count

            if session_number % 1000 == 0:
                print(f"Stored {session_number:,}/{args.sessions:,} sessions")

        load_duration = time.perf_counter() - start_time
        after_load = memory_snapshot(client)
        namespaced_keys_after_load = count_namespace_keys(
            client, run_prefix
        )

        memory_delta = (
            after_load["used_memory_bytes"]
            - baseline["used_memory_bytes"]
        )
        memory_per_session = memory_delta / args.sessions

        print(f"Stored mappings: {total_mappings:,}")
        print(f"Load duration: {load_duration:.2f} seconds")
        print(f"Memory after load: {after_load['used_memory_human']}")
        print(f"Memory increase: {memory_delta:,} bytes")
        print(f"Simulation keys after load: {namespaced_keys_after_load:,}")

        print(f"Waiting {args.wait} seconds for TTL expiry...")
        time.sleep(args.wait)

        # SCAN and EXISTS-style reads trigger Redis expiration checks.
        remaining_keys = count_namespace_keys(client, run_prefix)
        after_expiry = memory_snapshot(client)

        available_memory = max(
            0, maxmemory - baseline["used_memory_bytes"]
        )

        estimated_capacity = (
            int(available_memory / memory_per_session)
            if memory_per_session > 0
            else None
        )

        extrapolations = {}
        for target_sessions in (100_000, 1_000_000):
            extrapolations[str(target_sessions)] = (
                int(memory_per_session * target_sessions)
            )

        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "redis": {
                "host": REDIS_HOST,
                "port": REDIS_PORT,
                "database": REDIS_DB,
                "policy": policy,
                "maxmemory_bytes": maxmemory,
            },
            "simulation": {
                "run_prefix": run_prefix,
                "sessions": args.sessions,
                "mappings": total_mappings,
                "ttl_seconds": args.ttl,
                "wait_seconds": args.wait,
                "load_duration_seconds": round(load_duration, 3),
            },
            "memory": {
                "baseline": baseline,
                "after_load": after_load,
                "after_ttl_expiry": after_expiry,
                "increase_bytes": memory_delta,
                "average_increase_bytes_per_session": round(
                    memory_per_session, 2
                ),
                "estimated_capacity_sessions": estimated_capacity,
                "estimated_additional_memory_bytes": extrapolations,
            },
            "ttl_cleanup": {
                "keys_after_load": namespaced_keys_after_load,
                "keys_remaining_after_ttl": remaining_keys,
                "passed": remaining_keys == 0,
            },
            "notes": [
                "All stored values are synthetic test data.",
                "Memory estimates are workload-specific extrapolations.",
                "Redis allocator fragmentation can prevent used_memory "
                "from returning exactly to its baseline.",
                "volatile-lru only evicts keys that have an expiration set.",
            ],
        }

        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(report, indent=2) + "\n",
            encoding="utf-8",
        )

        print(f"Keys remaining after TTL: {remaining_keys:,}")
        print(f"TTL cleanup: {'PASS' if remaining_keys == 0 else 'FAIL'}")
        print(f"JSON report: {output_path}")

        if remaining_keys != 0:
            raise RuntimeError(
                "Some simulation keys remain after the TTL wait."
            )

    finally:
        deleted = delete_namespace_keys(client, run_prefix)
        print(f"Final targeted cleanup: {deleted:,} keys deleted")


if __name__ == "__main__":
    main()
