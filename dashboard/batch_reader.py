"""Safe reader for the isolated Day 14 batch progress JSON file."""

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REQUIRED_KEYS = {
    "schema_version",
    "source",
    "batch_id",
    "status",
    "updated_at",
    "expected_attacks",
    "expected_benign",
    "expected_total",
    "completed_attacks",
    "completed_benign",
    "completed_total",
    "completion_pct",
    "attack_blocked",
    "attack_correct_rule_matches",
    "attack_missed",
    "wrong_rule_blocks",
    "attack_detection_rate_pct",
    "attack_rule_match_rate_pct",
    "benign_allowed",
    "benign_false_positives",
    "benign_false_positive_rate_pct",
    "error_count",
    "requests_per_second",
    "latency_avg_ms",
    "latency_p95_ms",
    "category_stats",
}


@dataclass(frozen=True)
class BatchProgressSnapshot:
    available: bool
    data: dict[str, Any] | None
    message: str


class BatchProgressReader:
    """Read and validate the atomically replaced batch progress JSON file."""

    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser()

    @staticmethod
    def _valid_number(value: Any, *, nullable: bool = False) -> bool:
        if value is None:
            return nullable
        return (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(value)
            and value >= 0
        )

    @classmethod
    def _validate(cls, data: Any) -> None:
        if not isinstance(data, dict):
            raise ValueError("Progress document must be a JSON object")

        missing = REQUIRED_KEYS - set(data)
        if missing:
            raise ValueError(f"Missing progress fields: {sorted(missing)}")

        if data["schema_version"] != 1:
            raise ValueError("Unsupported batch progress schema version")

        if data["source"] not in {"synthetic", "m5"}:
            raise ValueError("Unknown evaluation source")

        if data["status"] not in {"running", "completed", "interrupted"}:
            raise ValueError("Invalid batch status")

        for key in ("batch_id", "updated_at"):
            if not isinstance(data[key], str) or not data[key]:
                raise ValueError(f"{key} must be a non-empty string")

        integer_fields = (
            "expected_attacks",
            "expected_benign",
            "expected_total",
            "completed_attacks",
            "completed_benign",
            "completed_total",
            "attack_blocked",
            "attack_correct_rule_matches",
            "attack_missed",
            "wrong_rule_blocks",
            "benign_allowed",
            "benign_false_positives",
            "error_count",
        )

        for key in integer_fields:
            value = data[key]
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{key} must be a non-negative integer")

        if data["expected_total"] != (
            data["expected_attacks"] + data["expected_benign"]
        ):
            raise ValueError("Expected total does not match expected categories")

        if data["completed_total"] != (
            data["completed_attacks"] + data["completed_benign"]
        ):
            raise ValueError("Completed total does not match completed categories")

        if data["completed_total"] > data["expected_total"]:
            raise ValueError("Completed total exceeds expected total")

        for key in (
            "completion_pct",
            "attack_detection_rate_pct",
            "attack_rule_match_rate_pct",
            "benign_false_positive_rate_pct",
            "requests_per_second",
            "latency_avg_ms",
            "latency_p95_ms",
        ):
            if not cls._valid_number(data[key], nullable=True):
                raise ValueError(f"Invalid numeric value for {key}")

        if not 0 <= data["completion_pct"] <= 100:
            raise ValueError("Completion percentage must be between 0 and 100")

        for key in (
            "attack_detection_rate_pct",
            "attack_rule_match_rate_pct",
            "benign_false_positive_rate_pct",
        ):
            value = data[key]
            if value is not None and value > 100:
                raise ValueError(f"{key} must not exceed 100")

        if not isinstance(data["category_stats"], dict):
            raise ValueError("category_stats must be an object")

        for category, stats in data["category_stats"].items():
            if not isinstance(category, str) or not isinstance(stats, dict):
                raise ValueError("Invalid category statistics")

            for key in (
                "total",
                "completed",
                "blocked",
                "correct_rule_matches",
                "missed",
                "wrong_rule_blocks",
                "errors",
            ):
                value = stats.get(key)
                if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                    raise ValueError(f"Invalid {category}.{key}")

    def poll(self) -> BatchProgressSnapshot:
        try:
            raw = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return BatchProgressSnapshot(
                False, None, "No Day 14 batch has written progress yet."
            )
        except OSError as exc:
            return BatchProgressSnapshot(
                False, None, f"Cannot read batch progress: {exc}"
            )

        if len(raw) > 1_000_000:
            return BatchProgressSnapshot(
                False, None, "Batch progress file exceeds the permitted size."
            )

        try:
            data = json.loads(raw)
            self._validate(data)
        except (json.JSONDecodeError, ValueError, TypeError) as exc:
            return BatchProgressSnapshot(
                False, None, f"Invalid batch progress: {exc}"
            )

        return BatchProgressSnapshot(
            True,
            data,
            "Batch progress read successfully.",
        )
