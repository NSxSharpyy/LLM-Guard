import json

from dashboard.latency_reader import JsonlLatencyTailReader


def make_metric(
    number=1,
    *,
    firewall=5.0,
    upstream=100.0,
    measurement="unary_full_response",
):
    return {
        "timestamp": "2026-11-19T09:00:00Z",
        "trace_id": f"latency-test-{number}",
        "firewall_inspection_ms": firewall,
        "upstream_latency_ms": upstream,
        "upstream_measurement": measurement,
    }


def append_metric(path, record, newline=True):
    with path.open("ab") as file:
        data = json.dumps(record).encode("utf-8")
        file.write(data + (b"\n" if newline else b""))


def test_reader_calculates_unary_averages_from_same_sample_population(tmp_path):
    path = tmp_path / "latency_metrics.jsonl"
    append_metric(path, make_metric(1, firewall=4.0, upstream=80.0))
    append_metric(path, make_metric(2, firewall=6.0, upstream=120.0))
    append_metric(
        path,
        make_metric(
            3,
            firewall=3.0,
            upstream=None,
            measurement="not_forwarded",
        ),
    )
    append_metric(
        path,
        make_metric(
            4,
            firewall=8.0,
            upstream=900.0,
            measurement="stream_full_response",
        ),
    )

    result = JsonlLatencyTailReader(path).poll()

    assert result.available
    assert result.total_records == 4
    assert result.unary_sample_count == 2
    assert result.firewall_avg_ms == 5.0
    assert result.upstream_avg_ms == 100.0
    assert result.streaming_sample_count == 1
    assert result.streaming_avg_ms == 900.0
    assert result.blocked_sample_count == 1


def test_reader_waits_for_partial_jsonl_record(tmp_path):
    path = tmp_path / "latency_metrics.jsonl"
    record = json.dumps(make_metric()).encode("utf-8")
    path.write_bytes(record[:25])

    reader = JsonlLatencyTailReader(path)
    first = reader.poll()

    assert first.total_records == 0
    assert first.malformed == 0

    with path.open("ab") as file:
        file.write(record[25:] + b"\n")

    second = reader.poll()
    assert second.total_records == 1
    assert second.unary_sample_count == 1


def test_reader_skips_invalid_json_and_invalid_schema(tmp_path):
    path = tmp_path / "latency_metrics.jsonl"
    invalid_schema = make_metric()
    invalid_schema["extra"] = "unexpected"

    path.write_bytes(
        b"not-json\n"
        + json.dumps(invalid_schema).encode("utf-8")
        + b"\n"
        + json.dumps(make_metric()).encode("utf-8")
        + b"\n"
    )

    result = JsonlLatencyTailReader(path).poll()

    assert result.total_records == 1
    assert result.malformed == 2


def test_reader_rejects_negative_and_non_finite_latency(tmp_path):
    path = tmp_path / "latency_metrics.jsonl"
    negative = make_metric(1, firewall=-1.0)
    infinite = make_metric(2, upstream=float("inf"))

    path.write_text(
        "\n".join(json.dumps(item) for item in (negative, infinite, make_metric(3)))
        + "\n",
        encoding="utf-8",
    )

    result = JsonlLatencyTailReader(path).poll()

    assert result.total_records == 1
    assert result.malformed == 2


def test_reader_does_not_double_count_existing_lines(tmp_path):
    path = tmp_path / "latency_metrics.jsonl"
    append_metric(path, make_metric())

    reader = JsonlLatencyTailReader(path)
    first = reader.poll()
    second = reader.poll()

    assert first.total_records == second.total_records == 1


def test_reader_reads_only_newly_appended_records(tmp_path):
    path = tmp_path / "latency_metrics.jsonl"
    append_metric(path, make_metric(1))

    reader = JsonlLatencyTailReader(path)
    assert reader.poll().total_records == 1

    append_metric(path, make_metric(2))
    result = reader.poll()

    assert result.total_records == 2
    assert result.unary_sample_count == 2


def test_reader_limits_recent_window_but_tracks_total_records(tmp_path):
    path = tmp_path / "latency_metrics.jsonl"
    for number in range(1, 6):
        append_metric(path, make_metric(number))

    result = JsonlLatencyTailReader(path, max_samples=3).poll()

    assert result.total_records == 5
    assert len(result.recent_samples) == 3
    assert result.recent_samples[-1]["trace_id"] == "latency-test-5"


def test_reader_resets_after_truncation(tmp_path):
    path = tmp_path / "latency_metrics.jsonl"
    append_metric(path, make_metric(1))
    append_metric(path, make_metric(2))

    reader = JsonlLatencyTailReader(path)
    assert reader.poll().total_records == 2

    path.write_text(json.dumps(make_metric(3)) + "\n", encoding="utf-8")
    result = reader.poll()

    assert result.total_records == 1
    assert len(result.recent_samples) == 1
    assert result.recent_samples[0]["trace_id"] == "latency-test-3"


def test_reader_resets_after_file_replacement(tmp_path):
    path = tmp_path / "latency_metrics.jsonl"
    replacement = tmp_path / "replacement.jsonl"
    append_metric(path, make_metric(1))

    reader = JsonlLatencyTailReader(path)
    assert reader.poll().total_records == 1

    append_metric(replacement, make_metric(2))
    replacement.replace(path)

    result = reader.poll()
    assert result.total_records == 1
    assert result.recent_samples[0]["trace_id"] == "latency-test-2"


def test_reader_handles_missing_file(tmp_path):
    result = JsonlLatencyTailReader(
        tmp_path / "not-created-yet.jsonl"
    ).poll()

    assert not result.available
    assert result.total_records == 0
    assert "does not exist" in result.message


def test_interrupted_stream_is_not_in_completed_stream_average(tmp_path):
    path = tmp_path / "latency_metrics.jsonl"
    append_metric(
        path,
        make_metric(
            1,
            firewall=5.0,
            upstream=500.0,
            measurement="stream_interrupted",
        ),
    )
    append_metric(
        path,
        make_metric(
            2,
            firewall=7.0,
            upstream=700.0,
            measurement="stream_full_response",
        ),
    )

    result = JsonlLatencyTailReader(path).poll()

    assert result.streaming_sample_count == 1
    assert result.streaming_avg_ms == 700.0
    assert result.interrupted_sample_count == 1
    assert result.unary_sample_count == 0
    assert result.firewall_avg_ms is None
    assert result.upstream_avg_ms is None


def test_invalid_forwarding_measurement_combinations_are_rejected(tmp_path):
    path = tmp_path / "latency_metrics.jsonl"
    bad_not_forwarded = make_metric(
        1,
        upstream=10.0,
        measurement="not_forwarded",
    )
    bad_forwarded = make_metric(
        2,
        upstream=None,
        measurement="unary_full_response",
    )

    path.write_text(
        json.dumps(bad_not_forwarded)
        + "\n"
        + json.dumps(bad_forwarded)
        + "\n",
        encoding="utf-8",
    )

    result = JsonlLatencyTailReader(path).poll()

    assert result.total_records == 0
    assert result.malformed == 2
