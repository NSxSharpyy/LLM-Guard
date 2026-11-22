import pytest

from dashboard.event_table import paginate_events, sort_events


def make_event(number, action="ALLOW", score=0.5, latency=10.0):
    return {
        "timestamp": f"2026-11-16T10:00:{number:02d}Z",
        "trace_id": f"table-test-{number}",
        "client_ip": "192.0.2.10",
        "user_id": f"user-{number}",
        "user_role": "analyst",
        "action": action,
        "rule_id": "POLICY_ALLOW_001",
        "ml_score": score,
        "latency_ms": latency,
    }


@pytest.fixture
def sample_events():
    return [
        make_event(1, "ALLOW", 0.2, 30.0),
        make_event(2, "BLOCK", 0.95, 12.0),
        make_event(3, "ALLOW", 0.4, 50.0),
        make_event(4, "BLOCK", 0.85, 8.0),
    ]


def test_sort_timestamp_descending(sample_events):
    result = sort_events(sample_events, "timestamp", True)

    assert [e["trace_id"] for e in result] == [
        "table-test-4",
        "table-test-3",
        "table-test-2",
        "table-test-1",
    ]


def test_sort_timestamp_ascending(sample_events):
    result = sort_events(sample_events, "timestamp", False)

    assert [e["trace_id"] for e in result] == [
        "table-test-1",
        "table-test-2",
        "table-test-3",
        "table-test-4",
    ]


def test_sort_action(sample_events):
    result = sort_events(sample_events, "action", False)

    assert [e["action"] for e in result] == [
        "ALLOW",
        "ALLOW",
        "BLOCK",
        "BLOCK",
    ]


def test_sort_ml_score(sample_events):
    result = sort_events(sample_events, "ml_score", True)

    assert [e["ml_score"] for e in result] == [
        0.95,
        0.85,
        0.4,
        0.2,
    ]


def test_sort_latency(sample_events):
    result = sort_events(sample_events, "latency_ms", False)

    assert [e["latency_ms"] for e in result] == [
        8.0,
        12.0,
        30.0,
        50.0,
    ]


def test_unsupported_sort_field_is_rejected(sample_events):
    with pytest.raises(ValueError, match="Unsupported sort field"):
        sort_events(sample_events, "client_ip")


def test_pagination_returns_correct_page(sample_events):
    result, page, total_pages = paginate_events(
        sample_events,
        page=2,
        page_size=2,
    )

    assert page == 2
    assert total_pages == 2
    assert [e["trace_id"] for e in result] == [
        "table-test-3",
        "table-test-4",
    ]


def test_pagination_clamps_out_of_range_page(sample_events):
    result, page, total_pages = paginate_events(
        sample_events,
        page=99,
        page_size=2,
    )

    assert page == 2
    assert total_pages == 2
    assert len(result) == 2


def test_pagination_handles_empty_events():
    result, page, total_pages = paginate_events([])

    assert result == []
    assert page == 1
    assert total_pages == 1


def test_pagination_rejects_invalid_page_size(sample_events):
    with pytest.raises(ValueError, match="Page size"):
        paginate_events(sample_events, page_size=0)


def test_pagination_rejects_invalid_page_number(sample_events):
    with pytest.raises(ValueError, match="Page number"):
        paginate_events(sample_events, page=0)


def test_sort_does_not_modify_original_events(sample_events):
    original = list(sample_events)

    sort_events(sample_events, "timestamp", True)

    assert sample_events == original


def test_allow_status_has_green_badge():
    from dashboard.event_table import status_badge

    assert status_badge("ALLOW") == "🟢 ALLOW"


def test_block_status_has_red_badge():
    from dashboard.event_table import status_badge

    assert status_badge("BLOCK") == "🔴 BLOCK"


def test_unknown_status_is_rejected():
    from dashboard.event_table import status_badge

    with pytest.raises(ValueError, match="Unsupported SIEM action"):
        status_badge("WARN")
