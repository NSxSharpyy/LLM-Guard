import json
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from src.mock.mock_llm import app as mock_app
from src.proxy.proxy_server import app as proxy_app
from src.proxy.proxy_server import state
from src.security.latency_logger import LatencyMetricsLogger
from src.security.siem_logger import SIEMEventLogger


AUTH_HEADERS = {"Authorization": "Bearer sk-guard-dev-tenant-001"}


def read_metrics(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


@pytest.mark.asyncio
async def test_unary_request_records_separate_firewall_and_upstream_latency(
    tmp_path: Path,
) -> None:
    await state.rate_limiter.reset()

    metrics_path = tmp_path / "latency_metrics.jsonl"
    original_latency_logger = state.latency_logger
    original_siem_logger = state.siem_logger
    original_client = state.client

    state.latency_logger = LatencyMetricsLogger(metrics_path)
    state.siem_logger = SIEMEventLogger(
        log_path=str(tmp_path / "security_events.jsonl")
    )

    mock_client = AsyncClient(
        transport=ASGITransport(app=mock_app),
        base_url="http://mockupstream",
    )
    state.client = mock_client

    try:
        async with AsyncClient(
            transport=ASGITransport(app=proxy_app),
            base_url="http://testproxy",
        ) as client:
            response = await client.post(
                "/v1/chat/completions",
                json={
                    "model": "mock-llama-3",
                    "messages": [{"role": "user", "content": "Latency test"}],
                    "stream": False,
                },
                headers=AUTH_HEADERS,
            )

        assert response.status_code == 200
        metrics = read_metrics(metrics_path)
        assert len(metrics) == 1

        metric = metrics[0]
        assert metric["trace_id"] == response.headers["x-trace-id"]
        assert metric["firewall_inspection_ms"] > 0
        assert metric["upstream_latency_ms"] > 0
        assert metric["upstream_measurement"] == "unary_full_response"
        assert metric["timestamp"].endswith("Z")
    finally:
        await mock_client.aclose()
        state.client = original_client
        state.latency_logger = original_latency_logger
        state.siem_logger = original_siem_logger


@pytest.mark.asyncio
async def test_blocked_request_records_firewall_latency_without_upstream_latency(
    tmp_path: Path,
) -> None:
    metrics_path = tmp_path / "latency_metrics.jsonl"
    original_latency_logger = state.latency_logger
    original_siem_logger = state.siem_logger

    state.latency_logger = LatencyMetricsLogger(metrics_path)
    state.siem_logger = SIEMEventLogger(
        log_path=str(tmp_path / "security_events.jsonl")
    )

    try:
        async with AsyncClient(
            transport=ASGITransport(app=proxy_app),
            base_url="http://testproxy",
        ) as client:
            response = await client.post(
                "/v1/chat/completions",
                json={
                    "model": "mock-llama-3",
                    "messages": [{"role": "user", "content": "Unauthenticated"}],
                    "stream": False,
                },
            )

        assert response.status_code == 401
        metrics = read_metrics(metrics_path)
        assert len(metrics) == 1

        metric = metrics[0]
        assert metric["trace_id"] == response.headers["x-trace-id"]
        assert metric["firewall_inspection_ms"] > 0
        assert metric["upstream_latency_ms"] is None
        assert metric["upstream_measurement"] == "not_forwarded"
    finally:
        state.latency_logger = original_latency_logger
        state.siem_logger = original_siem_logger


@pytest.mark.asyncio
async def test_stream_records_full_duration_only_after_stream_completion(
    tmp_path: Path,
) -> None:
    await state.rate_limiter.reset()

    metrics_path = tmp_path / "latency_metrics.jsonl"
    original_latency_logger = state.latency_logger
    original_siem_logger = state.siem_logger
    original_client = state.client

    state.latency_logger = LatencyMetricsLogger(metrics_path)
    state.siem_logger = SIEMEventLogger(
        log_path=str(tmp_path / "security_events.jsonl")
    )

    mock_client = AsyncClient(
        transport=ASGITransport(app=mock_app),
        base_url="http://mockupstream",
    )
    state.client = mock_client

    try:
        async with AsyncClient(
            transport=ASGITransport(app=proxy_app),
            base_url="http://testproxy",
        ) as client:
            async with client.stream(
                "POST",
                "/v1/chat/completions",
                json={
                    "model": "mock-llama-3",
                    "messages": [{"role": "user", "content": "Stream latency test"}],
                    "stream": True,
                },
                headers={
                    **AUTH_HEADERS,
                    "X-Mock-Token-Count": "10",
                    "X-Mock-Benchmark-Mode": "true",
                },
            ) as response:
                assert response.status_code == 200
                trace_id = response.headers["x-trace-id"]
                body = await response.aread()
                assert b"[DONE]" in body

        metrics = read_metrics(metrics_path)
        assert len(metrics) == 1

        metric = metrics[0]
        assert metric["trace_id"] == trace_id
        assert metric["firewall_inspection_ms"] > 0
        assert metric["upstream_latency_ms"] > 0
        assert metric["upstream_measurement"] == "stream_full_response"
    finally:
        await mock_client.aclose()
        state.client = original_client
        state.latency_logger = original_latency_logger
        state.siem_logger = original_siem_logger
