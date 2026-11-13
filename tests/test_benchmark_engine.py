import pytest
from httpx import ASGITransport, AsyncClient

from benchmarks.load_test import (
    benchmark_streaming,
    benchmark_unary,
    calculate_percentile,
)
from src.mock.mock_llm import app as mock_app
from src.proxy.proxy_server import app as proxy_app
from src.proxy.proxy_server import state


def test_percentile_calculation_accuracy() -> None:
    sample = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]
    assert calculate_percentile(sample, 50) == 5.5
    assert calculate_percentile(sample, 90) == 9.1
    assert calculate_percentile(sample, 99) == 9.91
    assert calculate_percentile([], 99) == 0.0


@pytest.mark.asyncio
async def test_concurrent_benchmark_runners() -> None:
    mock_transport = ASGITransport(app=mock_app)
    mock_client = AsyncClient(transport=mock_transport, base_url="http://mockupstream")
    state.client = mock_client

    try:
        proxy_transport = ASGITransport(app=proxy_app)
        async with AsyncClient(transport=proxy_transport, base_url="http://testproxy") as pclient:
            unary_res = await benchmark_unary(pclient, concurrency=20, total_requests=50)
            assert unary_res["error_rate_pct"] == 0.0
            assert unary_res["successful_requests"] == 50
            assert unary_res["e2e_p99_ms"] > 0.0
            assert unary_res["proxy_transit_p99_ms"] > 0.0

            stream_res = await benchmark_streaming(pclient, concurrency=20, total_requests=50)
            assert stream_res["error_rate_pct"] == 0.0
            assert stream_res["successful_streams"] == 50
            assert stream_res["e2e_ttft_p99_ms"] > 0.0
    finally:
        await mock_client.aclose()
        state.client = None
