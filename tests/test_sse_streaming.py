import json
import os
import psutil
import pytest
from httpx import ASGITransport, AsyncClient

from src.mock.mock_llm import app as mock_app
from src.proxy.proxy_server import app as proxy_app
from src.proxy.proxy_server import state


@pytest.mark.asyncio
async def test_proxy_sse_streaming_passthrough() -> None:
    """Verifies real-time SSE chunk passthrough from upstream mock to client."""
    mock_transport = ASGITransport(app=mock_app)
    mock_client = AsyncClient(transport=mock_transport, base_url="http://mockupstream")
    state.client = mock_client

    try:
        proxy_transport = ASGITransport(app=proxy_app)
        async with AsyncClient(transport=proxy_transport, base_url="http://testproxy") as pclient:
            payload = {
                "model": "mock-llama-3",
                "messages": [{"role": "user", "content": "Stream via proxy"}],
                "stream": True,
            }
            async with pclient.stream("POST", "/v1/chat/completions", json=payload) as res:
                assert res.status_code == 200
                assert "text/event-stream" in res.headers["content-type"]
                assert "x-proxy-ttft-ms" in res.headers

                chunks = []
                done_received = False
                async for line in res.aiter_lines():
                    line = line.strip()
                    if not line or not line.startswith("data: "):
                        continue
                    data_str = line[len("data: ") :]
                    if data_str == "[DONE]":
                        done_received = True
                        break
                    chunks.append(json.loads(data_str))

                assert len(chunks) >= 19
                assert done_received is True
    finally:
        await mock_client.aclose()
        state.client = None


@pytest.mark.asyncio
async def test_4000_token_stream_memory_footprint() -> None:
    """
    Verifies Day 4 KPI: Streaming 4,000 tokens keeps memory growth flat (<30MB)
    without stalling or buffering the full response in RAM.
    """
    process = psutil.Process(os.getpid())
    rss_before_mb = process.memory_info().rss / (1024 * 1024)

    mock_transport = ASGITransport(app=mock_app)
    mock_client = AsyncClient(transport=mock_transport, base_url="http://mockupstream")
    state.client = mock_client

    try:
        proxy_transport = ASGITransport(app=proxy_app)
        async with AsyncClient(transport=proxy_transport, base_url="http://testproxy") as pclient:
            payload = {
                "model": "mock-llama-3",
                "messages": [{"role": "user", "content": "Generate 4000 tokens"}],
                "stream": True,
            }
            headers = {"X-Mock-Token-Count": "4000"}

            token_chunks_count = 0
            done_received = False

            async with pclient.stream(
                "POST", "/v1/chat/completions", json=payload, headers=headers
            ) as res:
                assert res.status_code == 200
                async for line in res.aiter_lines():
                    line = line.strip()
                    if not line or not line.startswith("data: "):
                        continue
                    data_str = line[len("data: ") :]
                    if data_str == "[DONE]":
                        done_received = True
                        break
                    parsed = json.loads(data_str)
                    if parsed["choices"][0]["delta"].get("content"):
                        token_chunks_count += 1

            rss_after_mb = process.memory_info().rss / (1024 * 1024)
            memory_growth_mb = rss_after_mb - rss_before_mb

            assert token_chunks_count == 4000
            assert done_received is True
            assert memory_growth_mb < 30.0, f"Memory spiked by {memory_growth_mb:.2f}MB"
    finally:
        await mock_client.aclose()
        state.client = None
