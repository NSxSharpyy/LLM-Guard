# File: tests/test_proxy_core.py
import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from src.mock.mock_llm import app as mock_app
from src.proxy.proxy_server import app as proxy_app
from src.proxy.proxy_server import state


@pytest.mark.asyncio
async def test_proxy_healthcheck() -> None:
    transport = ASGITransport(app=proxy_app)
    async with AsyncClient(transport=transport, base_url="http://testproxy") as client:
        res = await client.get("/healthz")
        assert res.status_code == 200
        assert res.json()["service"] == "llm_guard_proxy"


@pytest.mark.asyncio
async def test_proxy_transparent_forwarding_and_latency_header() -> None:
    mock_transport = ASGITransport(app=mock_app)
    mock_client = AsyncClient(transport=mock_transport, base_url="http://mockupstream")
    
    state.client = mock_client

    try:
        proxy_transport = ASGITransport(app=proxy_app)
        async with AsyncClient(transport=proxy_transport, base_url="http://testproxy") as pclient:
            payload = {
                "model": "mock-llama-3",
                "messages": [{"role": "user", "content": "Latency verification"}],
                "stream": False,
            }
            res = await pclient.post("/v1/chat/completions", json=payload)
            
            assert res.status_code == 200
            data = res.json()
            assert data["model"] == "mock-llama-3"
            assert "upstream mock LLM" in data["choices"][0]["message"]["content"]
            
            # Verify proxy transit latency tracking
            assert "x-proxy-latency-ms" in res.headers
            overhead = float(res.headers["x-proxy-latency-ms"])
            assert overhead > 0.0
    finally:
        await mock_client.aclose()
        state.client = None


@pytest.mark.asyncio
async def test_proxy_upstream_down_bad_gateway() -> None:
    dead_client = httpx.AsyncClient(base_url="http://127.0.0.1:9999")
    state.client = dead_client

    try:
        proxy_transport = ASGITransport(app=proxy_app)
        async with AsyncClient(transport=proxy_transport, base_url="http://testproxy") as pclient:
            payload = {
                "model": "mock-llama-3",
                "messages": [{"role": "user", "content": "Will fail"}],
                "stream": False,
            }
            res = await pclient.post("/v1/chat/completions", json=payload)
            assert res.status_code == 502
            assert "Bad Gateway" in res.json()["detail"]
    finally:
        await dead_client.aclose()
        state.client = None
