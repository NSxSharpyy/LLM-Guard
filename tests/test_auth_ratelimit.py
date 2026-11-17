import pytest
from httpx import ASGITransport, AsyncClient

from src.mock.mock_llm import app as mock_app
from src.proxy.proxy_server import app as proxy_app
from src.proxy.proxy_server import state

SAMPLE_PAYLOAD = {
    "model": "mock-llama-3",
    "messages": [{"role": "user", "content": "Security check"}],
    "stream": False,
}


@pytest.mark.asyncio
async def test_missing_authorization_header_returns_401() -> None:
    proxy_transport = ASGITransport(app=proxy_app)
    async with AsyncClient(
        transport=proxy_transport,
        base_url="http://testproxy",
    ) as client:
        res = await client.post("/v1/chat/completions", json=SAMPLE_PAYLOAD)

    assert res.status_code == 401
    body = res.json()["error"]
    assert body["code"] == "AUTHENTICATION_FAILED"
    assert body["rule_id"] == "AUTH-401-MISSING-HEADER"
    assert "Missing Authorization header" in body["message"]
    assert body["trace_id"] == res.headers["x-trace-id"]


@pytest.mark.asyncio
async def test_malformed_authorization_scheme_returns_401() -> None:
    proxy_transport = ASGITransport(app=proxy_app)
    async with AsyncClient(
        transport=proxy_transport,
        base_url="http://testproxy",
    ) as client:
        res = await client.post(
            "/v1/chat/completions",
            json=SAMPLE_PAYLOAD,
            headers={"Authorization": "Basic dXNlcjpwYXNz"},
        )

    assert res.status_code == 401
    body = res.json()["error"]
    assert body["code"] == "AUTHENTICATION_FAILED"
    assert body["rule_id"] == "AUTH-401-MISSING-HEADER"
    assert "Invalid Authorization header format" in body["message"]
    assert body["trace_id"] == res.headers["x-trace-id"]


@pytest.mark.asyncio
async def test_invalid_api_key_returns_403() -> None:
    proxy_transport = ASGITransport(app=proxy_app)
    async with AsyncClient(
        transport=proxy_transport,
        base_url="http://testproxy",
    ) as client:
        res = await client.post(
            "/v1/chat/completions",
            json=SAMPLE_PAYLOAD,
            headers={"Authorization": "Bearer sk-guard-fake-invalid-key"},
        )

    assert res.status_code == 403
    body = res.json()["error"]
    assert body["code"] == "AUTHENTICATION_FAILED"
    assert body["rule_id"] == "AUTH-403-INVALID-KEY"
    assert "Invalid or revoked API key" in body["message"]
    assert body["trace_id"] == res.headers["x-trace-id"]


@pytest.mark.asyncio
async def test_sliding_window_rate_limiter_enforces_429() -> None:
    await state.rate_limiter.reset()
    mock_transport = ASGITransport(app=mock_app)
    mock_client = AsyncClient(
        transport=mock_transport,
        base_url="http://mockupstream",
    )
    state.client = mock_client

    limited_headers = {
        "Authorization": "Bearer sk-guard-ratelimit-test-005",
        "X-Mock-Benchmark-Mode": "true",
    }

    try:
        proxy_transport = ASGITransport(app=proxy_app)
        async with AsyncClient(
            transport=proxy_transport,
            base_url="http://testproxy",
        ) as pclient:
            for idx in range(5):
                res = await pclient.post(
                    "/v1/chat/completions",
                    json=SAMPLE_PAYLOAD,
                    headers=limited_headers,
                )
                assert res.status_code == 200
                assert res.headers["x-ratelimit-limit"] == "5"
                assert res.headers["x-ratelimit-remaining"] == str(4 - idx)

            blocked_res = await pclient.post(
                "/v1/chat/completions",
                json=SAMPLE_PAYLOAD,
                headers=limited_headers,
            )
            assert blocked_res.status_code == 429
            assert "Retry-After" in blocked_res.headers
            assert blocked_res.headers["x-ratelimit-remaining"] == "0"

            body = blocked_res.json()["error"]
            assert body["code"] == "RATE_LIMIT_EXCEEDED"
            assert body["rule_id"] == "RL-429-RPM-EXCEEDED"
            assert "Rate limit of 5 RPM exceeded" in body["message"]
            assert body["trace_id"] == blocked_res.headers["x-trace-id"]
    finally:
        await mock_client.aclose()
        state.client = None
