from unittest.mock import MagicMock, patch

from fastapi import HTTPException
from src.proxy.proxy_server import _extract_client_ip
import httpx
import pytest
from unittest.mock import AsyncMock
from httpx import ASGITransport, AsyncClient

from src.mock.mock_llm import app as mock_app
from src.proxy.proxy_server import app as proxy_app
from src.proxy.proxy_server import state
from src.security.ip_validator import IPAccessController

AUTH_HEADERS = {"Authorization": "Bearer sk-guard-dev-tenant-001"}
AUTH_HEADERS = {"Authorization": "Bearer sk-guard-dev-tenant-001"}


@pytest.mark.asyncio
async def test_proxy_healthcheck() -> None:
    transport = ASGITransport(app=proxy_app)
    async with AsyncClient(transport=transport, base_url="http://testproxy") as client:
        res = await client.get("/healthz")
        assert res.status_code == 200
        assert res.json()["service"] == "llm_guard_proxy"


@pytest.mark.asyncio
async def test_proxy_transparent_forwarding_and_latency_header() -> None:
    await state.rate_limiter.reset()
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
            res = await pclient.post("/v1/chat/completions", json=payload, headers=AUTH_HEADERS)

            assert res.status_code == 200
            data = res.json()
            assert data["model"] == "mock-llama-3"
            assert "upstream mock LLM" in data["choices"][0]["message"]["content"]
            assert res.headers["x-tenant-id"] == "tenant-dev-001"

            assert "x-proxy-latency-ms" in res.headers
            overhead = float(res.headers["x-proxy-latency-ms"])
            assert overhead > 0.0
    finally:
        await mock_client.aclose()
        state.client = None


@pytest.mark.asyncio
async def test_proxy_upstream_down_bad_gateway() -> None:
    await state.rate_limiter.reset()
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
            res = await pclient.post("/v1/chat/completions", json=payload, headers=AUTH_HEADERS)
            assert res.status_code == 502
            assert "Bad Gateway" in res.json()["detail"]
    finally:
        await dead_client.aclose()
        state.client = None

@pytest.mark.asyncio
async def test_proxy_blocks_blacklisted_ip() -> None:
    original_controller = state.ip_controller
    original_logger = state.siem_logger
    state.ip_controller = IPAccessController(
        blocked_ips=["127.0.0.1"]
    )
    state.siem_logger = original_logger
    state.siem_logger.log_event = AsyncMock()

    try:
        transport = ASGITransport(app=proxy_app)
        async with AsyncClient(
            transport=transport,
            base_url="http://testproxy",
        ) as client:
            payload = {
                "model": "mock-llama-3",
                "messages": [{"role": "user", "content": "Test IP blocking"}],
                "stream": False,
            }

            response = await client.post(
                "/v1/chat/completions",
                json=payload,
                headers=AUTH_HEADERS,
            )

            assert response.status_code == 403
            assert response.json()["detail"] == (
                "Client IP address is not allowed"
            )
            assert response.headers["X-Guard-Rule-Id"] == (
                "IP-403-BLACKLISTED"
            )

            state.siem_logger.log_event.assert_awaited_once()
            logged_event = state.siem_logger.log_event.await_args.kwargs
            assert logged_event["action"] == "BLOCK"
            assert logged_event["rule_id"] == "IP-403-BLACKLISTED"

    finally:
        state.ip_controller = original_controller
        state.siem_logger = original_logger

@pytest.mark.asyncio
async def test_proxy_blocks_ip_outside_allowed_cidr() -> None:
    original_controller = state.ip_controller
    original_logger = state.siem_logger

    state.ip_controller = IPAccessController(
        allowed_networks=["10.10.0.0/16"]
    )
    mock_logger = AsyncMock()
    state.siem_logger = type("MockSIEM", (), {"log_event": mock_logger})()

    try:
        transport = ASGITransport(app=proxy_app)
        async with AsyncClient(
            transport=transport,
            base_url="http://testproxy",
        ) as client:
            payload = {
                "model": "mock-llama-3",
                "messages": [{"role": "user", "content": "Test CIDR blocking"}],
                "stream": False,
            }

            response = await client.post(
                "/v1/chat/completions",
                json=payload,
                headers=AUTH_HEADERS,
            )

            assert response.status_code == 403
            assert response.headers["X-Guard-Rule-Id"] == (
                "IP-403-CIDR-DENIED"
            )
            mock_logger.assert_awaited_once()

    finally:
        state.ip_controller = original_controller
        state.siem_logger = original_logger

@pytest.mark.asyncio
async def test_proxy_allows_ip_inside_corporate_cidr() -> None:
    original_controller = state.ip_controller

    state.ip_controller = IPAccessController(
        allowed_networks=["127.0.0.1/32"]
    )

    try:
        transport = ASGITransport(app=proxy_app)

        async with AsyncClient(
            transport=transport,
            base_url="http://testproxy",
        ) as client:
            response = await client.post(
                "/v1/chat/completions",
                json={
                    "model": "mock-llama-3",
                    "messages": [
                        {"role": "user", "content": "Test allowed IP"}
                    ],
                    "stream": False,
                },
            )

            # IP is allowed, so the request reaches API authentication.
            assert response.status_code == 401

    finally:
        state.ip_controller = original_controller


def test_untrusted_client_cannot_spoof_forwarded_ip() -> None:
    request = MagicMock()
    request.client.host = "192.168.1.50"
    request.headers = {
        "X-Forwarded-For": "10.10.5.20"
    }

    with patch.dict(
        "os.environ",
        {"LLM_GUARD_TRUSTED_PROXY_CIDRS": "10.0.0.0/8"},
    ):
        result = _extract_client_ip(request)

    assert result == "192.168.1.50"

def test_trusted_proxy_extracts_forwarded_client_ip() -> None:
    request = MagicMock()
    request.client.host = "10.0.0.5"
    request.headers = {
        "X-Forwarded-For": "192.168.1.25"
    }

    with patch.dict(
        "os.environ",
        {"LLM_GUARD_TRUSTED_PROXY_CIDRS": "10.0.0.0/8"},
    ):
        result = _extract_client_ip(request)

    assert result == "192.168.1.25"

def test_trusted_proxy_without_forwarded_header_is_rejected() -> None:
    request = MagicMock()
    request.client.host = "10.0.0.5"
    request.headers = {}

    with patch.dict(
        "os.environ",
        {"LLM_GUARD_TRUSTED_PROXY_CIDRS": "10.0.0.0/8"},
    ):
        with pytest.raises(HTTPException) as exc_info:
            _extract_client_ip(request)

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == (
        "Missing X-Forwarded-For header from trusted proxy"
    )

def test_trusted_proxy_with_invalid_forwarded_ip_is_rejected() -> None:
    request = MagicMock()
    request.client.host = "10.0.0.5"
    request.headers = {
        "X-Forwarded-For": "not-an-ip"
    }

    with patch.dict(
        "os.environ",
        {"LLM_GUARD_TRUSTED_PROXY_CIDRS": "10.0.0.0/8"},
    ):
        with pytest.raises(HTTPException) as exc_info:
            _extract_client_ip(request)

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "Invalid X-Forwarded-For header"

def test_invalid_immediate_peer_ip_is_rejected() -> None:
    request = MagicMock()
    request.client.host = "invalid-peer-ip"
    request.headers = {}

    with pytest.raises(HTTPException) as exc_info:
        _extract_client_ip(request)

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "Invalid immediate peer IP address"