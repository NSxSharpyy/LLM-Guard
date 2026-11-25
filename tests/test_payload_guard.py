import pytest
from httpx import ASGITransport, AsyncClient

from src.mock.mock_llm import app as mock_app
from src.proxy import payload_guard, proxy_server
from src.proxy.proxy_server import app as proxy_app
from src.proxy.proxy_server import state


@pytest.mark.asyncio
async def test_payload_size_and_message_turn_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    await state.rate_limiter.reset()
    await state.metrics.reset()

    def _limited_check(raw_body: bytes, parsed_body: dict) -> payload_guard.PayloadVerdict:
        return payload_guard.inspect_request_limits(
            raw_body=raw_body,
            parsed_body=parsed_body,
            max_payload_bytes=200,
            max_messages=2,
        )

    monkeypatch.setattr(proxy_server, "inspect_request_limits", _limited_check)

    mock_client = AsyncClient(transport=ASGITransport(app=mock_app), base_url="http://mockupstream")
    state.client = mock_client

    headers = {
        "Authorization": "Bearer sk-guard-bench-enterprise-999",
        "X-Mock-Benchmark-Mode": "true",
    }

    try:
        async with AsyncClient(transport=ASGITransport(app=proxy_app), base_url="http://testproxy") as client:
            # 1. Oversized payload
            huge_msg = "x" * 300
            r_big = await client.post(
                "/v1/chat/completions",
                json={"model": "mock-llama-3", "messages": [{"role": "user", "content": huge_msg}]},
                headers=headers,
            )
            assert r_big.status_code == 400
            assert r_big.json()["rule_id"] == "REQ-400-OVERSIZED-PAYLOAD"

            # 2. Too many messages
            r_turns = await client.post(
                "/v1/chat/completions",
                json={
                    "model": "mock-llama-3",
                    "messages": [
                        {"role": "user", "content": "m1"},
                        {"role": "assistant", "content": "m2"},
                        {"role": "user", "content": "m3"},
                    ],
                },
                headers=headers,
            )
            assert r_turns.status_code == 400
            assert r_turns.json()["rule_id"] == "REQ-400-TOO-MANY-MESSAGES"

            # 3. Valid request
            r_ok = await client.post(
                "/v1/chat/completions",
                json={"model": "mock-llama-3", "messages": [{"role": "user", "content": "ping"}]},
                headers=headers,
            )
            assert r_ok.status_code == 200
    finally:
        await mock_client.aclose()
        state.client = None
