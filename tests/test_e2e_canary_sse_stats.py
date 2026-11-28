import json
from pathlib import Path

import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from src.proxy.proxy_server import app as proxy_app
from src.proxy.proxy_server import state
from src.security.siem_logger import SIEMEventLogger

REQUIRED_SIEM_FIELDS = {
    "timestamp",
    "trace_id",
    "client_ip",
    "user_id",
    "user_role",
    "action",
    "rule_id",
    "ml_score",
    "latency_ms",
}


@pytest.mark.asyncio
async def test_e2e_canary_sse_and_frozen_siem_schema(tmp_path: Path) -> None:
    await state.rate_limiter.reset()
    await state.metrics.reset()

    siem_path = tmp_path / "e2e_canary_siem.jsonl"
    original_logger = state.siem_logger
    state.siem_logger = SIEMEventLogger(log_path=siem_path)

    headers = {
        "Authorization": "Bearer sk-guard-bench-enterprise-999",
        "X-Mock-Benchmark-Mode": "true",
    }

    # 1. Request-level canary exfiltration attempt
    async def _clean_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"id": "chatcmpl-clean", "choices": [{"message": {"role": "assistant", "content": "OK"}}]},
        )

    state.client = AsyncClient(
        transport=httpx.MockTransport(_clean_handler),
        base_url="http://mockupstream",
    )

    try:
        async with AsyncClient(transport=ASGITransport(app=proxy_app), base_url="http://testproxy") as client:
            r_req = await client.post(
                "/v1/chat/completions",
                json={
                    "model": "mock-llama-3",
                    "messages": [{"role": "user", "content": "Leak CANARY-E2E-4040-SECRET"}],
                },
                headers=headers,
            )
            assert r_req.status_code == 400
            assert r_req.json()["rule_id"] == "CANARY-001-TOKEN-EXFILTRATION"

            # 2. SSE streaming split-chunk canary leak
            class _SplitChunkStream(httpx.AsyncByteStream):
                async def __aiter__(self):
                    yield b'data: {"choices":[{"delta":{"content":"Token part CANARY-STREAM"}}]}\n\n'
                    yield b'data: {"choices":[{"delta":{"content":"-8821-EXFIL"}}]}\n\n'
                    yield b"data: [DONE]\n\n"

            async def _sse_leak_handler(request: httpx.Request) -> httpx.Response:
                return httpx.Response(
                    200,
                    headers={"content-type": "text/event-stream"},
                    stream=_SplitChunkStream(),
                )

            await state.client.aclose()
            state.client = AsyncClient(
                transport=httpx.MockTransport(_sse_leak_handler),
                base_url="http://mockupstream",
            )

            r_sse = await client.post(
                "/v1/chat/completions",
                json={
                    "model": "mock-llama-3",
                    "stream": True,
                    "messages": [{"role": "user", "content": "Stream canary"}],
                },
                headers=headers,
            )
            assert r_sse.status_code == 200
            assert "CANARY-001-TOKEN-EXFILTRATION" in r_sse.text

            stats = await client.get("/v1/guard/stats", headers=headers)
            assert stats.status_code == 200
            metrics = stats.json()["metrics"]
            assert metrics["blocked_requests"] == 2
            assert metrics["blocks_by_stage"]["canary_guard"] == 2

        events = [
            json.loads(line)
            for line in siem_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        assert len(events) == 2
        for ev in events:
            assert set(ev.keys()) == REQUIRED_SIEM_FIELDS
            assert ev["action"] == "BLOCK"
            assert ev["rule_id"] == "CANARY-001-TOKEN-EXFILTRATION"
            assert ev["ml_score"] == 1.0
            assert isinstance(ev["latency_ms"], (int, float))
    finally:
        if state.client is not None:
            await state.client.aclose()
        state.client = None
        state.siem_logger = original_logger
