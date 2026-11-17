import json
from pathlib import Path
import pytest
from httpx import ASGITransport, AsyncClient

from src.mock.mock_llm import app as mock_app
from src.proxy.proxy_server import app as proxy_app
from src.proxy.proxy_server import state
from src.security.siem_logger import SIEMEventLogger

EXPECTED_FROZEN_KEYS = {
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

SAMPLE_PAYLOAD = {
    "model": "mock-llama-3",
    "messages": [{"role": "user", "content": "SIEM telemetry verification"}],
    "stream": False,
}


@pytest.mark.asyncio
async def test_siem_jsonl_schema_and_429_block_events(tmp_path: Path) -> None:
    await state.rate_limiter.reset()
    test_log_file = tmp_path / "security_events.jsonl"
    original_logger = state.siem_logger
    state.siem_logger = SIEMEventLogger(log_path=str(test_log_file))

    mock_transport = ASGITransport(app=mock_app)
    mock_client = AsyncClient(transport=mock_transport, base_url="http://mockupstream")
    state.client = mock_client

    try:
        proxy_transport = ASGITransport(app=proxy_app)
        async with AsyncClient(transport=proxy_transport, base_url="http://testproxy") as pclient:
            # 1. Trigger 401 Unauthorized -> anonymous BLOCK event
            r_401 = await pclient.post("/v1/chat/completions", json=SAMPLE_PAYLOAD)
            assert r_401.status_code == 401
            assert r_401.headers["x-trace-id"].startswith("trc-")

            # 2. Trigger 5 ALLOW + 1 HTTP 429 BLOCK burst on 5-RPM test tenant
            limited_headers = {
                "Authorization": "Bearer sk-guard-ratelimit-test-005",
                "X-Mock-Benchmark-Mode": "true",
            }
            for _ in range(5):
                r_ok = await pclient.post(
                    "/v1/chat/completions", json=SAMPLE_PAYLOAD, headers=limited_headers
                )
                assert r_ok.status_code == 200

            r_429 = await pclient.post(
                "/v1/chat/completions", json=SAMPLE_PAYLOAD, headers=limited_headers
            )
            assert r_429.status_code == 429
            trace_429 = r_429.headers["x-trace-id"]

        # Parse and validate every emitted JSONL line against frozen Day 1 schema
        lines = test_log_file.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 7  # 1 (401) + 5 (200) + 1 (429)

        records = [json.loads(line) for line in lines]
        for rec in records:
            assert set(rec.keys()) == EXPECTED_FROZEN_KEYS
            assert isinstance(rec["ml_score"], float)
            assert isinstance(rec["latency_ms"], float)
            assert rec["trace_id"].startswith("trc-")

        # Verify 401 event
        assert records[0]["user_id"] == "anonymous"
        assert records[0]["user_role"] == "unauthenticated"
        assert records[0]["action"] == "BLOCK"
        assert records[0]["rule_id"] == "AUTH-401-MISSING-HEADER"
        assert records[0]["ml_score"] == 0.0

        # Verify 429 event
        block_429 = records[-1]
        assert block_429["trace_id"] == trace_429
        assert block_429["user_id"] == "usr-ratelimit-test"
        assert block_429["user_role"] == "free"
        assert block_429["action"] == "BLOCK"
        assert block_429["rule_id"] == "RL-429-RPM-EXCEEDED"
        assert block_429["ml_score"] == 0.0
    finally:
        await mock_client.aclose()
        state.client = None
        state.siem_logger = original_logger
