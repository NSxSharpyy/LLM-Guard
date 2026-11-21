import json
from pathlib import Path
import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from src.proxy.proxy_server import app as proxy_app
from src.proxy.proxy_server import state
from src.security.siem_logger import SIEMEventLogger

AUTH_HEADERS = {
    "Authorization": "Bearer sk-guard-bench-enterprise-999",
}


@pytest.mark.asyncio
async def test_hardcoded_secrets_blocked_by_dlp(tmp_path: Path) -> None:
    await state.rate_limiter.reset()
    test_log = tmp_path / "security_events.jsonl"
    orig_logger = state.siem_logger
    state.siem_logger = SIEMEventLogger(log_path=str(test_log))

    # Dummy client (should never even be called because DLP blocks pre-upstream)
    dummy_client = httpx.AsyncClient(base_url="http://127.0.0.1:9999")
    state.client = dummy_client

    secret_prompts = [
        "My AWS key is AKIAIOSFODNN7EXAMPLE please deploy this.",
        "Debug this OpenAI key: sk-proj-9876543210abcdefghijklmnop",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...",
    ]

    try:
        proxy_transport = ASGITransport(app=proxy_app)
        async with AsyncClient(transport=proxy_transport, base_url="http://testproxy") as pclient:
            for prompt in secret_prompts:
                payload = {
                    "model": "mock-llama-3",
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False,
                }
                res = await pclient.post("/v1/chat/completions", json=payload, headers=AUTH_HEADERS)
                assert res.status_code == 400
                assert res.json()["rule_id"] == "DLP-001-SECRET-EXFILTRATION"

        records = [json.loads(line) for line in test_log.read_text().strip().splitlines()]
        assert len(records) == 3
        assert all(r["action"] == "BLOCK" and r["rule_id"] == "DLP-001-SECRET-EXFILTRATION" for r in records)
    finally:
        await dummy_client.aclose()
        state.client = None
        state.siem_logger = orig_logger


@pytest.mark.asyncio
async def test_pii_inline_redaction_before_upstream_dispatch(tmp_path: Path) -> None:
    await state.rate_limiter.reset()
    test_log = tmp_path / "security_events.jsonl"
    orig_logger = state.siem_logger
    state.siem_logger = SIEMEventLogger(log_path=str(test_log))

    captured_upstream_bodies: list[dict] = []

    async def mock_upstream_handler(request: httpx.Request) -> httpx.Response:
        captured_upstream_bodies.append(json.loads(request.content.decode("utf-8")))
        return httpx.Response(
            200,
            json={
                "id": "chatcmpl-test",
                "object": "chat.completion",
                "created": 1700000000,
                "model": "mock-llama-3",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "Processed safely."},
                        "finish_reason": "stop",
                    }
                ],
            },
        )

    mock_client = httpx.AsyncClient(
        transport=httpx.MockTransport(mock_upstream_handler),
        base_url="http://mockupstream",
    )
    state.client = mock_client

    try:
        proxy_transport = ASGITransport(app=proxy_app)
        async with AsyncClient(transport=proxy_transport, base_url="http://testproxy") as pclient:
            payload = {
                "model": "mock-llama-3",
                "messages": [
                    {
                        "role": "user",
                        "content": "Contact alice@example.com, PAN ABCDE1234F, card 4532015112830366, ref 1234567812345678.",
                    }
                ],
                "stream": False,
            }
            res = await pclient.post("/v1/chat/completions", json=payload, headers=AUTH_HEADERS)
            assert res.status_code == 200
            assert res.headers["x-guard-pii-redacted"] == "true"
            assert res.headers["x-guard-rule-id"] == "DLP-002-PII-REDACTED"

        # Verify upstream NEVER saw raw email, PAN, or Luhn-valid card
        forwarded_msg = captured_upstream_bodies[0]["messages"][0]["content"]
        assert "alice@example.com" not in forwarded_msg
        assert "ABCDE1234F" not in forwarded_msg
        assert "4532015112830366" not in forwarded_msg
        assert "[REDACTED_EMAIL]" in forwarded_msg
        assert "[REDACTED_PAN]" in forwarded_msg
        assert "[REDACTED_CREDIT_CARD]" in forwarded_msg
        # Non-Luhn reference ID must remain intact (zero false positive)
        assert "1234567812345678" in forwarded_msg

        rec = json.loads(test_log.read_text().strip())
        assert rec["action"] == "ALLOW"
        assert rec["rule_id"] == "DLP-002-PII-REDACTED"
    finally:
        await mock_client.aclose()
        state.client = None
        state.siem_logger = orig_logger
