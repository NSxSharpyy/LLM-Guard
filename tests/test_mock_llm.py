# File: tests/test_mock_llm.py
import json
import pytest
from httpx import ASGITransport, AsyncClient

from src.mock.mock_llm import app
from src.schemas.openai import ChatCompletionResponse, ChatCompletionStreamChunk


@pytest.mark.asyncio
async def test_mock_llm_healthcheck() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/healthz")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"
        assert response.json()["port"] == 8001


@pytest.mark.asyncio
async def test_mock_llm_unary_completion() -> None:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        payload = {
            "model": "mock-llama-3",
            "messages": [{"role": "user", "content": "Ping mock LLM"}],
            "stream": False,
        }
        response = await client.post("/v1/chat/completions", json=payload)
        assert response.status_code == 200
        data = response.json()
        validated = ChatCompletionResponse.model_validate(data)
        assert validated.choices[0].message.role == "assistant"
        assert "upstream mock LLM" in validated.choices[0].message.content


@pytest.mark.asyncio
async def test_mock_llm_streaming_sse_integrity() -> None:
    """Verifies that the SSE stream delivers uninterrupted chunks and terminates cleanly."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        payload = {
            "model": "mock-llama-3",
            "messages": [{"role": "user", "content": "Stream test prompt"}],
            "stream": True,
        }
        async with client.stream("POST", "/v1/chat/completions", json=payload) as response:
            assert response.status_code == 200
            assert "text/event-stream" in response.headers["content-type"]

            chunks_received = 0
            has_done_signal = False
            reconstructed_text = ""

            async for line in response.aiter_lines():
                line = line.strip()
                if not line or not line.startswith("data: "):
                    continue

                raw_data = line[len("data: ") :]
                if raw_data == "[DONE]":
                    has_done_signal = True
                    break

                chunk_dict = json.loads(raw_data)
                validated_chunk = ChatCompletionStreamChunk.model_validate(chunk_dict)
                content = validated_chunk.choices[0].delta.content
                if content:
                    reconstructed_text += content
                chunks_received += 1

            assert chunks_received >= 19
            assert has_done_signal is True
            assert "upstream mock LLM" in reconstructed_text
