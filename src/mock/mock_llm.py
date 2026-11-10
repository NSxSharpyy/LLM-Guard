# File: src/mock/mock_llm.py
import asyncio
import random
import time
import uuid
from typing import AsyncGenerator

from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse

from src.schemas.openai import (
    ChatChoice,
    ChatChoiceDelta,
    ChatCompletionRequest,
    ChatCompletionResponse,
    ChatCompletionStreamChunk,
    ChatMessage,
    CompletionUsage,
    StreamChoice,
)

app = FastAPI(
    title="LLM-Guard Mock Upstream LLM Server",
    description="Simulates realistic OpenAI-compatible LLM streaming and latency responses",
    version="1.0.0",
)

DEFAULT_RESPONSE_TOKENS = [
    "Hello", "!", " I", " am", " the", " upstream", " mock", " LLM", " engine", ".",
    " Analyzing", " your", " prompt", " and", " generating", " a", " secure", " response", "."
]


async def generate_token_stream(
    completion_id: str,
    model_name: str,
    min_jitter_ms: int = 100,
    max_jitter_ms: int = 500,
) -> AsyncGenerator[str, None]:
    initial_chunk = ChatCompletionStreamChunk(
        id=completion_id,
        created=int(time.time()),
        model=model_name,
        choices=[StreamChoice(index=0, delta=ChatChoiceDelta(role="assistant", content=""), finish_reason=None)],
    )
    yield f"data: {initial_chunk.model_dump_json()}\n\n"

    for token in DEFAULT_RESPONSE_TOKENS:
        jitter_delay = random.uniform(min_jitter_ms / 1000.0, max_jitter_ms / 1000.0)
        await asyncio.sleep(jitter_delay)
        chunk = ChatCompletionStreamChunk(
            id=completion_id,
            created=int(time.time()),
            model=model_name,
            choices=[StreamChoice(index=0, delta=ChatChoiceDelta(content=token), finish_reason=None)],
        )
        yield f"data: {chunk.model_dump_json()}\n\n"

    final_chunk = ChatCompletionStreamChunk(
        id=completion_id,
        created=int(time.time()),
        model=model_name,
        choices=[StreamChoice(index=0, delta=ChatChoiceDelta(), finish_reason="stop")],
    )
    yield f"data: {final_chunk.model_dump_json()}\n\n"
    yield "data: [DONE]\n\n"


@app.post("/v1/chat/completions")
async def chat_completions(request: ChatCompletionRequest):
    if not request.messages:
        raise HTTPException(status_code=400, detail="Messages array cannot be empty")

    completion_id = f"chatcmpl-mock-{uuid.uuid4().hex[:12]}"
    created_ts = int(time.time())

    if request.stream:
        return StreamingResponse(
            generate_token_stream(completion_id=completion_id, model_name=request.model),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
        )

    await asyncio.sleep(0.2)
    full_content = "".join(DEFAULT_RESPONSE_TOKENS).strip()

    return ChatCompletionResponse(
        id=completion_id,
        created=created_ts,
        model=request.model,
        choices=[ChatChoice(index=0, message=ChatMessage(role="assistant", content=full_content), finish_reason="stop")],
        usage=CompletionUsage(prompt_tokens=15, completion_tokens=len(DEFAULT_RESPONSE_TOKENS), total_tokens=15 + len(DEFAULT_RESPONSE_TOKENS)),
    )


@app.get("/healthz")
async def healthcheck():
    return {"status": "healthy", "service": "mock_upstream_llm", "port": 8001}

