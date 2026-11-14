import json
import os
import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator, AsyncIterator

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import StreamingResponse
from starlette.requests import ClientDisconnect

from src.security.auth import authenticate_request
from src.security.rate_limiter import SlidingWindowRateLimiter

UPSTREAM_BASE_URL = os.getenv("UPSTREAM_BASE_URL", "http://127.0.0.1:8001")


class ProxyState:
    client: httpx.AsyncClient | None = None
    rate_limiter: SlidingWindowRateLimiter = SlidingWindowRateLimiter(window_seconds=60.0)


state = ProxyState()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    limits = httpx.Limits(
        max_keepalive_connections=100,
        max_connections=500,
        keepalive_expiry=30.0,
    )
    timeout = httpx.Timeout(connect=3.0, read=30.0, write=5.0, pool=5.0)

    state.client = httpx.AsyncClient(
        base_url=UPSTREAM_BASE_URL,
        limits=limits,
        timeout=timeout,
        headers={"User-Agent": "LLM-Guard-CoreProxy/1.0"},
    )
    try:
        yield
    finally:
        if state.client is not None:
            await state.client.aclose()


app = FastAPI(
    title="LLM-Guard AI Firewall Proxy",
    description="Core Reverse Proxy Middleware Layer with Auth, Rate Limiting & Zero-Buffer SSE",
    version="1.1.0",
    lifespan=lifespan,
)


@app.get("/healthz")
async def healthcheck() -> dict[str, str]:
    """Unauthenticated liveness probe for container orchestrators."""
    return {"status": "healthy", "service": "llm_guard_proxy", "port": "8000"}


async def stream_upstream_bytes(
    upstream_resp: httpx.Response,
) -> AsyncGenerator[bytes, None]:
    """
    Zero-buffer async generator yielding raw SSE chunks directly as they arrive
    from the upstream LLM without accumulating the full response in RAM.
    """
    try:
        async for chunk in upstream_resp.aiter_raw():
            if chunk:
                yield chunk
    except (ClientDisconnect, GeneratorExit):
        pass
    finally:
        await upstream_resp.aclose()


@app.post("/v1/chat/completions")
async def proxy_chat_completions(request: Request) -> Response:
    # Stage 1: Authenticate API Key & Resolve Tenant Context
    tenant = authenticate_request(request)

    # Stage 2: Enforce Sliding-Window Per-Tenant Rate Limit
    rl_info = await state.rate_limiter.check_and_record(
        tenant_id=tenant.tenant_id,
        rpm_limit=tenant.rpm_limit,
    )

    if state.client is None:
        raise HTTPException(status_code=500, detail="Proxy client uninitialized")

    try:
        raw_body = await request.body()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to read request body: {exc}")

    is_stream = False
    try:
        parsed_body = json.loads(raw_body)
        if isinstance(parsed_body, dict):
            is_stream = bool(parsed_body.get("stream", False))
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Malformed JSON payload")

    # Strip hop-by-hop headers AND client proxy Authorization token before forwarding upstream
    forward_headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in ("host", "content-length", "authorization")
    }

    security_headers = {
        "X-Tenant-Id": tenant.tenant_id,
        "X-RateLimit-Limit": str(rl_info.limit),
        "X-RateLimit-Remaining": str(rl_info.remaining),
        "X-RateLimit-Reset": str(rl_info.reset_seconds),
        "X-LLM-Guard-Version": "1.1.0",
    }

    t_start = time.perf_counter()

    # 1. HIGH-THROUGHPUT SSE STREAMING PATH
    if is_stream:
        req = state.client.build_request(
            "POST",
            "/v1/chat/completions",
            content=raw_body,
            headers=forward_headers,
        )
        try:
            upstream_resp = await state.client.send(req, stream=True)
        except httpx.ConnectError:
            raise HTTPException(
                status_code=502,
                detail="Bad Gateway: Upstream LLM engine unreachable at port 8001",
            )
        except httpx.TimeoutException:
            raise HTTPException(
                status_code=504,
                detail="Gateway Timeout: Upstream LLM engine exceeded response deadline",
            )

        if upstream_resp.status_code >= 400:
            err_body = await upstream_resp.aread()
            await upstream_resp.aclose()
            return Response(
                content=err_body,
                status_code=upstream_resp.status_code,
                headers=security_headers,
                media_type=upstream_resp.headers.get("content-type", "application/json"),
            )

        ttft_ms = (time.perf_counter() - t_start) * 1000.0

        stream_headers = {
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
            "X-Proxy-TTFT-Ms": f"{ttft_ms:.2f}",
            **security_headers,
        }

        return StreamingResponse(
            stream_upstream_bytes(upstream_resp),
            status_code=upstream_resp.status_code,
            headers=stream_headers,
            media_type="text/event-stream",
        )

    # 2. STANDARD UNARY JSON PATH
    try:
        upstream_resp = await state.client.post(
            "/v1/chat/completions",
            content=raw_body,
            headers=forward_headers,
        )
    except httpx.ConnectError:
        raise HTTPException(
            status_code=502,
            detail="Bad Gateway: Upstream LLM engine unreachable at port 8001",
        )
    except httpx.TimeoutException:
        raise HTTPException(
            status_code=504,
            detail="Gateway Timeout: Upstream LLM engine exceeded response deadline",
        )

    transit_latency_ms = (time.perf_counter() - t_start) * 1000.0

    response_headers = dict(upstream_resp.headers)
    response_headers["X-Proxy-Latency-Ms"] = f"{transit_latency_ms:.2f}"
    response_headers.update(security_headers)

    return Response(
        content=upstream_resp.content,
        status_code=upstream_resp.status_code,
        headers=response_headers,
        media_type=upstream_resp.headers.get("content-type", "application/json"),
    )
