# File: src/proxy/proxy_server.py
import os
import time
from contextlib import asynccontextmanager
from typing import AsyncIterator

import httpx
from fastapi import FastAPI, HTTPException, Request, Response

# Upstream target defaults to Day 2 mock server on port 8001
UPSTREAM_BASE_URL = os.getenv("UPSTREAM_BASE_URL", "http://127.0.0.1:8001")


class ProxyState:
    """Container to hold the pooled HTTP client across request lifecycles."""
    client: httpx.AsyncClient | None = None


state = ProxyState()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """
    Lifespan manager setting up high-performance connection pooling.
    Prevents TCP socket exhaustion under heavy concurrent load.
    """
    # Connection pool configuration
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
    description="Core Reverse Proxy Middleware Layer",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/healthz")
async def healthcheck() -> dict[str, str]:
    """Liveness probe for the proxy server."""
    return {"status": "healthy", "service": "llm_guard_proxy", "port": "8000"}


@app.post("/v1/chat/completions")
async def proxy_chat_completions(request: Request) -> Response:
    """
    Intercepts client chat completion requests, forwards them directly to the
    upstream LLM server, and measures pure proxy transit overhead.
    """
    if state.client is None:
        raise HTTPException(status_code=500, detail="Proxy client uninitialized")

    # 1. Capture incoming body bytes
    try:
        raw_body = await request.body()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to read request body: {exc}")

    # Forward necessary headers while dropping hop-by-hop/conflicting headers
    forward_headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in ("host", "content-length")
    }

    # 2. Timing the forwarding transit
    t_start = time.perf_counter()

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

    t_end = time.perf_counter()
    transit_latency_ms = (t_end - t_start) * 1000.0

    # 3. Inject diagnostic telemetry headers
    response_headers = dict(upstream_resp.headers)
    response_headers["X-Proxy-Latency-Ms"] = f"{transit_latency_ms:.2f}"
    response_headers["X-LLM-Guard-Version"] = "1.0.0"

    return Response(
        content=upstream_resp.content,
        status_code=upstream_resp.status_code,
        headers=response_headers,
        media_type=upstream_resp.headers.get("content-type", "application/json"),
    )
