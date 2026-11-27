import json
import os
import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator, AsyncIterator

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.requests import ClientDisconnect

from src.proxy.metrics import GuardRuntimeMetrics
from src.proxy.payload_guard import inspect_request_limits
from src.security.auth import TenantContext, authenticate_request
from src.security.canary_guard import inspect_canary_payload, inspect_canary_text
from src.security.pii_guard import inspect_and_sanitize_payload
from src.security.prompt_guard import inspect_chat_payload
from src.security.rate_limiter import SlidingWindowRateLimiter
from src.security.siem_logger import SIEMEventLogger, generate_trace_id

UPSTREAM_BASE_URL = os.getenv("UPSTREAM_BASE_URL", "http://127.0.0.1:8001")


class ProxyState:
    client: httpx.AsyncClient | None = None
    rate_limiter: SlidingWindowRateLimiter = SlidingWindowRateLimiter(window_seconds=60.0)
    siem_logger: SIEMEventLogger = SIEMEventLogger()
    metrics: GuardRuntimeMetrics = GuardRuntimeMetrics()


state = ProxyState()


def _extract_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"


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
        headers={"User-Agent": "LLM-Guard-CoreProxy/1.4"},
    )
    try:
        yield
    finally:
        if state.client is not None:
            await state.client.aclose()


app = FastAPI(
    title="LLM-Guard AI Firewall Proxy",
    description="Core Reverse Proxy Middleware Layer with Auth, Rate Limiting, Prompt Guard, DLP & SIEM",
    version="1.4.0",
    lifespan=lifespan,
)


@app.get("/healthz")
async def healthcheck() -> dict[str, object]:
    """Unauthenticated liveness and security-pipeline status probe."""
    return {
        "status": "healthy",
        "service": "llm_guard_proxy",
        "port": "8000",
        "version": "1.4.0",
        "siem_log_path": str(state.siem_logger.log_path),
        "guardrails": [
            "auth",
            "sliding_window_rate_limiter",
            "payload_guard",
            "canary_guard",
            "prompt_guard",
            "pii_dlp_guard",
            "output_guard",
            "siem_jsonl_emitter",
        ],
    }


@app.get("/v1/guard/stats")
async def guard_stats(request: Request) -> dict[str, object]:
    """Authenticated runtime guardrail decision counters."""
    tenant = authenticate_request(request)
    snap = await state.metrics.snapshot()
    return {
        "tenant_id": tenant.tenant_id,
        "version": "1.4.0",
        "metrics": snap,
    }


async def stream_upstream_bytes(
    upstream_resp: httpx.Response,
    *,
    trace_id: str,
    client_ip: str,
    tenant: TenantContext,
    dlp_rule_id: str,
    dlp_risk_score: float,
    pii_redacted: bool,
    t_req_start: float,
) -> AsyncGenerator[bytes, None]:
    """
    Zero-buffer async generator yielding raw SSE chunks directly as they arrive
    from the upstream LLM while inspecting a sliding tail window for canary leaks.
    """
    rolling_window = ""
    canary_triggered = False
    try:
        async for chunk in upstream_resp.aiter_raw():
            if not chunk:
                continue
            decoded = chunk.decode("utf-8", errors="replace")
            rolling_window = (rolling_window + decoded)[-256:]
            verdict = inspect_canary_text(rolling_window)
            if verdict.blocked:
                canary_triggered = True
                total_guard_ms = (time.perf_counter() - t_req_start) * 1000.0
                await state.metrics.record_block("canary_guard")
                await state.siem_logger.log_event(
                    trace_id=trace_id,
                    client_ip=client_ip,
                    user_id=tenant.user_id,
                    user_role=tenant.user_role,
                    action="BLOCK",
                    rule_id=verdict.rule_id,
                    ml_score=verdict.risk_score,
                    latency_ms=total_guard_ms,
                )
                alert_payload = json.dumps(
                    {
                        "error": {
                            "message": f"Blocked by LLM-Guard Canary Policy ({verdict.rule_id})",
                            "rule_id": verdict.rule_id,
                            "trace_id": trace_id,
                        }
                    }
                )
                yield f"data: {alert_payload}\n\ndata: [DONE]\n\n".encode("utf-8")
                break
            yield chunk

        if not canary_triggered:
            total_guard_ms = (time.perf_counter() - t_req_start) * 1000.0
            await state.metrics.record_allow(pii_redacted=pii_redacted)
            await state.siem_logger.log_event(
                trace_id=trace_id,
                client_ip=client_ip,
                user_id=tenant.user_id,
                user_role=tenant.user_role,
                action="ALLOW",
                rule_id=dlp_rule_id,
                ml_score=dlp_risk_score,
                latency_ms=total_guard_ms,
            )
    except (ClientDisconnect, GeneratorExit):
        pass
    finally:
        await upstream_resp.aclose()


@app.post("/v1/chat/completions")
async def proxy_chat_completions(request: Request) -> Response:
    t_req_start = time.perf_counter()
    trace_id = generate_trace_id()
    client_ip = _extract_client_ip(request)
    tenant: TenantContext | None = None

    # Stage 1: Authenticate API Key & Resolve User/Role Context
    try:
        tenant = authenticate_request(request)
    except HTTPException as auth_exc:
        latency_ms = (time.perf_counter() - t_req_start) * 1000.0
        exc_headers = dict(auth_exc.headers or {})
        rule_id = exc_headers.pop(
            "X-Guard-Rule-Id",
            "AUTH-401-MISSING-HEADER" if auth_exc.status_code == 401 else "AUTH-403-INVALID-KEY",
        )
        exc_headers["X-Trace-Id"] = trace_id

        await state.metrics.record_block("auth")
        await state.siem_logger.log_event(
            trace_id=trace_id,
            client_ip=client_ip,
            user_id="anonymous",
            user_role="unauthenticated",
            action="BLOCK",
            rule_id=rule_id,
            ml_score=0.0,
            latency_ms=latency_ms,
        )
        return JSONResponse(
            status_code=auth_exc.status_code,
            content={"detail": auth_exc.detail},
            headers=exc_headers,
        )

    # Stage 2: Enforce Sliding-Window Per-Tenant Rate Limit
    try:
        rl_info = await state.rate_limiter.check_and_record(
            tenant_id=tenant.tenant_id,
            rpm_limit=tenant.rpm_limit,
        )
    except HTTPException as rl_exc:
        latency_ms = (time.perf_counter() - t_req_start) * 1000.0
        exc_headers = dict(rl_exc.headers or {})
        exc_headers["X-Trace-Id"] = trace_id
        exc_headers["X-Tenant-Id"] = tenant.tenant_id

        await state.metrics.record_block("rate_limit")
        await state.siem_logger.log_event(
            trace_id=trace_id,
            client_ip=client_ip,
            user_id=tenant.user_id,
            user_role=tenant.user_role,
            action="BLOCK",
            rule_id="RL-429-RPM-EXCEEDED",
            ml_score=0.0,
            latency_ms=latency_ms,
        )
        return JSONResponse(
            status_code=rl_exc.status_code,
            content={"detail": rl_exc.detail},
            headers=exc_headers,
        )

    if state.client is None:
        raise HTTPException(status_code=500, detail="Proxy client uninitialized")

    try:
        raw_body = await request.body()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to read request body: {exc}")

    is_stream = False
    parsed_body: dict[str, object] = {}
    try:
        loaded = json.loads(raw_body)
        if isinstance(loaded, dict):
            parsed_body = loaded
            is_stream = bool(parsed_body.get("stream", False))
    except json.JSONDecodeError:
        latency_ms = (time.perf_counter() - t_req_start) * 1000.0
        await state.metrics.record_block("malformed_json")
        await state.siem_logger.log_event(
            trace_id=trace_id,
            client_ip=client_ip,
            user_id=tenant.user_id,
            user_role=tenant.user_role,
            action="BLOCK",
            rule_id="REQ-400-MALFORMED-JSON",
            ml_score=0.0,
            latency_ms=latency_ms,
        )
        return JSONResponse(
            status_code=400,
            content={"detail": "Malformed JSON payload"},
            headers={"X-Trace-Id": trace_id},
        )

    # Stage 2.5: Request Byte Size & Message Turn Limits
    payload_verdict = inspect_request_limits(raw_body=raw_body, parsed_body=parsed_body)
    if payload_verdict.blocked:
        latency_ms = (time.perf_counter() - t_req_start) * 1000.0
        await state.metrics.record_block("payload_guard")
        await state.siem_logger.log_event(
            trace_id=trace_id,
            client_ip=client_ip,
            user_id=tenant.user_id,
            user_role=tenant.user_role,
            action="BLOCK",
            rule_id=payload_verdict.rule_id,
            ml_score=payload_verdict.risk_score,
            latency_ms=latency_ms,
        )
        return JSONResponse(
            status_code=400,
            content={
                "detail": f"Blocked by LLM-Guard Payload Policy ({payload_verdict.rule_id}): {payload_verdict.reason}",
                "rule_id": payload_verdict.rule_id,
                "trace_id": trace_id,
            },
            headers={
                "X-Trace-Id": trace_id,
                "X-Tenant-Id": tenant.tenant_id,
                "X-Guard-Rule-Id": payload_verdict.rule_id,
            },
        )

    # Stage 2.8: Pre-Inference Canary-Token Exfiltration Check
    canary_in_verdict = inspect_canary_payload(parsed_body)
    if canary_in_verdict.blocked:
        latency_ms = (time.perf_counter() - t_req_start) * 1000.0
        await state.metrics.record_block("canary_guard")
        await state.siem_logger.log_event(
            trace_id=trace_id,
            client_ip=client_ip,
            user_id=tenant.user_id,
            user_role=tenant.user_role,
            action="BLOCK",
            rule_id=canary_in_verdict.rule_id,
            ml_score=canary_in_verdict.risk_score,
            latency_ms=latency_ms,
        )
        return JSONResponse(
            status_code=400,
            content={
                "detail": f"Blocked by LLM-Guard Canary Policy ({canary_in_verdict.rule_id}): {canary_in_verdict.reason}",
                "rule_id": canary_in_verdict.rule_id,
                "trace_id": trace_id,
            },
            headers={
                "X-Trace-Id": trace_id,
                "X-Tenant-Id": tenant.tenant_id,
                "X-Guard-Rule-Id": canary_in_verdict.rule_id,
            },
        )

    # Stage 3: Pre-Inference Prompt Injection & Jailbreak Guardrail
    guard_verdict = inspect_chat_payload(parsed_body)
    if guard_verdict.blocked:
        latency_ms = (time.perf_counter() - t_req_start) * 1000.0
        await state.metrics.record_block("prompt_guard")
        await state.siem_logger.log_event(
            trace_id=trace_id,
            client_ip=client_ip,
            user_id=tenant.user_id,
            user_role=tenant.user_role,
            action="BLOCK",
            rule_id=guard_verdict.rule_id,
            ml_score=guard_verdict.risk_score,
            latency_ms=latency_ms,
        )
        return JSONResponse(
            status_code=400,
            content={
                "detail": f"Blocked by LLM-Guard Security Policy ({guard_verdict.rule_id}): {guard_verdict.reason}",
                "rule_id": guard_verdict.rule_id,
                "trace_id": trace_id,
            },
            headers={
                "X-Trace-Id": trace_id,
                "X-Tenant-Id": tenant.tenant_id,
                "X-Guard-Rule-Id": guard_verdict.rule_id,
            },
        )

    # Stage 4: Pre-Inference PII & Secrets DLP Guardrail
    dlp_verdict = inspect_and_sanitize_payload(parsed_body, raw_body)
    if dlp_verdict.blocked:
        latency_ms = (time.perf_counter() - t_req_start) * 1000.0
        await state.metrics.record_block("dlp_secret")
        await state.siem_logger.log_event(
            trace_id=trace_id,
            client_ip=client_ip,
            user_id=tenant.user_id,
            user_role=tenant.user_role,
            action="BLOCK",
            rule_id=dlp_verdict.rule_id,
            ml_score=dlp_verdict.risk_score,
            latency_ms=latency_ms,
        )
        return JSONResponse(
            status_code=400,
            content={
                "detail": f"Blocked by LLM-Guard DLP Policy ({dlp_verdict.rule_id}): {dlp_verdict.reason}",
                "rule_id": dlp_verdict.rule_id,
                "trace_id": trace_id,
            },
            headers={
                "X-Trace-Id": trace_id,
                "X-Tenant-Id": tenant.tenant_id,
                "X-Guard-Rule-Id": dlp_verdict.rule_id,
            },
        )

    forward_body = dlp_verdict.sanitized_body

    forward_headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in ("host", "content-length", "authorization")
    }

    security_headers = {
        "X-Trace-Id": trace_id,
        "X-Tenant-Id": tenant.tenant_id,
        "X-RateLimit-Limit": str(rl_info.limit),
        "X-RateLimit-Remaining": str(rl_info.remaining),
        "X-RateLimit-Reset": str(rl_info.reset_seconds),
        "X-Guard-Rule-Id": dlp_verdict.rule_id,
        "X-Guard-PII-Redacted": "true" if dlp_verdict.redacted else "false",
        "X-LLM-Guard-Version": "1.4.0",
    }

    t_upstream_start = time.perf_counter()

    # 1. HIGH-THROUGHPUT SSE STREAMING PATH
    if is_stream:
        req = state.client.build_request(
            "POST",
            "/v1/chat/completions",
            content=forward_body,
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

        ttft_ms = (time.perf_counter() - t_upstream_start) * 1000.0

        stream_headers = {
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
            "X-Proxy-TTFT-Ms": f"{ttft_ms:.2f}",
            **security_headers,
        }

        return StreamingResponse(
            stream_upstream_bytes(
                upstream_resp,
                trace_id=trace_id,
                client_ip=client_ip,
                tenant=tenant,
                dlp_rule_id=dlp_verdict.rule_id,
                dlp_risk_score=dlp_verdict.risk_score,
                pii_redacted=dlp_verdict.redacted,
                t_req_start=t_req_start,
            ),
            status_code=upstream_resp.status_code,
            headers=stream_headers,
            media_type="text/event-stream",
        )

    # 2. STANDARD UNARY JSON PATH
    try:
        upstream_resp = await state.client.post(
            "/v1/chat/completions",
            content=forward_body,
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

    # Stage 5: Post-Inference Unary Canary-Token Exfiltration Check
    upstream_text = upstream_resp.content.decode("utf-8", errors="replace")
    canary_out_verdict = inspect_canary_text(upstream_text)
    if canary_out_verdict.blocked:
        total_latency_ms = (time.perf_counter() - t_req_start) * 1000.0
        await state.metrics.record_block("canary_guard")
        await state.siem_logger.log_event(
            trace_id=trace_id,
            client_ip=client_ip,
            user_id=tenant.user_id,
            user_role=tenant.user_role,
            action="BLOCK",
            rule_id=canary_out_verdict.rule_id,
            ml_score=canary_out_verdict.risk_score,
            latency_ms=total_latency_ms,
        )
        return JSONResponse(
            status_code=400,
            content={
                "detail": f"Blocked by LLM-Guard Canary Policy ({canary_out_verdict.rule_id}): {canary_out_verdict.reason}",
                "rule_id": canary_out_verdict.rule_id,
                "trace_id": trace_id,
            },
            headers={
                "X-Trace-Id": trace_id,
                "X-Tenant-Id": tenant.tenant_id,
                "X-Guard-Rule-Id": canary_out_verdict.rule_id,
            },
        )

    transit_latency_ms = (time.perf_counter() - t_upstream_start) * 1000.0
    total_latency_ms = (time.perf_counter() - t_req_start) * 1000.0

    await state.metrics.record_allow(pii_redacted=dlp_verdict.redacted)
    await state.siem_logger.log_event(
        trace_id=trace_id,
        client_ip=client_ip,
        user_id=tenant.user_id,
        user_role=tenant.user_role,
        action="ALLOW",
        rule_id=dlp_verdict.rule_id,
        ml_score=dlp_verdict.risk_score,
        latency_ms=total_latency_ms,
    )

    response_headers = dict(upstream_resp.headers)
    response_headers["X-Proxy-Latency-Ms"] = f"{transit_latency_ms:.2f}"
    response_headers.update(security_headers)

    return Response(
        content=upstream_resp.content,
        status_code=upstream_resp.status_code,
        headers=response_headers,
        media_type=upstream_resp.headers.get("content-type", "application/json"),
    )
