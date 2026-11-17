from src.security.ip_validator import IPAccessController
import logging
import ipaddress
from pathlib import Path
import yaml

from rule_engine_service import RuleEngine
from token_limiter import TokenLimiter
import json
import os
import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator, AsyncIterator

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.requests import ClientDisconnect

from src.security.auth import TenantContext, authenticate_request
from src.security.ip_validator import IPAccessController
from src.security.prompt_guard import inspect_chat_payload
from src.security.rate_limiter import SlidingWindowRateLimiter
from src.security.siem_logger import SIEMEventLogger, generate_trace_id

UPSTREAM_BASE_URL = os.getenv("UPSTREAM_BASE_URL", "http://127.0.0.1:8001")
logger = logging.getLogger(__name__)

RULES_PATH = Path(__file__).resolve().parents[2] / "rules.yaml"
def _get_ip_list(env_name: str) -> list[str]:
    """Read comma-separated IP/CIDR values from an environment variable."""
    value = os.getenv(env_name, "")
    return [item.strip() for item in value.split(",") if item.strip()]

def load_security_rules() -> list[dict]:
    """Load firewall rules from the root rules.yaml file."""
    with RULES_PATH.open("r", encoding="utf-8") as file:
        config = yaml.safe_load(file) or {}

    rules = config.get("rules")

    if not isinstance(rules, list):
        raise ValueError("rules.yaml must contain a valid 'rules' list")

    return rules

def extract_prompt_text(payload: dict) -> str:
    """Extract text content from OpenAI-style chat messages."""

    messages = payload.get("messages", [])

    if not isinstance(messages, list):
        return ""

    extracted_text = []

    for message in messages:
        if not isinstance(message, dict):
            continue

        content = message.get("content", "")

        if isinstance(content, str):
            extracted_text.append(content)

        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict):
                    text_content = part.get("text")

                    if isinstance(text_content, str):
                        extracted_text.append(text_content)

    return "\n".join(extracted_text)

class ProxyState:
    client: httpx.AsyncClient | None = None
    rate_limiter: SlidingWindowRateLimiter = SlidingWindowRateLimiter(window_seconds=60.0)
    siem_logger: SIEMEventLogger = SIEMEventLogger()
    ip_controller: IPAccessController = IPAccessController(
    allowed_networks=_get_ip_list("LLM_GUARD_ALLOWED_CIDRS"),
    blocked_ips=_get_ip_list("LLM_GUARD_BLOCKED_IPS"),
    )
    rules: list[dict] = load_security_rules()
    rule_engine: RuleEngine = RuleEngine(rules)
    token_limiter: TokenLimiter = TokenLimiter(
        max_tokens=int(os.getenv("MAX_PROMPT_TOKENS", "2500"))
    )

state = ProxyState()


def _extract_client_ip(request: Request) -> str:
    """Extract client IP without trusting arbitrary forwarded headers."""

    if not request.client or not request.client.host:
        raise HTTPException(
            status_code=400,
            detail="Unable to determine client IP address",
        )

    try:
        peer_ip = ipaddress.ip_address(request.client.host)
    except ValueError:
        raise HTTPException(
        status_code=400,
        detail="Invalid immediate peer IP address",
    )

    trusted_proxies = [
        ipaddress.ip_network(cidr, strict=False)
        for cidr in _get_ip_list("LLM_GUARD_TRUSTED_PROXY_CIDRS")
    ]

    is_trusted_proxy = any(
        peer_ip.version == network.version and peer_ip in network
        for network in trusted_proxies
    )

    if not is_trusted_proxy:
        return str(peer_ip)

    forwarded = request.headers.get("X-Forwarded-For")

    if not forwarded:
        raise HTTPException(
            status_code=400,
            detail="Missing X-Forwarded-For header from trusted proxy",
        )

    try:
        forwarded_ips = [
            ipaddress.ip_address(value.strip())
            for value in forwarded.split(",")
        ]
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Invalid X-Forwarded-For header",
        )

    # Walk from the nearest proxy towards the original client.
    for address in reversed(forwarded_ips):
        is_trusted_hop = any(
            address.version == network.version and address in network
            for network in trusted_proxies
        )
        if not is_trusted_hop:
            return str(address)

    return str(forwarded_ips[0])


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
        headers={"User-Agent": "LLM-Guard-CoreProxy/1.3"},
    )
    try:
        await state.rate_limiter.connect()
        yield
    finally:
        if state.client is not None:
            await state.client.aclose()

        await state.rate_limiter.close()


app = FastAPI(
    title="LLM-Guard AI Firewall Proxy",
    description="Core Reverse Proxy Middleware Layer with Auth, Rate Limiting, Prompt Guardrails & SIEM",
    version="1.3.0",
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
    t_req_start = time.perf_counter()
    trace_id = generate_trace_id()
    client_ip = _extract_client_ip(request)

# Stage 0: Enforce IP allowlist and blacklist
        # Stage 0: Enforce IP allowlist and blacklist
    ip_result = state.ip_controller.validate_ip(client_ip)

    if not ip_result.allowed:
        latency_ms = (time.perf_counter() - t_req_start) * 1000.0

        rule_id = {
            "BLACKLISTED_IP": "IP-403-BLACKLISTED",
            "IP_NOT_IN_ALLOWED_CIDR": "IP-403-CIDR-DENIED",
            "INVALID_IP_ADDRESS": "IP-403-INVALID",
        }.get(ip_result.reason, "IP-403-DENIED")

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
            status_code=403,
            content={"detail": "Client IP address is not allowed"},
            headers={
                "X-Trace-Id": trace_id,
                "X-Guard-Rule-Id": rule_id,
            },
        )

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
            rl_info = await state.rate_limiter.check_limit(
        api_key=tenant.api_key_id or tenant.tenant_id,
        max_reqs=tenant.rpm_limit,
        window_secs=60,
    )
    except HTTPException as rl_exc:
        latency_ms = (time.perf_counter() - t_req_start) * 1000.0
        exc_headers = dict(rl_exc.headers or {})
        exc_headers["X-Trace-Id"] = trace_id
        exc_headers["X-Tenant-Id"] = tenant.tenant_id

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

    # Stage 3: Pre-Inference Prompt Injection & Jailbreak Guardrail
    guard_verdict = inspect_chat_payload(parsed_body)
    if guard_verdict.blocked:
        latency_ms = (time.perf_counter() - t_req_start) * 1000.0
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

        # Stage 4: Member 4 - Token Limit Enforcement
    prompt_text = extract_prompt_text(parsed_body)

    token_result = state.token_limiter.validate_prompt(prompt_text)

    if token_result["is_blocked"]:
        latency_ms = (time.perf_counter() - t_req_start) * 1000.0

        await state.siem_logger.log_event(
            trace_id=trace_id,
            client_ip=client_ip,
            user_id=tenant.user_id,
            user_role=tenant.user_role,
            action="BLOCK",
            rule_id="TOK-413-LIMIT-EXCEEDED",
            ml_score=0.0,
            latency_ms=latency_ms,
        )

        return JSONResponse(
            status_code=413,
            content={
                "detail": "Prompt exceeds maximum token limit",
                "token_count": token_result["token_count"],
                "max_tokens": token_result["max_tokens"],
            },
            headers={
                "X-Trace-Id": trace_id,
                "X-Tenant-Id": tenant.tenant_id,
            },
        )

    # Stage 5: Member 4 - Static Rule Engine
    rule_result = state.rule_engine.evaluate(prompt_text)

    if rule_result.is_blocked:
        latency_ms = (time.perf_counter() - t_req_start) * 1000.0

        await state.siem_logger.log_event(
            trace_id=trace_id,
            client_ip=client_ip,
            user_id=tenant.user_id,
            user_role=tenant.user_role,
            action="BLOCK",
            rule_id=rule_result.triggered_rule or "RULE-ENGINE-BLOCK",
            ml_score=0.0,
            latency_ms=latency_ms,
        )

        return JSONResponse(
            status_code=403,
            content={
                "detail": "Blocked by Member 4 Rule Engine",
                "rule_id": rule_result.triggered_rule,
                "severity": rule_result.severity,
                "trace_id": trace_id,
            },
            headers={
                "X-Trace-Id": trace_id,
                "X-Tenant-Id": tenant.tenant_id,
                "X-Guard-Rule-Id": rule_result.triggered_rule or "",
            },
        )

    # WARN rules allow the request but attach a warning header.
    rule_warning_headers = {}

    if rule_result.severity == "WARN":
        warning_rule = rule_result.triggered_rule or "WARNING"
        rule_warning_headers["X-LLM-Guard-Warning"] = warning_rule

        logger.warning(
            "Rule Engine warning triggered: %s",
            warning_rule,
        )

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
        "X-LLM-Guard-Version": "1.3.0",
    }

    security_headers.update(rule_warning_headers)

    t_upstream_start = time.perf_counter()

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

        ttft_ms = (time.perf_counter() - t_upstream_start) * 1000.0
        total_guard_ms = (time.perf_counter() - t_req_start) * 1000.0

        await state.siem_logger.log_event(
            trace_id=trace_id,
            client_ip=client_ip,
            user_id=tenant.user_id,
            user_role=tenant.user_role,
            action="ALLOW",
            rule_id="PASS-ALL-CHECKS",
            ml_score=0.0,
            latency_ms=total_guard_ms,
        )

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

    transit_latency_ms = (time.perf_counter() - t_upstream_start) * 1000.0
    total_latency_ms = (time.perf_counter() - t_req_start) * 1000.0

    await state.siem_logger.log_event(
        trace_id=trace_id,
        client_ip=client_ip,
        user_id=tenant.user_id,
        user_role=tenant.user_role,
        action="ALLOW",
        rule_id="PASS-ALL-CHECKS",
        ml_score=0.0,
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
