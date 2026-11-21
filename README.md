# LLM-Guard (`proxy-core`)

High-performance FastAPI reverse proxy firewall for LLM APIs (`/v1/chat/completions`) featuring constant-time API key authentication, sliding-window rate limiting, Unicode-normalized prompt injection detection, Luhn-verified PII/secrets DLP, output inspection/redaction, zero-buffer SSE streaming, and frozen 9-field JSONL SIEM telemetry.

## Architecture Overview
- **Reverse Proxy (`src/proxy/proxy_server.py`)**: Async `httpx` connection pool with zero-buffer SSE streaming (`text/event-stream`), `X-Trace-Id` propagation, and enriched `/healthz` pipeline status probe.
- **Upstream Mock (`src/mock/mock_llm.py`)**: Local OpenAI-compatible mock inference server for unary and streaming tests.
- **Container Stack (`Dockerfile`, `docker-compose.yml`, `requirements-docker.txt`)**: Multi-service compose setup (`mock-llm`, `proxy`, and `soc-dashboard`) sharing `llm_guard_shared_logs` (`/app/logs/security_events.jsonl` mounted `rw` on `proxy` and `ro` on `soc-dashboard`).

## Security Pipeline Stages
1. **Authentication (`src/security/auth.py`)**: Constant-time SHA-256 + `hmac.compare_digest` bearer key validation (`401`/`403`) resolving `tenant_id`, `user_id`, `user_role`, and per-tenant `rpm_limit`.
2. **Rate Limiting (`src/security/rate_limiter.py`)**: Per-tenant sliding-window RPM enforcement returning `429` with rate-limit headers.
3. **Prompt Injection Guard (`src/security/prompt_guard.py`)**: NFKC + zero-width Unicode normalization and adversarial rule matching (`PI-001`..`PI-004`).
4. **PII & Secrets DLP (`src/security/pii_guard.py`)**: Hard blocks secrets (`DLP-001-SECRET-EXFILTRATION`) and redacts PII (`DLP-002-PII-REDACTED`) before upstream forwarding.
5. **Output Guard (`src/security/output_guard.py`)**: Scans and redacts sensitive output patterns (`DLP-OUT-001-API-KEY`, `DLP-OUT-002-EMAIL`).
6. **SIEM Telemetry (`src/security/siem_logger.py`)**: Appends frozen 9-field JSONL events (`timestamp`, `trace_id`, `client_ip`, `user_id`, `user_role`, `action`, `rule_id`, `ml_score`, `latency_ms`) to `SIEM_LOG_PATH` (default `logs/security_events.jsonl`).

## Quick Start (Local)
```bash
# Terminal 1: Upstream Mock LLM
uvicorn src.mock.mock_llm:app --host 127.0.0.1 --port 8001

# Terminal 2: LLM-Guard Proxy
SIEM_LOG_PATH="logs/security_events.jsonl" UPSTREAM_BASE_URL="[http://127.0.0.1:8001](http://127.0.0.1:8001)" \
  uvicorn src.proxy.proxy_server:app --host 127.0.0.1 --port 8000
