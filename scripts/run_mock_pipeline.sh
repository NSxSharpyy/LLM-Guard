
#!/usr/bin/env bash

set -Eeuo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

PYTHON="$PROJECT_ROOT/.venv/bin/python"
LOG_DIR="$PROJECT_ROOT/logs"

LLM_PID=""
PROXY_PID=""

cleanup() {
    if [[ -n "$PROXY_PID" || -n "$LLM_PID" ]]; then
        echo
        echo "[INFO] Stopping mock services..."
    fi

    if [[ -n "$PROXY_PID" ]]; then
        kill "$PROXY_PID" 2>/dev/null || true
        wait "$PROXY_PID" 2>/dev/null || true
    fi

    if [[ -n "$LLM_PID" ]]; then
        kill "$LLM_PID" 2>/dev/null || true
        wait "$LLM_PID" 2>/dev/null || true
    fi

    if [[ -n "$PROXY_PID" || -n "$LLM_PID" ]]; then
        echo "[INFO] Mock services stopped."
    fi
}

if [[ ! -x "$PYTHON" ]]; then
    echo "[FAIL] Virtual environment Python not found."
    echo "Expected: $PYTHON"
    exit 1
fi

mkdir -p "$LOG_DIR"

# Refuse to use services from an earlier run.
if curl -fsS http://127.0.0.1:6001/health >/dev/null 2>&1 ||
   curl -fsS http://127.0.0.1:6002/health >/dev/null 2>&1; then
    echo "[FAIL] A mock service is already running."
    echo "Stop the existing service before launching this pipeline."
    exit 1
fi

# Install cleanup handlers only after the pre-check.
trap cleanup EXIT
trap 'exit 130' INT TERM

echo "=== Starting Week 1 Mock DLP Pipeline ==="

"$PYTHON" -m mock_integration.mock_llm_server \
    > "$LOG_DIR/mock_llm_server.log" 2>&1 &
LLM_PID=$!

echo "[INFO] Mock LLM starting (port 6002)..."

"$PYTHON" -m mock_integration.mock_proxy_server \
    > "$LOG_DIR/mock_proxy_server.log" 2>&1 &
PROXY_PID=$!

echo "[INFO] Mock proxy starting (port 6001)..."

# Wait for both health endpoints.
ready=false

for attempt in {1..30}; do
    if curl -fsS http://127.0.0.1:6002/health >/dev/null 2>&1 &&
       curl -fsS http://127.0.0.1:6001/health >/dev/null 2>&1; then
        ready=true
        break
    fi

    if ! kill -0 "$LLM_PID" 2>/dev/null ||
       ! kill -0 "$PROXY_PID" 2>/dev/null; then
        echo "[FAIL] A mock service exited unexpectedly."
        echo "[INFO] Check logs in $LOG_DIR/"
        exit 1
    fi

    sleep 1
done

if [[ "$ready" != true ]]; then
    echo "[FAIL] Services did not become healthy in time."
    echo "[INFO] Check logs in $LOG_DIR/"
    exit 1
fi

echo "[PASS] Mock LLM is healthy."
echo "[PASS] Mock proxy is healthy."

echo
echo "=== MOCK PIPELINE READY ==="
echo "Mock LLM:   http://127.0.0.1:6002"
echo "Mock proxy: http://127.0.0.1:6001"
echo
echo "Run tests in another terminal:"
echo "  python -m pytest -v tests/test_day7_integration.py"
echo "  python scripts/week1_integration_test.py"
echo
echo "Press Ctrl+C to stop both services."

# Monitor both processes while the pipeline is running.
while kill -0 "$LLM_PID" 2>/dev/null &&
      kill -0 "$PROXY_PID" 2>/dev/null; do
    sleep 1
done

echo "[FAIL] A mock service stopped unexpectedly."
echo "[INFO] Check logs in $LOG_DIR/"
exit 1
