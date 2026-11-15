"""
Mock LLM server for Day 7 integration testing.

Accepts prompts from the mock proxy, records exactly what it receives,
and returns an echo response.

This is a local test service, not a production LLM server.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, request


app = Flask(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = PROJECT_ROOT / "logs"
LOG_FILE = LOG_DIR / "mock_llm_received.jsonl"

LOG_DIR.mkdir(parents=True, exist_ok=True)


@app.get("/health")
def health():
    return jsonify({
        "status": "healthy",
        "service": "mock-llm",
    }), 200


@app.post("/generate")
def generate():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Expected a JSON object"}), 400

    prompt = data.get("prompt")

    if not isinstance(prompt, str) or not prompt.strip():
        return jsonify({"error": "A non-empty prompt is required"}), 400

    # Record exactly what reached the mock LLM.
    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "prompt": prompt,
    }

    with LOG_FILE.open("a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(log_entry) + "\n")

    # Echo the received prompt to simulate an LLM completion.
    completion = f"Mock LLM processed: {prompt}"

    return jsonify({
        "completion": completion,
        "model": "day7-mock-llm",
    }), 200


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=6002,
        debug=False,
    )
