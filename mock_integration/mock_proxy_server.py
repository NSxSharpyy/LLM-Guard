"""
Mock proxy server for Day 7 integration testing.

Client -> DLPInterceptor -> Mock LLM -> DLPInterceptor -> Client
"""

import requests
from flask import Flask, jsonify, request

from dlp import DLPInterceptor


app = Flask(__name__)

# One interceptor instance shared by requests to this proxy.
interceptor = DLPInterceptor()

MOCK_LLM_URL = "http://127.0.0.1:6002/generate"
UPSTREAM_TIMEOUT = 10


@app.get("/health")
def health():
    return jsonify({
        "status": "healthy",
        "service": "mock-proxy",
        "active_sessions": interceptor.active_session_count(),
    }), 200


@app.post("/chat")
def chat():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Expected a JSON object"}), 400

    prompt = data.get("prompt")
    session_id = data.get("session_id")

    if not isinstance(prompt, str) or not prompt.strip():
        return jsonify({"error": "A non-empty prompt is required"}), 400

    if not isinstance(session_id, str) or not session_id.strip():
        return jsonify({"error": "A non-empty session_id is required"}), 400

    try:
        # Step 1: Mask sensitive information before forwarding.
        masked_prompt, entities = interceptor.redact(
            prompt,
            session_id,
        )

        # Step 2: Send only the masked prompt to the mock LLM.
        upstream_response = requests.post(
            MOCK_LLM_URL,
            json={"prompt": masked_prompt},
            timeout=UPSTREAM_TIMEOUT,
        )

        upstream_response.raise_for_status()
        upstream_data = upstream_response.json()

        completion = upstream_data.get("completion")

        if not isinstance(completion, str):
            return jsonify({
                "error": "Mock LLM returned an invalid completion"
            }), 502

        # Step 3: Restore original values in the response.
        restored_completion = interceptor.unmask(
            completion,
            session_id,
        )

        return jsonify({
            "completion": restored_completion,
            "entities": entities,
            "entity_count": len(entities),
            "session_id": session_id,
        }), 200

    except requests.RequestException:
        app.logger.exception("Mock LLM request failed")
        return jsonify({
            "error": "Mock LLM is unavailable"
        }), 502

    except Exception:
        app.logger.exception("Proxy processing failed")
        return jsonify({
            "error": "Proxy processing failed"
        }), 500


@app.post("/end-session")
def end_session():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Expected a JSON object"}), 400

    session_id = data.get("session_id")

    if not isinstance(session_id, str) or not session_id.strip():
        return jsonify({"error": "A non-empty session_id is required"}), 400

    interceptor.end_session(session_id)

    return jsonify({
        "status": "session ended",
        "session_active": interceptor.has_session(session_id),
        "active_sessions": interceptor.active_session_count(),
    }), 200

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=6001,
        debug=False,
    )
