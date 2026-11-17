from fastapi.responses import JSONResponse

from src.security.error_response import build_security_error


def test_build_security_error_returns_standard_schema():
    response = build_security_error(
        status_code=403,
        code="PROMPT_SECURITY_VIOLATION",
        rule_id="SEC-004",
        message="Prompt violated corporate AI security policy",
        trace_id="trc-test123",
    )

    assert isinstance(response, JSONResponse)
    assert response.status_code == 403

    body = response.body.decode("utf-8")

    import json
    data = json.loads(body)

    assert data == {
        "error": {
            "code": "PROMPT_SECURITY_VIOLATION",
            "rule_id": "SEC-004",
            "message": "Prompt violated corporate AI security policy",
            "trace_id": "trc-test123",
        }
    }