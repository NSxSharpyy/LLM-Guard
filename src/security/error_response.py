from fastapi.responses import JSONResponse


def build_security_error(
    status_code: int,
    code: str,
    rule_id: str,
    message: str,
    trace_id: str,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    """Build a standardized enterprise security error response."""

    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": code,
                "rule_id": rule_id,
                "message": message,
                "trace_id": trace_id,
            }
        },
        headers=headers,
    )