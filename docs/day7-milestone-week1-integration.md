
# Day 7 — Week 1 Integration Milestone

## Status

**LOCAL MOCK HTTP INTEGRATION: VERIFIED**

The local mock pipeline demonstrates reversible PII masking across an HTTP boundary.

This milestone does not claim integration with the actual M1 proxy or a production LLM provider.

## 1. Objective

Verify that sensitive information is masked before a prompt is forwarded to an upstream LLM service and restored when the response returns to the client.

## 2. Architecture

```text
Client
  |
  v
Mock Proxy (127.0.0.1:6001)
  |
  | DLPInterceptor.redact()
  v
Masked prompt
  |
  v
Mock LLM (127.0.0.1:6002)
  |
  | Echo completion
  v
Mock Proxy
  |
  | DLPInterceptor.unmask()
  v
Client receives restored response
```

## 3. Services

### Mock Proxy

File: `mock_integration/mock_proxy_server.py`

Address: `http://127.0.0.1:6001`

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Proxy health and active session count |
| POST | `/chat` | Mask prompt, forward it, restore response |
| POST | `/end-session` | Clear session mappings |

### Mock LLM

File: `mock_integration/mock_llm_server.py`

Address: `http://127.0.0.1:6002`

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Mock LLM health |
| POST | `/generate` | Receive and log prompt, return echo response |

Received prompts are recorded in:

`logs/mock_llm_received.jsonl`

The mock LLM records the exact prompt it receives. During a
negative security test, this log may contain original sensitive
values if masking is bypassed.

The `logs/` directory is ignored by Git, but Git exclusion does
not provide confidentiality. These logs are intended for local
development and testing only. Restrict access to them and
remove test logs when they are no longer needed.

Do not use this prompt-logging implementation in production.
Production logging must avoid recording original sensitive
values.

## 4. Detection and masking coverage

| Entity | Placeholder |
|---|---|
| Email address | `<EMAIL_1>` |
| Phone number | `<PHONE_1>` |
| Credit card | `<CREDIT_CARD_1>` |

Other custom recognizers remain part of the existing DLP engine.

## 5. Request processing

1. Client sends a prompt and session ID to `/chat`.
2. Proxy validates the request.
3. `DLPInterceptor.redact()` detects and replaces sensitive values.
4. Proxy forwards the masked prompt to the mock LLM.
5. Mock LLM logs the exact prompt it receives.
6. Mock LLM returns an echo completion.
7. `DLPInterceptor.unmask()` restores original values.
8. Proxy returns the restored completion to the client.
9. Client can end the session using `/end-session`.

## 6. Security verification

A negative security test was performed by temporarily bypassing
the masking step in the proxy's upstream forwarding logic.

The standalone security verification script detected that the
original email, phone number, and credit-card values reached
the mock LLM.

The secure implementation was subsequently restored and
retested successfully.

This confirms that the verification script can detect a
failure in the DLP enforcement path.

The mock LLM is not itself a security boundary. Requests must
pass through the DLP proxy for this protection to apply.

## 7. Test coverage

Test file: `tests/test_day7_integration.py`

The 10 integration tests cover:

- Mock proxy health.
- Mock LLM health.
- Email masking and restoration.
- Phone masking and restoration.
- Credit-card masking and restoration.
- Verification that only masked values reach the upstream service.
- Missing prompt validation.
- Missing session ID validation.
- Invalid JSON validation.
- Session cleanup.

Run with both mock servers running:

```bash
python -m pytest -v tests/test_day7_integration.py
```

**Day 7 integration result: 10 passed.**

The complete project suite was validated in separate groups: 115 tests passed in total.

## 8. Dependencies

Day 7 adds the following dependencies:

- Flask 3.0.3
- Requests 2.32.3

Both are recorded in `requirements.txt`.

## 9. Limitations

This is a local development and integration test environment.

It does not yet provide:

- Integration with the actual M1 proxy.
- Integration with a real LLM provider.
- Authentication or authorization for proxy clients.
- Session ownership enforcement.
- Production-grade network security.
- Production deployment or scalability guarantees.

The client currently supplies the session ID. Production integration must enforce authenticated session ownership and reliable cleanup.

## 10. Next steps

Before production use:

1. Integrate the DLP interceptor with the actual M1 proxy.
2. Ensure all LLM traffic passes through the DLP enforcement layer.
3. Implement authenticated session management.
4. Add appropriate error handling, logging, and security controls.
5. Run integration tests against the actual upstream environment.

## 11. M1 Replacement and Integration Plan

The local mock HTTP pipeline is a development validation environment. The following steps are required when replacing it with the actual M1 proxy integration.

1. Identify the actual M1 request and response interfaces.
2. Replace the mock LLM HTTP forwarding endpoint with the approved M1 integration interface.
3. Preserve the `DLPInterceptor.redact()` operation before forwarding prompts.
4. Preserve the `DLPInterceptor.unmask()` operation before returning responses to clients.
5. Implement authenticated session identification and session ownership enforcement.
6. Ensure all LLM traffic passes through the DLP enforcement layer.
7. Add integration tests against the actual M1 environment.
8. Verify that failures, timeouts, and session cleanup cannot expose original sensitive values.

The mock implementation must remain available for isolated development and regression testing.

## 12. Security Perspectives

### 12.1 Attacker Perspective

Potential security tests include:

- Attempt to send unmasked PII through the proxy.
- Submit malformed JSON and incomplete requests.
- Attempt to reuse another session's identifier.
- Test whether placeholders from one session can be resolved in another session.
- Attempt to bypass the DLP enforcement layer.
- Verify that upstream requests never contain original sensitive values.

These are recommended security tests. They do not imply that every listed attack scenario has already been implemented or tested.

### 12.2 SOC Perspective

Security Operations Center monitoring should include:

- Proxy request failures and upstream communication errors.
- Unexpected forwarding of unmasked sensitive information.
- Repeated malformed requests and suspicious session activity.
- Session cleanup failures.
- Security events recorded without unnecessarily exposing original PII.

The current mock implementation provides upstream prompt logging for development verification. It is not a complete SOC monitoring solution.

### 12.3 GRC Perspective

Governance, Risk, and Compliance considerations include:

- Documenting the sensitive-data categories detected by the DLP engine.
- Maintaining test evidence for masking, restoration, and negative security tests.
- Defining access controls and retention policies for logs and session mappings.
- Recording known limitations and unresolved production risks.
- Obtaining appropriate security review and approval before production deployment.

## 13. Troubleshooting

| Problem | Recommended action |
|---|---|
| Port 6001 or 6002 already occupied | Identify and stop the existing mock service before restarting the launcher |
| Flask module missing | Activate `.venv` and install dependencies from `requirements.txt` |
| Proxy health check fails | Check proxy startup output and logs |
| Mock LLM health check fails | Check whether port 6002 is available and inspect the LLM service |
| Integration tests fail | Run the failing test with `pytest -v` and inspect the traceback |
| Sensitive values reach upstream | Stop testing, inspect the proxy forwarding path, and rerun the security verification |
| Original values are not restored | Inspect session mappings and the interceptor's unmasking flow |

## 14. Git and Pull Request Checklist

Before submitting the Day 7 implementation for review:

- [ ] Review all modified and untracked files.
- [ ] Confirm that generated logs and temporary files are excluded.
- [ ] Confirm that no secrets or real sensitive personal information are included.
- [ ] Run the Day 7 integration tests.
- [ ] Run the standalone security verification script.
- [ ] Review the negative security test evidence.
- [ ] Review the documentation and implementation diff.
- [ ] Confirm that the intended target branch and repository are correct.
- [ ] Obtain repository write access or prepare a pull request from an authorized fork.
- [ ] Obtain explicit approval before committing or pushing.

## 15. Completion Summary

The Day 7 local mock integration provides a testable HTTP boundary around the existing DLP interceptor.

Validated capabilities:

- HTTP prompt processing through a mock proxy.
- Email, phone, and credit-card masking.
- Forwarding masked prompts to the mock LLM.
- Restoration of original values in the client response.
- Detection of an intentionally introduced masking bypass.
- Session cleanup through the proxy endpoint.
- Automated integration and standalone security verification.

The implementation remains a local mock integration. Actual M1 integration, production authentication, authorization, deployment, and operational monitoring remain future work.

## 16. Milestone conclusion

The local mock HTTP integration demonstrates the core DLP workflow: sensitive values are masked before forwarding to the upstream mock service and restored before the response reaches the client.

**Day 7 local mock integration: implementation and validation complete.**
