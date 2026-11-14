
# DLPInterceptor Integration Guide

## 1. Overview

`DLPInterceptor` is the public entry point for integrating LLM-Guard DLP into an application.

It combines three internal components:

- `DLPEngine`: Detects sensitive information.
- `PlaceholderManager`: Assigns semantic placeholders.
- `Vault`: Stores original values for reversible restoration.

The interceptor allows applications to mask sensitive information before sending prompts to an LLM and restore original values in the returned response.

## 2. Importing the Interceptor

```python
from dlp import DLPInterceptor
```

Initialize the interceptor:

```python
dlp = DLPInterceptor()
```

## 3. Creating a Session

Each conversation should have a unique, securely generated session ID.

Example:

```python
import secrets

session_id = secrets.token_urlsafe(32)
```

The same session ID must be used for masking and restoring information belonging to that conversation.

## 4. Masking Sensitive Information

Use `redact()` to detect and mask sensitive information.

```python
masked_prompt, entities = dlp.redact(
    "Contact john@example.com",
    session_id
)

print(masked_prompt)
```

Expected output:

```text
Contact <EMAIL_1>
```

The returned metadata contains detection information such as:

- Entity type
- Original text offsets
- Detection confidence
- Assigned placeholder

Original sensitive values are not included in the returned metadata.

## 5. Sending Prompts to an LLM

Only send the masked prompt to the external LLM.

```python
masked_prompt, entities = dlp.redact(
    user_prompt,
    session_id
)

# Send masked_prompt to your LLM provider.
```

Never send the original user prompt or original sensitive values to the LLM.

## 6. Restoring Sensitive Information

After receiving the LLM response, call `unmask()`.

```python
final_response = dlp.unmask(
    llm_response,
    session_id
)
```

Example:

LLM response:

```text
Please contact <EMAIL_1>.
```

Restored response:

```text
Please contact john@example.com.
```

Only placeholders that exist in the current session's vault are restored.

## 7. Session-Level Placeholder Management

Placeholder numbering persists across multiple calls within a session.

Example:

```python
first, _ = dlp.redact(
    "Contact john@example.com",
    session_id
)

second, _ = dlp.redact(
    "Contact jane@example.com",
    session_id
)
```

Expected:

```text
First: Contact <EMAIL_1>
Second: Contact <EMAIL_2>
```

Repeated values reuse their existing placeholders within the session.

Different sessions maintain independent mappings.

## 8. Ending a Session

When a conversation ends, clear its mappings:

```python
dlp.end_session(session_id)
```

Check the number of active vault sessions:

```python
print(dlp.active_session_count())
```

The vault uses in-memory storage. Ending a session removes its stored mappings and placeholder manager.

Applications should ensure cleanup occurs even when an LLM request fails, using `try/finally` where appropriate.

## 9. Complete Integration Example

```python
import secrets

from dlp import DLPInterceptor


def process_prompt(user_prompt, llm_client):
    dlp = DLPInterceptor()
    session_id = secrets.token_urlsafe(32)

    try:
        # Step 1: Mask sensitive information.
        masked_prompt, entities = dlp.redact(
            user_prompt,
            session_id
        )

        # Step 2: Send only the masked prompt upstream.
        llm_response = llm_client.generate(masked_prompt)

        # Step 3: Restore original values.
        final_response = dlp.unmask(
            llm_response,
            session_id
        )

        return final_response

    finally:
        # Step 4: Remove session mappings.
        dlp.end_session(session_id)
```

`llm_client.generate()` is a placeholder for the application's actual LLM integration.

For multi-turn conversations, reuse the same interceptor instance and session ID for the lifetime of the conversation. Do not create a new interceptor for every message.

## 10. Security Considerations

- Use unpredictable session IDs.
- Keep session IDs private and associate them with authenticated application sessions.
- Never send original sensitive values to the LLM.
- Do not log original prompts or sensitive vault mappings.
- Do not expose internal vault mappings to external clients.
- Always clean up completed sessions.
- Use HTTPS when communicating with external LLM providers.
- The current vault is in-memory and does not provide persistence or automatic expiration.
- Session isolation does not replace application-level authentication and authorization.

## 11. Current Limitations

- The vault is process-local and in-memory.
- Session mappings are lost when the process restarts.
- There is no automatic session expiration.
- The implementation does not authenticate session IDs independently.
- Placeholder restoration only works when the LLM response preserves the exact placeholder syntax.
- Production deployments require additional lifecycle, access-control, and operational security controls.

## 12. Testing

Run the complete test suite:

```bash
python -m pytest -v
```

Compile the project:

```bash
python -m compileall -q dlp tests examples
```

Run the integration example:

```bash
python examples/usage_example.py
```
