# Day 19: Structured JSON Integrity Findings

## 1. Objective

Verify that placeholders can be safely restored inside structured JSON responses without corrupting JSON syntax or changing the intended data.

The tests focus on nested JSON objects, arrays, unknown placeholders, and original values containing special characters such as quotes, backslashes, and newlines.

## 2. Problem Identified

The existing `unmask_text()` method performs direct string substitution.

This is suitable for ordinary text, but it can produce invalid JSON when a restored value contains JSON-special characters.

For example, restoring a value containing quotation marks directly into a JSON string can introduce unescaped quotes and cause `json.loads()` to raise a `JSONDecodeError`.

The plain-text method remains unchanged. It should not be used to restore values inside structured JSON documents.

## 3. Implementation

### JSON-aware restoration

The following methods were implemented:

- `Vault.unmask_json()`
- `RedisVault.unmask_json()`
- `DLPInterceptor.unmask_json()`

The JSON-aware restoration process:

1. Parses the masked response as JSON.
2. Retrieves the placeholder mapping for the requested session.
3. Recursively restores placeholders in JSON string values, including nested objects and arrays.
4. Serializes the restored data back into valid JSON.

This allows quotation marks, backslashes, and newline characters to be escaped correctly during serialization.

Unknown placeholders are preserved.

Non-standard JSON constants such as `NaN` and `Infinity` are rejected.

### Streaming support

`StreamUnmasker` now supports `json_mode=True`.

In this mode, incoming chunks are buffered until `flush()` is called. The complete JSON document is then restored through the vault's `unmask_json()` method.

Buffering the complete document avoids attempting to parse incomplete JSON fragments.

## 4. Test Coverage

The Day 19 test suite covers:

- Normal JSON objects.
- Nested JSON objects.
- JSON arrays.
- Placeholder restoration.
- Values containing quotation marks.
- Values containing backslashes.
- Values containing newline characters.
- Unknown placeholders.
- Invalid JSON input.
- Rejection of non-standard JSON constants.
- `DLPInterceptor` JSON restoration.
- Redis-backed JSON restoration.
- Streaming JSON restoration.
- The known limitation of plain `unmask_text()` when used with JSON-special characters.

## 5. API Usage Guidance

Use `unmask_text()` for ordinary text responses.

Use `unmask_json()` when restoring placeholders in a complete structured JSON document.

Use `StreamUnmasker(..., json_mode=True)` when receiving a structured JSON response in chunks.

Do not use direct text substitution as a substitute for JSON parsing and serialization.

## 6. Scope and Limitations

The JSON-aware methods restore placeholders in string values, including values inside nested objects and arrays. They do not restore placeholders in JSON object keys.

JSON streaming mode buffers the complete document until `flush()` is called. This preserves JSON integrity but does not provide incremental restoration of individual JSON fields.

## 7. Conclusion

The Day 19 implementation adds JSON-aware placeholder restoration for both in-memory and Redis-backed vaults, integrates the functionality with the interceptor, and supports complete JSON documents received through streaming.

The plain-text API remains available for ordinary text. Structured JSON responses should use the JSON-aware restoration path to preserve valid JSON syntax.

