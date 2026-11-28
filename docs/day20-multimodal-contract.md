# Day 20 — Multimodal Input Contract

## 1. Overview

The multimodal handler extends the existing DLP pipeline to support requests containing ordinary text and attachments with previously extracted text.

It ensures that sensitive information in both the main request and attachment content is passed through the existing `DLPInterceptor`.

The handler uses one session ID for all content, allowing the Redis-backed vault to reuse placeholders across different input sections.

## 2. Supported Input Structure

The handler accepts a Python dictionary with the following structure:

```python
{
    "text": "Please review this document.",
    "attachments": [
        {
            "filename": "report.pdf",
            "extracted_text": "Contact alice@example.com",
            "mime_type": "application/pdf",
            "size_bytes": 2048
        }
    ]
}
```

### Top-level fields

| Field | Required | Type | Description |
|---|---|---|---|
| text | Yes | string | Main request text |
| attachments | No | list | Attachment metadata and extracted text |

Unexpected top-level fields are rejected.

### Attachment fields

| Field | Required | Type | Description |
|---|---|---|---|
| filename | Yes | string | Original attachment filename |
| extracted_text | Yes | string | Previously extracted attachment content |
| mime_type | No | string | Attachment MIME type |
| size_bytes | No | non-negative integer | Attachment size |

Unexpected attachment fields are rejected.

## 3. Processing Workflow

1. Validate the top-level input.
2. Validate every attachment and its metadata.
3. Convert the input into a `MultiModalInput` representation.
4. Send the main text to `DLPInterceptor.redact()`.
5. Send each attachment's extracted text to `DLPInterceptor.redact()` separately.
6. Use the same session ID for every redaction operation.
7. Aggregate detected entity metadata.
8. Return masked content, preserved metadata, total entity count, and sorted entity types.

## 4. Output Structure

Example:

```python
{
    "masked_text": "Please contact <EMAIL_1>.",
    "attachments": [
        {
            "filename": "report.pdf",
            "mime_type": "application/pdf",
            "size_bytes": 2048,
            "masked_text": "Contact <EMAIL_2>"
        }
    ],
    "total_entities_found": 2,
    "entity_types_found": ["EMAIL_ADDRESS"]
}
```

The placeholder values are illustrative. Actual placeholder allocation is controlled by the session vault.

The original `extracted_text` field is never included in the returned attachment objects.

## 5. Metadata Security Boundary

The following fields are treated as metadata:

- filename
- mime_type
- size_bytes

These fields are preserved but are not scanned by the DLP engine.

Only the main `text` field and attachment `extracted_text` fields are scanned.

This is an explicit design boundary. Metadata may contain sensitive information, so upstream components and callers must not treat these fields as automatically sanitized.

## 6. Placeholder and Session Behavior

All content is processed using the same session ID.

The Redis-backed vault provides shared placeholder allocation across workers. Repeated sensitive values can therefore reuse their existing placeholders within the session, subject to the vault's entity matching rules.

The handler does not independently allocate or manage placeholders.

## 7. Validation and Error Handling

Invalid inputs raise `MultiModalInputError`, including:

- Input is not a dictionary.
- Required main text is missing.
- Unexpected top-level fields are supplied.
- Main text is not a string.
- Attachments are not supplied as a list.
- An attachment is not a dictionary.
- Required attachment fields are missing.
- Attachment filename or extracted text is not a string.
- Unsupported attachment fields are supplied.
- MIME type is not a string.
- Attachment size is negative or not an integer.

## 8. Out-of-Scope Functionality

This component does not perform:

- PDF parsing
- DOCX parsing
- Image processing
- Optical Character Recognition (OCR)
- Audio transcription
- Video transcription
- File uploads or storage

An upstream extraction component must provide attachment content as a plain string in `extracted_text`.

## 9. Security Considerations

- All content fields are processed through the existing DLP interceptor.
- The original extracted attachment text is excluded from output.
- Placeholder allocation remains controlled by the Redis-backed vault.
- Metadata is preserved without scanning and must be handled accordingly
- The handler does not weaken existing role-based masking behavior.
- Session lifecycle and cleanup remain the responsibility of the existing interceptor and vault infrastructure.
