"""Generate deterministic synthetic PII payloads for the Day 13 audit."""

import argparse
import base64
import hashlib
import json
import string
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dlp.dlp_engine import DLPEngine
from dlp.verhoeff import validate as verhoeff_validate


DEFAULT_OUTPUT = ROOT / "data" / "pii_audit_payloads.json"
ENTITY_TYPES = [
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "US_SSN",
    "AADHAAR_CARD",
    "PAN_CARD",
    "AWS_ACCESS_KEY",
    "AWS_SECRET_KEY",
    "JWT_TOKEN",
]


def luhn_check_digit(number):
    digits = [int(char) for char in number]
    total = 0

    for index, digit in enumerate(reversed(digits)):
        if index % 2 == 0:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit

    return str((-total) % 10)


def make_aadhaar(index):
    base = f"{23456789000 + index:011d}"

    for digit in string.digits:
        candidate = base + digit
        if verhoeff_validate(candidate):
            return candidate

    raise RuntimeError("Unable to generate Aadhaar checksum fixture")


def make_jwt(index):
    header = "eyJhbGciOiJIUzI1NiJ9"
    payload_data = json.dumps(
        {"sub": f"audit-user-{index:04d}", "test": True},
        separators=(",", ":"),
    ).encode()

    payload = base64.urlsafe_b64encode(payload_data).decode().rstrip("=")
    signature = hashlib.sha256(
        f"day13-synthetic-signature-{index}".encode()
    ).hexdigest()[:32]

    return f"{header}.{payload}.{signature}"


def make_value(entity_type, index):
    if entity_type == "EMAIL_ADDRESS":
        return f"audit.user{index:04d}@example.com"

    if entity_type == "PHONE_NUMBER":
        # Fictional-use 555-0100 through 555-0199 range.
        return f"+1 202-555-{100 + index:04d}"

    if entity_type == "CREDIT_CARD":
        # Synthetic Luhn-valid test numbers using a common test prefix.
        base = f"411111{index:09d}"
        return base + luhn_check_digit(base)

    if entity_type == "US_SSN":
        return f"219-09-{1000 + index:04d}"

    if entity_type == "AADHAAR_CARD":
        return make_aadhaar(index)

    if entity_type == "PAN_CARD":
        return f"ABCDE{index:04d}F"

    if entity_type == "AWS_ACCESS_KEY":
        return f"AKIA{index:016X}"

    if entity_type == "AWS_SECRET_KEY":
        return hashlib.sha256(
            f"day13-synthetic-aws-secret-{index}".encode()
        ).hexdigest()[:40]

    if entity_type == "JWT_TOKEN":
        return make_jwt(index)

    raise ValueError(f"Unsupported entity type: {entity_type}")


def make_prompt(entity_type, value, audit_id):
    contexts = {
        "EMAIL_ADDRESS": f"Contact email address: {value}",
        "PHONE_NUMBER": f"Contact phone number: {value}",
        "CREDIT_CARD": f"Test credit card number: {value}",
        "US_SSN": f"Please verify the SSN {value}",
        "AADHAAR_CARD": f"Aadhaar number: {value}",
        "PAN_CARD": f"PAN number: {value}",
        "AWS_ACCESS_KEY": f"AWS access key: {value}",
        "AWS_SECRET_KEY": f"AWS secret access key: {value}",
        "JWT_TOKEN": f"Authorization JWT token: {value}",
    }

    return f"AUDIT_ID={audit_id}. {contexts[entity_type]}"


def generate(count):
    engine = DLPEngine()
    records = []

    # Distribute the requested total as evenly as possible.
    base_count, remainder = divmod(count, len(ENTITY_TYPES))
    index_by_type = Counter()

    for entity_index, entity_type in enumerate(ENTITY_TYPES):
        type_count = base_count + (1 if entity_index < remainder else 0)

        for _ in range(type_count):
            index = index_by_type[entity_type]
            index_by_type[entity_type] += 1

            value = make_value(entity_type, index)
            audit_id = f"DAY13-{len(records) + 1:04d}"
            prompt = make_prompt(entity_type, value, audit_id)

            masked, entities = engine.redact(prompt)
            detected_types = {
                entity["entity_type"] for entity in entities
            }

            if entity_type not in detected_types:
                raise RuntimeError(
                    f"{audit_id}: expected {entity_type}, "
                    f"detected {sorted(detected_types)}"
                )

            if value in masked:
                raise RuntimeError(
                    f"{audit_id}: raw synthetic value was not masked"
                )

            records.append({
                "audit_id": audit_id,
                "entity_type": entity_type,
                "raw_value": value,
                "prompt": prompt,
            })

    return records


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=500)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    if args.count < 1:
        parser.error("--count must be at least 1")

    records = generate(args.count)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(records, indent=2) + "\n",
        encoding="utf-8",
    )

    counts = Counter(record["entity_type"] for record in records)

    print(f"Generated: {len(records)} payloads")
    print(f"Output: {args.output}")
    print("\nEntity distribution:")

    for entity_type in ENTITY_TYPES:
        print(f"  {entity_type}: {counts[entity_type]}")

    print("\nGENERATION AND MASKING VALIDATION: PASS")


if __name__ == "__main__":
    main()
