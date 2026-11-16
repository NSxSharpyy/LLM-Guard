
import base64
import binascii
import re
from urllib.parse import unquote


def decode_base64(text: str) -> str:
    """Decode valid Base64 text. Return original text if decoding fails."""
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    try:
        decoded_bytes = base64.b64decode(text, validate=True)
        return decoded_bytes.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return text


def decode_url(text: str) -> str:
    """Decode URL-encoded text."""
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    return unquote(text)


def decode_hex(text: str) -> str:
    """Decode hexadecimal text. Return original text if decoding fails."""
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    try:
        decoded_bytes = bytes.fromhex(text)
        return decoded_bytes.decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return text


def normalize_leetspeak(text: str) -> str:
    """Normalize common leetspeak characters."""
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    translation_table = str.maketrans({
        "3": "e",
        "@": "a",
        "1": "i",
        "0": "o",
        "4": "a",
        "5": "s",
        "7": "t",
    })

    return text.translate(translation_table)


def generate_payload_variants(text: str) -> list[str]:
    """Generate original and normalized variants for security inspection."""
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    variants = {text}

    url_decoded = decode_url(text)
    variants.add(url_decoded)

    hex_decoded = decode_hex(text)
    variants.add(hex_decoded)

    base64_decoded = decode_base64(text)
    variants.add(base64_decoded)

    for variant in list(variants):
        variants.add(normalize_leetspeak(variant))

    return list(variants)
