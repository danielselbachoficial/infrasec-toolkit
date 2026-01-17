from __future__ import annotations

import re

IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HOST_REGEX = re.compile(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")


def redact_text(value: str) -> str:
    value = IP_REGEX.sub("[redacted-ip]", value)
    value = HOST_REGEX.sub("[redacted-host]", value)
    return value


def redact_mapping(mapping: dict) -> dict:
    redacted = {}
    for key, val in mapping.items():
        if isinstance(val, str):
            redacted[key] = redact_text(val)
        elif isinstance(val, dict):
            redacted[key] = redact_mapping(val)
        elif isinstance(val, list):
            redacted[key] = [redact_text(item) if isinstance(item, str) else item for item in val]
        else:
            redacted[key] = val
    return redacted
