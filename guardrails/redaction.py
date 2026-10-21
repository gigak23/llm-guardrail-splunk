"""Hashing and redaction helpers. Raw PII is never logged."""
from __future__ import annotations

import hashlib


def hash_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4) if text else 0
