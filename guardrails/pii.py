"""PII / secret detection and redaction.

Regex is the deterministic core (and what tests exercise). Microsoft
Presidio is an optional extra: if installed it is reported via
PRESIDIO_AVAILABLE, but the regex path is used as the graceful fallback
and never requires it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

try:  # optional extra
    import presidio_analyzer  # noqa: F401

    PRESIDIO_AVAILABLE = True
except Exception:
    PRESIDIO_AVAILABLE = False


@dataclass
class Entity:
    type: str
    start: int
    end: int
    text: str


PATTERNS: list[tuple[str, re.Pattern]] = [
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("API_KEY", re.compile(r"\bsk-[A-Za-z0-9_-]{10,}\b")),
    ("AWS_ACCESS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GITHUB_TOKEN", re.compile(r"\bghp_[A-Za-z0-9]{20,}\b")),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("CREDIT_CARD", re.compile(r"\b(?:\d[ -]?){13,16}\b")),
    ("PHONE", re.compile(r"\b(?:\+1[ -]?)?\(?\d{3}\)?[ -]\d{3}-\d{4}\b")),
]


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
        alt = not alt
    return total % 10 == 0


def find_pii(text: str) -> list[Entity]:
    entities: list[Entity] = []
    claimed: list[tuple[int, int]] = []
    for etype, pattern in PATTERNS:
        for m in pattern.finditer(text or ""):
            if any(s < m.end() and m.start() < e for s, e in claimed):
                continue
            if etype == "CREDIT_CARD":
                digits = re.sub(r"\D", "", m.group(0))
                if not (13 <= len(digits) <= 16 and _luhn_ok(digits)):
                    continue
            if etype == "PHONE" and re.fullmatch(r"\d{3}-\d{2}-\d{4}", m.group(0)):
                continue  # SSN-shaped span already handled / not a phone
            entities.append(Entity(etype, m.start(), m.end(), m.group(0)))
            claimed.append((m.start(), m.end()))
    return sorted(entities, key=lambda e: e.start)


def redact_pii(text: str) -> tuple[str, list[Entity]]:
    entities = find_pii(text)
    out, last = [], 0
    for e in entities:
        out.append(text[last : e.start])
        out.append(f"[REDACTED_{e.type}]")
        last = e.end
    out.append(text[last:])
    return "".join(out), entities
