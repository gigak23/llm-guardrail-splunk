"""Prompt-injection / jailbreak scoring: signature + heuristic, 0.0-1.0."""
from __future__ import annotations

SIGNATURES: list[tuple[str, float]] = [
    ("ignore previous instructions", 0.90),
    ("ignore all previous", 0.90),
    ("ignore your instructions", 0.85),
    ("disregard previous instructions", 0.90),
    ("reveal your system prompt", 0.90),
    ("reveal the system prompt", 0.90),
    ("show me your system prompt", 0.85),
    ("what is your system prompt", 0.75),
    ("print your instructions", 0.80),
    ("you are now dan", 0.90),
    ("do anything now", 0.70),
    ("jailbreak", 0.70),
    ("developer mode", 0.65),
    ("bypass your restrictions", 0.85),
    ("bypass safety", 0.85),
    ("pretend you have no restrictions", 0.85),
    ("act as an unrestricted", 0.85),
    ("override your instructions", 0.85),
    ("system prompt", 0.45),
]


def score_injection(text: str) -> tuple[float, list[str]]:
    low = (text or "").lower()
    hits = [sig for sig, _ in SIGNATURES if sig in low]
    if not hits:
        return 0.0, []
    # Highest signature dominates; extra hits add a small bump, capped at 1.
    score = max(w for sig, w in SIGNATURES if sig in low)
    score = min(1.0, score + 0.05 * (len(hits) - 1))
    return round(score, 3), hits
