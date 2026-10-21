"""Policy loading and allow / redact / block decisions."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .injection import score_injection
from .leakage import leakage_similarity
from .pii import find_pii, redact_pii


@dataclass
class Policy:
    injection_block_threshold: float = 0.80
    injection_warn_threshold: float = 0.50
    leakage_block_threshold: float = 0.85
    pii_input_action: str = "redact"   # redact | block | allow
    pii_output_action: str = "redact"
    system_prompt: str = ""
    extra: dict = field(default_factory=dict)


def load_policy(path: str | Path) -> Policy:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    known = {k: v for k, v in data.items() if k in Policy.__dataclass_fields__ and k != "extra"}
    return Policy(**known, extra={k: v for k, v in data.items() if k not in known})


@dataclass
class Decision:
    decision: str  # ALLOW | REDACT | BLOCK
    text: str
    policy_id: str
    reason: str
    injection_score: float = 0.0
    injection_hits: list = field(default_factory=list)
    pii_types: list = field(default_factory=list)
    leakage_score: float = 0.0


def evaluate_input(text: str, policy: Policy) -> Decision:
    score, hits = score_injection(text)
    entities = find_pii(text)
    types = sorted({e.type for e in entities})
    if score >= policy.injection_block_threshold:
        return Decision("BLOCK", text, "injection_high",
                        "LLM01 prompt injection score above block threshold",
                        score, hits, types)
    if entities and policy.pii_input_action == "block":
        return Decision("BLOCK", text, "pii_input_block",
                        "PII/secrets in prompt and policy is block", score, hits, types)
    if entities and policy.pii_input_action == "redact":
        redacted, _ = redact_pii(text)
        return Decision("REDACT", redacted, "pii_input_redact",
                        "PII/secrets redacted before reaching the model", score, hits, types)
    if score >= policy.injection_warn_threshold:
        return Decision("REDACT", text, "injection_warn",
                        "Suspicious prompt allowed with warning score logged", score, hits, types)
    return Decision("ALLOW", text, "allow", "No policy violation", score, hits, types)


def evaluate_output(text: str, policy: Policy) -> Decision:
    leak = leakage_similarity(text, policy.system_prompt)
    entities = find_pii(text)
    types = sorted({e.type for e in entities})
    if leak >= policy.leakage_block_threshold:
        return Decision("BLOCK", "", "system_prompt_leakage",
                        "LLM07 output too similar to system prompt", 0.0, [], types, leak)
    if entities and policy.pii_output_action == "redact":
        redacted, _ = redact_pii(text)
        return Decision("REDACT", redacted, "pii_output_redact",
                        "PII/secrets redacted from model output", 0.0, [], types, leak)
    if entities and policy.pii_output_action == "block":
        return Decision("BLOCK", "", "pii_output_block",
                        "PII/secrets in model output and policy is block", 0.0, [], types, leak)
    return Decision("ALLOW", text, "allow", "No policy violation", 0.0, [], types, leak)
