"""Splunk HEC client. Unconfigured = emit the event JSON to stdout.

Event schema (never raw prompts / PII):
trace_id, user_id, app_id, model, prompt_hash, prompt_len, tokens_in,
tokens_out, latency_ms, guardrail_latency_ms, cost_usd (est.),
input_scores{injection,pii_count}, output_scores{pii_count,leakage},
decision, policy_id, reason, sourcetype=llm:guardrail:decision
"""
from __future__ import annotations

import json
import os
import sys
import urllib.request


def build_event(**fields) -> dict:
    base = {
        "trace_id": "", "user_id": "anonymous", "app_id": "demo_chat",
        "model": "mock-llm", "prompt_hash": "", "prompt_len": 0,
        "tokens_in": 0, "tokens_out": 0, "latency_ms": 0,
        "guardrail_latency_ms": 0, "cost_usd": 0.0,
        "input_scores": {"injection": 0.0, "pii_count": 0},
        "output_scores": {"pii_count": 0, "leakage": 0.0},
        "decision": "ALLOW", "policy_id": "allow", "reason": "",
    }
    base.update(fields)
    return base


class SplunkHECClient:
    def __init__(self, url: str | None = None, token: str | None = None,
                 index: str | None = None):
        self.url = url if url is not None else os.getenv("SPLUNK_HEC_URL", "")
        self.token = token if token is not None else os.getenv("SPLUNK_HEC_TOKEN", "")
        self.index = index or os.getenv("SPLUNK_INDEX", "llm_events")

    @property
    def configured(self) -> bool:
        return bool(self.url and self.token)

    def send_event(self, event: dict) -> bool:
        payload = {"index": self.index, "sourcetype": "llm:guardrail:decision",
                   "event": event}
        if not self.configured:
            print(json.dumps(payload), file=sys.stdout, flush=True)
            return False
        req = urllib.request.Request(
            self.url, data=json.dumps(payload).encode(),
            headers={"Authorization": f"Splunk {self.token}",
                     "Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310
                return 200 <= resp.status < 300
        except Exception:
            print(json.dumps(payload), file=sys.stdout, flush=True)
            return False
