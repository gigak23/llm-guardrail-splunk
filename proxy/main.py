"""LLM Guardrail proxy: OpenAI-compatible chat completions endpoint.

Flow: input guardrails -> mock or upstream LLM -> output guardrails ->
Splunk HEC / stdout telemetry. Run: uvicorn proxy.main:app --port 8000
"""
from __future__ import annotations

import os
import sys
import time
import uuid
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from guardrails.policy import evaluate_input, evaluate_output, load_policy  # noqa: E402
from guardrails.redaction import estimate_tokens, hash_text  # noqa: E402
from splunk.splunk_hec import SplunkHECClient, build_event  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
POLICY_PATH = os.getenv("POLICY_PATH", str(ROOT / "policies" / "default.yaml"))
MOCK_LLM = os.getenv("MOCK_LLM", "true").lower() == "true"
MODEL_NAME = os.getenv("MODEL_NAME", "mock-llm")
SYSTEM_PROMPT = os.getenv("SYSTEM_PROMPT", "You are a helpful assistant for internal use only.")

policy = load_policy(POLICY_PATH)
if not policy.system_prompt:
    policy.system_prompt = SYSTEM_PROMPT
hec = SplunkHECClient()
app = FastAPI(title="LLM Guardrail Proxy", version="0.1.0")

SAFE_BLOCK = "Request blocked by the LLM guardrail policy."
SAFE_LEAK = "Response blocked by the LLM guardrail policy."


def mock_llm(prompt: str, model: str) -> str:
    return f"Mock LLM response ({model}): I can help with that request. [prompt_chars={len(prompt)}]"


async def call_llm(prompt: str, model: str) -> str:
    if MOCK_LLM:
        return mock_llm(prompt, model)
    base = os.getenv("UPSTREAM_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    key = os.getenv("UPSTREAM_API_KEY", "")
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            f"{base}/chat/completions",
            headers={"Authorization": f"Bearer {key}"},
            json={"model": model, "messages": [{"role": "user", "content": prompt}]},
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]


@app.get("/health")
def health():
    return {"status": "ok", "mock_llm": MOCK_LLM, "model": MODEL_NAME,
            "splunk_hec_configured": hec.configured}


@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    started = time.time()
    body = await request.json()
    messages = body.get("messages") or []
    model = body.get("model") or MODEL_NAME
    user_id = body.get("user") or "anonymous"
    app_id = body.get("app_id") or "demo_chat"
    prompt = "\n".join(m.get("content", "") for m in messages if m.get("role") == "user")
    trace_id = uuid.uuid4().hex

    in_decision = evaluate_input(prompt, policy)
    if in_decision.decision == "BLOCK":
        content, finish = SAFE_BLOCK, "content_filter"
        out_pii, out_leak = [], 0.0
        final_decision = "BLOCK"
    else:
        raw = await call_llm(in_decision.text, model)
        out = evaluate_output(raw, policy)
        out_pii, out_leak = out.pii_types, out.leakage_score
        if out.decision == "BLOCK":
            content, finish, final_decision = SAFE_LEAK, "content_filter", "BLOCK"
        elif out.decision == "REDACT":
            content, finish, final_decision = out.text, "stop", "REDACT"
        else:
            content, finish = out.text, "stop"
            final_decision = in_decision.decision  # ALLOW or REDACT (input)

    latency_ms = int((time.time() - started) * 1000)
    event = build_event(
        trace_id=trace_id, user_id=user_id, app_id=app_id, model=model,
        prompt_hash=hash_text(prompt), prompt_len=len(prompt),
        tokens_in=estimate_tokens(prompt), tokens_out=estimate_tokens(content),
        latency_ms=latency_ms, guardrail_latency_ms=latency_ms,
        input_scores={"injection": in_decision.injection_score,
                      "pii_count": len(in_decision.pii_types),
                      "pii_types": in_decision.pii_types},
        output_scores={"pii_count": len(out_pii), "leakage": out_leak},
        decision=final_decision, policy_id=in_decision.policy_id,
        reason=in_decision.reason)
    hec.send_event(event)

    return JSONResponse({
        "id": f"chatcmpl-{trace_id}", "object": "chat.completion",
        "created": int(time.time()), "model": model,
        "choices": [{"index": 0,
                     "message": {"role": "assistant", "content": content},
                     "finish_reason": finish}],
        "usage": {"prompt_tokens": event["tokens_in"],
                  "completion_tokens": event["tokens_out"],
                  "total_tokens": event["tokens_in"] + event["tokens_out"]},
        "guardrail": {"decision": final_decision, "policy_id": in_decision.policy_id,
                      "input_scores": event["input_scores"],
                      "output_scores": event["output_scores"], "trace_id": trace_id},
    })
