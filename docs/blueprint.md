# Blueprint

## Goal
Prevent private information leaking through LLM apps in both directions,
block extraction attacks, and make every attempt detectable in Splunk.

## Components
1. **Guardrail proxy (FastAPI)** — OpenAI-compatible endpoint. Input checks,
   then LLM call (mock by default, any OpenAI-compatible upstream via env),
   then output checks.
2. **Guardrails** — PII/secrets (regex core, optional Presidio), injection
   scoring (signatures + heuristics, mirrored in a Splunk lookup), system
   prompt leakage (similarity), YAML policy: allow / redact / block.
3. **Splunk** — HEC JSON events (`llm_events`, sourcetype
   `llm:guardrail:decision`) with trace_id, user/app, model, prompt SHA-256
   hash (never raw PII), token estimates, latency, input/output scores,
   decision and policy_id. Data model stub `LLM_Guardrail`.
4. **Detections** (`splunk/app/default/savedsearches.conf`) — injection
   attempt, possible jailbreak success, PII exfiltration, token/cost
   anomaly, system-prompt probing. Feed ES Notables / RBA risk objects
   (user_id, app_id) in production.
5. **Dashboards** — SOC/AppSec and Executive/Model Ops (Dashboard Studio
   JSON in `splunk/dashboards/`).
6. **Response** — blocked requests return a safe completion with
   `finish_reason=content_filter`; alerts can disable a key/user and add
   them to a risk lookup the proxy policy references.

## Data flow
User -> proxy -> policy -> LLM -> policy -> user, with one HEC event per
request regardless of decision, so blocks are as visible as allows.

## Roadmap
V2: Llama Guard classifier, RAG indirect-injection checks, real cost
pricing per model. V3: multi-tenant policies, SOAR webhook blocklist,
red-team harness (promptfoo/garak) with block-rate metrics.
