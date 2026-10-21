# Threat Model — OWASP LLM Top 10 (2025) mapping

| ID | Threat | Control in this project | Splunk detection |
|---|---|---|---|
| LLM01 | Prompt Injection | Injection scoring on input, block >= 0.80, signatures lookup | Prompt Injection Attempt; Possible Jailbreak Success |
| LLM02 | Sensitive Information Disclosure | PII/secret scan + redaction on input and output | PII Exfiltration |
| LLM05 | Improper Output Handling | Output is treated as untrusted; blocked/redacted content never reaches caller as-is; callers must encode output for their context | Jailbreak Success (sensitive output after flagged input) |
| LLM06 | Excessive Agency | Proxy exposes chat only — no tools/agency in MVP; per-user token limits in policy roadmap; least-privilege upstream key | Token Cost Anomaly (abuse signal) |
| LLM07 | System Prompt Leakage | Leakage similarity check on output, block >= 0.85; system prompt never logged | System Prompt Probing; Jailbreak Success |
| LLM10 | Unbounded Consumption | Token estimation per request, per-user anomaly detection; rate limiting is the V2 proxy control | Token Cost Anomaly |

Out of scope for MVP: vector/embedding weaknesses (LLM08, no RAG yet),
supply-chain (LLM03) and poisoning (LLM04) — tracked in blueprint roadmap.
No control guarantees 100% prevention; the design goal is block-by-default
for high-confidence cases plus a complete, PII-free audit trail.
