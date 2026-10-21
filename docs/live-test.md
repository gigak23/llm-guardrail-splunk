# Splunk integration test — 2026-10-21

## Test level actually achieved: mock-HEC validation (NOT live Splunk)

A live Docker Splunk test was attempted first and was **not possible in this
environment**:

- `docker --version` → `docker: command not found` (no Docker installed)
- Host resources: 7.7 GiB RAM total with ~688 MiB available, 2 CPUs — below
  what the `splunk/splunk` image needs even if Docker were present

So the fallback validation below was run instead. **No claim is made that
events were ingested into, or searched in, a real Splunk instance.**
Splunk version: n/a (not run).

## Static validation (passed)

- `docker-compose.yml` and `policies/default.yaml` parse as YAML.
- `splunk/dashboards/soc_appsec.json` and `executive.json` parse as JSON.
  Note: these are simplified dashboard definitions (title/viz/query), not
  full Dashboard Studio schemas — they document the intended panels and
  queries but are not import-complete Dashboard Studio exports.
- All five `splunk/app/default/*.conf` files parse as INI-style conf;
  every stanza/field referenced by the saved searches exists in the HEC
  event schema (see below). One missing lookup file was found and fixed
  (see "Bugs fixed").

## Method (mock HEC)

1. A local mock HEC server (Python `http.server`) mimicked
   `POST /services/collector/event`: it required
   `Authorization: Splunk <token>` (400 on a bad token, like real HEC),
   and returned `{"text":"Success","code":0}`.
2. The real proxy was started (uvicorn, `MOCK_LLM=true`) with
   `SPLUNK_HEC_URL=http://127.0.0.1:18088/services/collector/event` and a
   throwaway local test token (not committed anywhere).
3. The 3 demo requests from `examples/demo_requests.sh` were sent.
4. 108 further synthetic events were sent through the real
   `SplunkHECClient` to exercise the remaining detections.
5. Each saved search in `savedsearches.conf` was translated to its core
   field conditions and evaluated in Python over the emitted events —
   the same `index` / `sourcetype` / field names the SPL uses:
   `index=llm_events`, `sourcetype=llm:guardrail:decision`,
   `decision`, `policy_id`, `prompt_hash`, `tokens_in`, `tokens_out`,
   `input_scores.injection`, `input_scores.pii_count`,
   `output_scores.pii_count`, `output_scores.leakage`.
   SPL itself was not executed by a Splunk search head.

## Results — demo requests (3 events received by mock HEC)

| Request | Decision | Key fields |
|---|---|---|
| Normal ("Explain RBAC…", alice) | `ALLOW` | injection=0.0, input PII=0, policy=`allow` |
| PII (fake SSN + email, alice) | `REDACT` | injection=0.0, input PII=2 (SSN, EMAIL), policy=`pii_input_redact` |
| Injection ("Ignore previous instructions…", mallory) | `BLOCK` | injection=1.0, policy=`injection_high` |

- All 3 HEC payloads had exactly the HEC envelope keys
  `{index, sourcetype, event}` with `index=llm_events` and
  `sourcetype=llm:guardrail:decision`.
- Raw SSN `123-45-6789` and raw email were **absent** from all HEC
  payloads (events carry counts/types and a SHA-256 prompt hash only).

## Results — detections

Demo-only corpus (3 events):

| Saved search | Result |
|---|---|
| Prompt Injection Attempt (`injection>0.8`) | **1 event** (mallory) ✅ |
| Possible Jailbreak Success | 0 (injection was blocked, not allowed) |
| PII Exfiltration (`sum output pii >3` per user) | 0 (demo PII was input-side and redacted; output PII=0) |
| Token Cost Anomaly (`tokens > avg+3σ`) | 0 (only 3 events) |
| System Prompt Probing (`≥5` distinct hashes, 5m) | 0 (only 1 probing prompt) |

Full corpus (111 events: 3 demo + 108 synthetic, all accepted by mock HEC):

| Saved search | Result |
|---|---|
| Prompt Injection Attempt | **6 events** ✅ |
| Possible Jailbreak Success | **1 event** (synthetic ALLOW, injection 0.75, leakage 0.9) ✅ |
| PII Exfiltration | **1 user** (`eve`, output PII sum = 4) ✅ |
| System Prompt Probing | **1 user** (`prober`, 5 distinct prompt hashes) ✅ |
| Token Cost Anomaly | **1 event** (1000-token request vs 100 baseline ~20-token requests for the same user) ✅ |

All five detection conditions therefore fire on data shaped exactly like
what the proxy emits, and correctly do not fire on the benign/small demo
set beyond the injection case.

## Bugs fixed in this change

1. **HEC over HTTPS would have failed against Docker Splunk.**
   `SplunkHECClient` used `urllib` with default certificate verification;
   Splunk's default HEC cert is self-signed, so every event would have
   silently fallen back to stdout in the docker-compose setup.
   Fix: `SPLUNK_HEC_VERIFY_SSL` (default `true`; set `false` only for
   local/Docker), wired into compose for the proxy service.
   Verified locally against a self-signed TLS mock HEC: default verify →
   send fails; `verify_ssl=False` and the env-var path → send succeeds.
2. **Hardcoded Splunk admin password in `docker-compose.yml`**
   (`SPLUNK_PASSWORD` was a literal default committed to git — a bad look
   in a security project). Fix: compose now requires
   `${SPLUNK_PASSWORD:?…}` from `.env`/shell and takes the HEC token from
   the environment; `.env.example` documents both. Also made the proxy's
   `env_file: .env` non-required so compose doesn't fail before `.env`
   is created.
3. **Missing lookup file.** `transforms.conf` referenced
   `llm_users_risk.csv`, which did not exist — that lookup would error in
   Splunk. Fix: added the file (header `user_id,risk_score,watchlist`).
   Also added `splunk/app/lookups/` copies of both lookups, because
   lookups previously lived only in `splunk/lookups/`, outside the app
   folder — copying just `splunk/app` into
   `$SPLUNK_HOME/etc/apps/llm_guardrail` (the documented install step)
   would have installed transforms with no lookup files at all.

## Regression tests

`pytest -q` → **15 passed** (unchanged suite, plus `compileall` clean).

## Limitations / not tested

- No real Splunk ingestion, search head, index creation
  (`llm_events`/`llm_metrics`), HEC token provisioning, or app install
  was exercised — that still requires a host with Docker (or a Splunk
  install) and several GB of free RAM.
- SPL syntax was checked by field/condition equivalence, not by a Splunk
  parser/`btool`; a real `btool check` and saved-search run remain TODO.
- Dashboards are panel/query definitions, not validated Dashboard Studio
  imports (see above).
- Splunk Enterprise Security / RBA risk rules were not tested (no ES).
- GitHub still lists `master` as the default branch; the code lives on
  `main` — set `main` as default in repo Settings → Branches.
