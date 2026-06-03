# Plan 028: SIEM / Log Export (Workstream F)

> **Status:** draft for review. Grounded in `audit.py` (the structured event
> source), `http_client.ssrf_safe_urlopen` (delivery), and the env/secret config
> pattern (`config.read_secret`, `*_FILE` support). Implements Plan 023 §F.
> **Scope for 0.5.0: syslog + Splunk HEC. Windows Event Log writer is deferred
> to a fast-follow** (platform-specific dependency; see Scope).

## Goal

Make cert-watch's audit log (and optionally alerts) **consumable by a SIEM**, so
a regulated SMB can land cert-watch events in Splunk / Sentinel / QRadar /
Elastic next to everything else. The audit rows are already structured
(`ts, actor, action, target_type, target_id, detail, source_ip`); this plan adds
**sinks**, not new data.

## Scope (what ships in 0.5.0 vs. later)

- **In 0.5.0:**
  - **Syslog handler** (generic, RFC 5424) — `logging.handlers.SysLogHandler`,
    **stdlib, zero new dependency**. Serves *any* SIEM (QRadar, Sentinel via AMA,
    Splunk via UF/syslog) and is the Azure-native path (AMA → Log Analytics via a
    Data Collection Rule). This is the broadest-reach, lowest-risk sink — do it
    first.
  - **Splunk HEC exporter** — POST events as JSON to a Splunk HTTP Event
    Collector with a token, **through `ssrf_safe_urlopen`** (HEC endpoints are
    typically internal, so this honours `allow_private`/`allowed_subnets`, unlike
    the public-only adapters). Structurally the same "format → POST through safe
    opener" shape as Plan 022.
- **Deferred (fast-follow, its own plan):**
  - **Windows Event Log writer** — needs `pywin32` (platform-specific, heavy);
    AMA/agents already collect from syslog, so this is a convenience for the IIS
    deployment, not a blocker. Gate behind an optional `[windows]` extra when
    built.
  - Azure Monitor **Logs Ingestion API** direct exporter (Plan 023 already
    defers this).

> **Honest scoping note:** "F" reads as one workstream but is three sinks plus a
> delivery mechanism. Syslog is genuinely small (stdlib handler + config). HEC is
> moderate (formatting + auth + the async-delivery decision below). The Event Log
> writer is the part that drags in a platform dependency and test complexity —
> hence deferred. Shipping syslog+HEC delivers the actual "SIEM-consumable"
> promise for 0.5.0 without that tail.

## The delivery decision — the part that isn't trivial

`record_audit` (`audit.py:16`) is a **synchronous, best-effort** INSERT on the
request path. A SIEM sink must **not** turn every audited action into a blocking
network POST (HEC) — that couples request latency to SIEM availability and can
hang a mutation.

Design: a small **non-blocking sink layer** invoked after the audit row is
committed:

- Syslog via `SysLogHandler` is already async-friendly (local UDP/TCP, fast); a
  failed syslog write must be swallowed and logged, never raised — matching
  `record_audit`'s contract.
- HEC POST goes through a **bounded background queue + worker thread** (or a
  thread-pool fire-and-forget), so the request returns immediately. On queue
  full, drop-with-warning rather than block. The worker batches events where the
  HEC API allows (multiple events per POST).
- All sinks are **fail-open**: SIEM export is observability, not a gate. A down
  SIEM must never break cert-watch writes. Log a WARNING and move on.

This async-with-backpressure piece is the real work in F and the reason it's
"moderate, not trivial."

## Config (env, `*_FILE` supported via `read_secret`)

- `CERT_WATCH_SYSLOG_HOST`, `CERT_WATCH_SYSLOG_PORT` (default 514),
  `CERT_WATCH_SYSLOG_PROTO` (`udp`/`tcp`), `CERT_WATCH_SYSLOG_FACILITY`.
- `CERT_WATCH_HEC_URL`, `CERT_WATCH_HEC_TOKEN` (+ `_FILE`),
  `CERT_WATCH_HEC_INDEX` (optional), `CERT_WATCH_HEC_SOURCETYPE` (optional),
  `CERT_WATCH_HEC_VERIFY_TLS` (default on).
- `CERT_WATCH_SIEM_EVENTS` — `audit` (default) or `audit,alerts`.

Each sink is enabled only when its required config is present (mirrors how SMTP /
webhook activate today).

## Event format

One JSON object per event: the audit row fields verbatim, plus `event_type`
(`cert_watch.audit` / `cert_watch.alert`), `instance` identifier, and
cert-watch `version`. Stable field names so SIEM field extraction is reliable.
For HEC, wrap in the HEC envelope (`{"event": {...}, "sourcetype": ..., "index":
..., "time": <epoch>}`). For syslog, RFC 5424 structured data with the JSON as
the message.

## Composition with Plan 026 (audit tamper-evidence)

Once the audit log is hash-chained (Plan 026), periodically pushing the signed
**chain head hash** through this export gives the **external anchor** that
upgrades tamper-evidence from "verifiable locally" toward "the operator can't
silently rewrite history." Sequence note: F can ship first (sinks), and the
head-hash push lands when 026 lands — they reinforce each other.

## Slices

1. **Sink interface + syslog sink** (stdlib, zero-dep), wired off `record_audit`
   post-commit, fail-open. Config + tests.
2. **HEC sink** — formatter + HEC envelope + delivery through `ssrf_safe_urlopen`,
   behind the bounded background queue. Config (+`_FILE` token). Tests with a
   mocked opener (success, HEC 4xx, queue-full drop, SIEM-down fail-open).
3. **Alerts opt-in** (`CERT_WATCH_SIEM_EVENTS=audit,alerts`).
4. **(Deferred)** Windows Event Log writer behind `[windows]` extra.

## Testing

- **Syslog**: assert a `SysLogHandler` record is emitted with the expected
  RFC-5424 shape for a sample audit event; sink disabled when unconfigured.
- **HEC**: mock `ssrf_safe_urlopen`; assert envelope/index/sourcetype/token
  header; assert a 4xx and a connection error are swallowed (fail-open) and
  logged; assert queue-full drops with a warning rather than blocking.
- **No-config**: with neither configured, `record_audit` behaviour is byte-for-
  byte unchanged (no sink work, no latency).
- **SSRF**: HEC honours `allow_private`/`allowed_subnets` (internal HEC allowed
  only when policy permits).

## Risks / decisions

- **Blocking the request path** — mitigated by the async queue for HEC; syslog is
  local/fast. The non-negotiable invariant: a SIEM problem never breaks or slows
  an audited action.
- **Event loss on crash** — the background queue is in-memory; a hard crash drops
  un-flushed events. Acceptable for v1 (the DB audit row is the source of truth;
  the SIEM copy is a mirror). Document it; durable spooling is a later option.
- **PII / secrets in `detail`** — audit `detail` is already sanitized at write
  time (SMTP/webhook credential scrubbing); confirm no sink re-introduces raw
  secrets. Reuse existing sanitization, don't re-derive.
