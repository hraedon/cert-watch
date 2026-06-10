# Plan 040 — CT Log Monitoring (Auto-Ingest)

**Status:** deferred 2026-06-10
**Author:** Opus 4.8 (portfolio review)
**Deferral rationale:** The crt.sh daily pull provides adequate mis-issuance
detection and coverage-gap analysis for the SMB self-hosted positioning.
Daily MTTD is within the SLA window regulated businesses actually require;
sub-hour detection is an enterprise differentiator, not an SMB need.
Revisit when a customer or auditor specifically requires real-time CT
monitoring.

**Architecture-forwards note (2026-06-10):** The current module boundary
(`ct_lookup.py` = data source, `ct_monitor.py` = orchestration + alerts)
is forwards-compatible with this plan. When un-deferred, extract the
mis-issuance detection logic from `ct_reconciliation()` into a
source-agnostic function that accepts cert entries from either crt.sh
or RFC 6962 `get-entries`. The alert pipeline (`create_ct_misissuance_alert`,
`evaluate_thresholds`) and scheduler callback (`ct_fn`) stay unchanged.
Do not couple new streaming infrastructure to the crt.sh query path.
**Strategic role:** Catch shadow certificates and unauthorized issuance in near-real-time, before the next scheduled scan. Fills the biggest unimplemented gap in the codebase (`ct_monitor.py` at 0% coverage).

## Why now

`cert_watch.ct_monitor` exists as an empty module (10 lines, 0% coverage). The CT reconciliation feature in `routes/api/insights.py` already queries `crt.sh` for known certs. The natural extension is to **watch** CT logs for *new* certs matching the monitored domains, auto-ingest them, and alert if an unexpected issuer or fingerprint appears.

This turns cert-watch from a "pull" model (scan on schedule) to a hybrid push+pull model.

## Scope

### WI-1 — CT log streaming client
- `ct_monitor.py` implements a `CTLogMonitor` class:
  - Polls known CT logs (Google Argon, Cloudflare Nimbus, etc.) via the RFC 6962 `get-entries` endpoint.
  - Uses a cursor table (`ct_log_cursor`) to track `start` per log so restarts are resumable.
  - Filters incoming certificates by `subject` / `subjectAltName` against the host list in the database.
  - Parses the DER entry into a `Certificate` via `certificate_model.parse_certificate`.

### WI-2 — Auto-ingest pipeline
- When a new cert is found for a known domain:
  - If it matches the **current** live cert (same fingerprint), no-op.
  - If it is a **new** leaf (different fingerprint, overlapping SANs), store it as `source="ct"` and link it to the host via `host_id`.
  - If it is a **chain-only** cert, store it in the chain table.

### WI-3 — Drift alerts from CT
- `evaluate_thresholds` gains a new alert type: `ct_unexpected`.
  - Triggers when a CT-discovered cert for a known host has:
    - An issuer not matching the previously stored issuer (issuer drift).
    - A key type/size downgrade (e.g., RSA 2048 → RSA 1024).
    - A self-signed flag when the previous cert was CA-signed.
  - Uses the existing `alerts.py` / `send_webhook` / `send_smtp` paths.

### WI-4 — Background integration
- `scheduler.py` adds a `ct_monitor_fn` parameter to `_run_cycle`.
- Runs after the scan cycle but before the alert cycle, so CT-discovered certs are available for threshold evaluation in the same daily window.
- Poll interval is configurable (`CERT_WATCH_CT_POLL_INTERVAL_MINUTES`, default 60).

### WI-5 — Dashboard indicator
- `routes/views.py` dashboard shows a "CT monitored" badge on hosts that have CT streaming enabled.
- A new `GET /api/insights/ct-detected` endpoint returns recently CT-discovered certs (last 24h) for the API consumers.

## Acceptance

- A synthetic CT log entry (mocked `get-entries` response) for a known domain is parsed, stored, and linked to the correct host.
- A CT entry with a new issuer for a known domain triggers a `ct_unexpected` alert.
- The cursor table prevents re-processing the same entries on restart.
- The scheduler runs the CT poll without blocking the scan or alert cycles.
- 0 lint errors; unit tests cover mock CT log, auto-ingest, drift detection, and cursor resumption; full suite passes.

## Non-goals

- Real-time WebSocket streaming from CT logs (polling is sufficient; RFC 6962 batch `get-entries` is the standard approach).
- Certificate revocation checks via CT (SCT verification is out of scope).
- CT log submission (we are a consumer, not a submitter).
- Changing the existing `ct_lookup.py` (crt.sh search) behavior; this plan adds a new module, it does not rewrite existing CT reconciliation.
