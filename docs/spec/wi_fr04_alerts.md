# Interface Specification: FR-04 Email Alerts

## Dependencies

- `interface_ref`: `certificate_model`
- `interface_ref`: `database_layer`

## AC-01: Alert Configuration
A `AlertConfig` dataclass must contain:
- `smtp_host: str`
- `smtp_port: int` (default 587)
- `smtp_user: str`
- `smtp_password: str`
- `from_addr: str`
- `recipients: list[str]`

## AC-02: Threshold Evaluation
A function `evaluate_thresholds(cert: Certificate, alert_repo: AlertRepository) -> list[Alert]` must check a certificate against expiry thresholds and create pending alerts:
- Leaf certificates: 14, 7, 3, 1 days before expiry
- Chain certificates: 30, 14, 7 days before expiry
- Must not create duplicate alerts for the same threshold on the same certificate.
- Alert thresholds must be computed against `Certificate.days_until_expiry()` from the `certificate_model` module — the test must call `days_until_expiry()` on a real `Certificate` instance obtained from `parse_certificate`, not construct a `Certificate` with literal `not_after` values. This ensures the implementation loads the real `certificate_model` module, not a stub.

## AC-02b: Renewal-Window Evaluation (Plan 027)
A function `evaluate_renewal_window(db_path, alert_repo, window_days) -> list[Alert]`
creates `renewal_stalled` alerts — a signal distinct from expiry warnings. A leaf
certificate qualifies when: it is inside the renewal window
(`0 <= days_remaining <= window_days`), and **no successor certificate exists**
(no other cert's `replaces_cert_id` points at it). This flags a broken
Certbot / cert-manager / ACME job before the generic expiry alarm. Idempotent:
at most one pending `renewal_stalled` alert per certificate. `window_days = 0`
(`CERT_WATCH_RENEWAL_WINDOW_DAYS`) disables it.

## AC-03: Send Alert
A function `send_alert(alert: Alert, config: AlertConfig) -> bool` must send an email via SMTP and return `True` on success, `False` on failure.

## AC-04: Process Pending
A function `process_pending(alert_repo: AlertRepository, config: AlertConfig) -> dict[str, int]` must send all pending alerts and return counts: `{"sent": N, "failed": M, "deferred": D}`.

An alert ends a cycle in one of three states. It is marked **sent**, or marked **failed** after its retries are exhausted, or left **pending** and counted as **deferred** — the last when no transport was reached at all because the delivery-evidence store could not be written. A deferral is not a delivery failure: nothing was dispatched, the destination was never contacted, and the alert stays deliverable for a later cycle. It must not consume the retry budget.

A pass that reaches no transport must also stop the cycle rather than exhaust
its backoff: there is no destination to back off from, and the same unwritable
database will refuse the next attempt. The failure message reports the transport
attempts that actually ran, which for a dual-channel estate exceeds
`ALERT_MAX_RETRIES` — that constant bounds the passes, not the sends.

Deferral is unbounded by design (see #38), so it must not be silent. Two surfaces
report it, both derived from `ALERT_UNDELIVERED_AFTER_HOURS` (`alerts.UNDELIVERED_AFTER_HOURS`,
24h — one daily cycle plus slack):

- `/api/health` reports `undelivered_alerts` — alerts still `pending` past that
  window — and degrades to `warning` on any.
- Activity marks each such alert **Not yet delivered**. The chip is additive: an
  attempt may be recorded and left `unknown` while the alert is still queued, and
  the outcome chip answers a different question from whether it went out.

Both are derived from age at read time rather than stored on the alert. The
deferral happens precisely when the database refuses a write, so the reason
cannot be persisted at the moment it is known — the store that would hold it is
the one that is down. Age is also cause-agnostic: it catches a scheduler that has
stopped flushing, which no delivery-side marker would ever record. An unreadable
`created_at` counts as undelivered on neither surface.

This is the operator-visible trace that the old, incorrect behavior supplied as
a side effect of marking such alerts `failed`. Closes #37.

## AC-05: Alert Formatting
Each alert email must include: certificate subject, expiry date, days remaining, and recommended action.

## AC-06: Graceful SMTP Failure
If SMTP connection fails, `send_alert` must catch the exception, store the error message in the alert record, and return `False` — not raise.

## AC-07: Delivery Evidence
SQLite-backed pending-alert processing records a durable start before each
transport invocation and a separate completion afterward. Failure to persist a
start refuses that attempt; failure to persist its outcome remains unknown and
must not itself provoke a duplicate send. Record only attempted envelope
recipients, allowlisted outcomes/failure categories, HTTP status and group
configuration at the attempt. Do not store transport credentials, URLs, response
bodies or raw exception text in this evidence.

Activity distinguishes recorded alert state from actual transport outcomes,
including partial SMTP refusal and unknown completion. Recipients and matching
groups are administrator-only; non-admin viewers receive safe outcome summaries
only for alerts already within their scope. Current group matches do not prove
which group supplied addresses saved when the alert was originally queued.
SMTP acceptance means relay acceptance, not mailbox receipt.

Finished sent/failed notifications with delivery evidence survive routine
certificate replacement, preserving their original historical certificate
reference. Obsolete pending notifications retain the existing discard behavior.
Alert retention/deletion also deletes that alert's delivery evidence. Historical
records without attempt observations must not invent a route or outcome.
