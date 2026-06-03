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
A function `process_pending(alert_repo: AlertRepository, config: AlertConfig) -> dict[str, int]` must send all pending alerts, mark them as sent or failed, and return counts: `{"sent": N, "failed": M}`.

## AC-05: Alert Formatting
Each alert email must include: certificate subject, expiry date, days remaining, and recommended action.

## AC-06: Graceful SMTP Failure
If SMTP connection fails, `send_alert` must catch the exception, store the error message in the alert record, and return `False` — not raise.