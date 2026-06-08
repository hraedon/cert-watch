# Interface Specification: FR-11 Alert Channels & SIEM Export

## Dependencies

- `interface_ref`: `alerts`
- `interface_ref`: `database_layer`
- `interface_ref`: `http_client`

## AC-01: Alert Channel Adapters

`send_webhook(alert, config: WebhookConfig) -> bool` must dispatch to an adapter registry based on `config.kind`:

1. **Generic** (`kind="generic"`) — POST the configured JSON template to the webhook URL.
2. **Discord** (`kind="discord"`) — POST a Discord-compatible embed message.
3. **Microsoft Teams** (`kind="teams"`) — POST an Adaptive Card via Workflows webhook.
4. **PagerDuty** (`kind="pagerduty"`) — POST to PagerDuty Events API v2 (`trigger` event).

All adapters must be pure `build()` functions returning the payload dict. No side effects in adapter code.

## AC-02: PagerDuty Resolve-on-Renewal

- `send_pagerduty_resolve(cert_id, routing_key)` sends a `resolve` event to PagerDuty.
- `resolve_pagerduty_for_renewed_cert(old_cert_id, db_path, webhook_config)` called in `store_scanned()` when a certificate is replaced.
- Dedup key is `sha256(cert_id:alert_type:threshold_days)[:32]`.
- PagerDuty success = HTTP 202.

## AC-03: SSRF-Safe Webhook Delivery

- All webhook delivery routes through `http_client.ssrf_safe_urlopen`.
- Validates initial URL and every redirect hop against `scan._is_blocked_ip`.
- Enforces `http(s)` scheme allowlist.
- Honors `allow_private`/`allowed_subnets` from `Settings`.
- `validate_webhook_url()` provides the shared validator for the API route.
- Blocked endpoints return clear "blocked by SSRF policy" error.

## AC-04: SIEM / Log Export

Three sinks, all **fail-open** (a down SIEM never blocks an audited action):

1. **Syslog** (`CERT_WATCH_SYSLOG_HOST`/`_PORT`/`_PROTO`):
   - Stdlib RFC-5424 handler.
   - Supports UDP and TCP.
   - Any SIEM or Azure AMA path.

2. **Splunk HEC** (`CERT_WATCH_HEC_URL` + `CERT_WATCH_HEC_TOKEN`/`_FILE`):
   - Through SSRF-safe opener.
   - Delivered on a bounded background pool.
   - JSON event format.

3. **Windows Event Log** (`CERT_WATCH_EVENTLOG=1`):
   - Application log via `pywin32` (`cert-watch[windows]` extra).
   - Disables itself off-Windows.
   - `pywin32>=306; sys_platform == 'win32'`.

All sinks:
- Logged at `INFO` level on successful delivery.
- Logged at `WARNING` level on failure (with error message).
- Never raise exceptions to the caller.

## AC-05: Audit Log

- Append-only `audit_log` table (migration 0002).
- Records: `timestamp`, `action`, `user`, `ip_address`, `target_type`, `target_id`, `details` (JSON).
- `resolve_source_ip()` uses proxy-aware extraction (`X-Forwarded-For`, `X-Real-IP`).
- Break-glass logins flagged `break_glass=true`.
- `CERT_WATCH_AUDIT_RETENTION_DAYS` (default 90) controls retention.
- `purge_old_audit()` trims at startup + daily.
- `0` disables retention.

## AC-06: Alert Retention

- `CERT_WATCH_ALERT_RETENTION_DAYS` (default 90) controls how many days of alerts to keep.
- `purge_old_alerts()` trims at startup + daily.
- `0` disables retention.

## AC-07: Alert Groups

- `alert_groups` table (migration 0008) with `name`, `recipients`, `webhook_url`, `webhook_kind`, `pagerduty_routing_key`.
- `alert_group_certs` junction table links certificates to alert groups.
- `resolve_all_group_recipients()` batches group routing in ≤3 queries.
- `evaluate_all_certs()` merges group + owner recipients into `extra_recipients`.
- Alert groups configurable via Settings GUI.
