# Plan 044 — Webhook Event Streaming

**Status:** proposed 2026-06-06
**Author:** Opus 4.8 (portfolio review)
**Strategic role:** Generalize the existing webhook delivery (alerts only) into a full event stream so operators can build reactive automation: Jira tickets, Slack notifications, PagerDuty incidents, custom playbooks.

## Why now

Today, webhooks are used only for alert delivery (expiry warnings, posture failures). The `alert_adapters.py` registry already has a clean pattern for dispatching to Discord, Teams, PagerDuty, and generic URLs. The natural extension is to emit a broader set of events:
- `cert_added` — a new cert is scanned or uploaded.
- `cert_renewed` — a cert is replaced by a successor (tracked via `replaces_cert_id`).
- `posture_changed` — a cert's posture grade drops (e.g., A → C).
- `scan_failed` — a host scan fails (connection timeout, TLS error).
- `policy_violation` — a configurable policy rule is breached (Plan 042).
- `alert_acknowledged` — an operator marks an alert as read.

This reuses the existing `alert_adapters.py` adapter registry and `WebhookConfig` model.

## Scope

### WI-1 — Event model
- `cert_watch.events` module with an `Event` dataclass:
  - `event_type: str` — one of the types above.
  - `timestamp: datetime`.
  - `payload: dict` — event-specific data (e.g., `cert_id`, `hostname`, `old_grade`, `new_grade`, `error_message`).
  - `source: str` — `scan`, `upload`, `ct`, `manual`, `scheduler`.

### WI-2 — Event emitter
- `emit_event(event: Event)` — synchronous, fail-open:
  - Writes to `event_log` table (append-only, like `audit_log`).
  - Fans out to configured webhook sinks via the existing `send_webhook()` adapter registry.
  - Uses `ThreadPoolExecutor` (bounded, same as SIEM) so the request path never blocks.
- `EventStreamConfig` dataclass (persisted in `kv_store`):
  - `enabled_event_types: list[str]` — whitelist of event types to emit.
  - `webhook_configs: list[WebhookConfig]` — one or more sinks (reuses existing `alerts.WebhookConfig`).
  - `rate_limit_per_second: int` — default 10, to prevent webhook spam.

### WI-3 — Instrumentation points
- `scan.py` `store_scanned()` emits `cert_added` (new cert) or `cert_renewed` (replacement detected).
- `posture.py` `evaluate_posture()` emits `posture_changed` if the grade differs from the stored grade.
- `scan.py` `scan_host()` emits `scan_failed` on `ScanError`.
- `upload.py` `store_uploaded()` emits `cert_added`.
- `routes/api/alerts.py` alert read/ack endpoint emits `alert_acknowledged`.
- `alerts.py` `evaluate_thresholds()` emits `alert_triggered` when a new alert is created.

### WI-4 — Event API
- `GET /api/events` — paginated list of recent events (time-range filter, type filter, source filter).
- `GET /api/events/stream` — Server-Sent Events (SSE) endpoint for real-time event streaming to browser dashboards.
- `GET /settings/events` — HTML page to configure event sinks, enable/disable event types, and test a webhook.

### WI-5 — Adapter additions
- `JiraAdapter` — creates a Jira issue via REST API; uses `WebhookConfig` fields for `base_url`, `api_token`, `project_key`.
- `SlackAdapter` — posts to a Slack channel via incoming webhook; reuses the generic `WebhookConfig.url`.
- Both adapters are pure `build()` functions following the `AlertAdapter` protocol.

### WI-6 — Retry and dead-letter
- Webhook delivery attempts 3 times with exponential backoff (reuses `retry.backoff_range()`).
- Failed deliveries are logged to `event_log` with `delivery_status="failed"` and `error_message`.
- A `GET /api/events/failed` endpoint shows failed deliveries for operator review.

## Acceptance

- A simulated cert scan emits a `cert_added` event that appears in `GET /api/events`.
- A posture grade drop emits `posture_changed` with `old_grade` and `new_grade` in the payload.
- A configured webhook sink receives the event JSON within 1 second of the triggering action.
- The SSE endpoint streams events to a browser client in real-time.
- Disabling an event type in settings stops emitting it.
- A failed webhook delivery is retried 3 times and then logged as failed.
- 0 lint errors; unit tests cover event emission, adapter dispatch, SSE streaming, and retry logic; full suite passes.

## Non-goals

- Event sourcing / CQRS (the DB remains the source of truth; the event stream is a projection).
- WebSocket support (SSE is simpler and sufficient for browser dashboards).
- Guaranteed exactly-once delivery (at-least-once is acceptable; idempotency is the consumer's responsibility).
- Kafka / NATS / message-bus integration; direct HTTP webhooks are the scope.
