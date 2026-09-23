# Plan 058: Alerting is a package with one persisted lifecycle

Plan 057, workstream W4. Designed 2026-09-22 against the plan-056 branch
(migration head `m0035_schema_reconciliation`). Assumes W1 (flush serialized
with the scheduler's cycle lock, #60, #61) and W3 (`transaction()`, SQL only
under `database/`) have landed.

## 0. Already fixed — W4 does not redo these

- #39: `purge_old_alerts` keeps undelivered rows 4× longer (PR #53).
- #38: `alerts.deferred_since` (m0033), `_settle_evidence_deferral` never
  raises, 72h give-up (PR #55).
- #30: `DeliveryEvidenceUnavailable` leaves the alert pending. #37 closed.
- PR #57 carries alerts onto the rewritten row on an unchanged rescan
  (`database/cert_ops.py:101-117`). Expiry dedupe still depends on that carry
  because it keys on the row id.

W4 moves the mechanisms behind these fixes into one lifecycle so the next fix
happens in one place.

## 1. Package layout and dependency direction

```
cert_watch/alerting/
  __init__.py        facade: run_alert_cycle, Dispatcher, DigestEngine, AlertConfig, WebhookConfig
  model.py           AlertType/AlertStatus enums, AlertDraft, OutboundMessage, SendResult,
                     channel names, AlertConfig/WebhookConfig, threshold constants
  messages.py        message and digest body formatting
  routing.py         resolve_routing() (was _resolve_group_config), resolve_cert_recipients,
                     role-user emails, find_orphan_certs; also used by routing_report
  rules/expiry.py    effective_thresholds, evaluate_thresholds, evaluate_all_certs
  rules/renewal.py   renewal window + renewal_overdue (from scheduler._check_renewal_overdue)
  rules/policy.py    evaluate_policy_alerts
  rules/drift.py     create_drift_alert (detection stays in database/drift)
  transports/base.py Transport protocol
  transports/smtp.py, webhook.py, adapters.py (from alert_adapters.py; builds from OutboundMessage)
  evidence.py        attempt_delivery + FAILURE_LABELS (no ContextVar)
  dispatch.py        Dispatcher (process_pending, _Delivery, _attempt_once, deferral settle)
  resolve.py         resolve_webhook_for_renewed_cert
  digest/engine.py   DigestEngine (claims, per-recipient SMTP, webhook fallback)
  digest/expiry.py, renewal.py, orphan.py   content per kind
cert_watch/database/alert_store.py   all alerts-table lifecycle SQL
```

`model` imports stdlib only; `messages` → `model`; `transports` → `model`,
`http_client`, `host_validation`; `evidence` → `model`,
`database.delivery_evidence`; `routing` → `model`, `database`, `tags`; `rules`
→ `model`, `messages`, `routing`, `database.alert_store`; `dispatch` → `model`,
`transports`, `evidence`, `database.alert_store`; `digest` → `model`,
`messages`, `routing`, `transports`, `database.digest_deliveries`. Callers
(`scheduler_context`, `scan`, `routes`, `events`) import the facade only.
Nothing under `alerting/` imports `scheduler*`, `scan`, `routes` or `events`;
`database/` never imports `alerting`. `tests/test_alerting_layering.py`
enforces this with an AST scan.

`events.py` stays outside (the event stream is its own product) and calls
`transports.webhook` with an `OutboundMessage` instead of the pseudo-alert
`Alert(status="event")`.

## 2. Persisted lifecycle

| status | meaning | terminal |
|---|---|---|
| `pending` | queued; eligible when `next_attempt_at IS NULL OR <= now` | no |
| `sending` | claimed by one dispatcher under a lease | no |
| `sent` | at least one channel accepted | yes |
| `failed` | give-up policy reached | yes (operator retry only) |
| `cancelled` | condition closed before delivery | yes |

`read` stays orthogonal. Deferral and budget exhaustion are `pending` plus
`deferred_since` / `next_attempt_at`, not states.

Transitions (only `database/alert_store.py` issues them):

| from → to | actor | guard |
|---|---|---|
| new → `pending` | rules via `AlertStore.enqueue(draft, conn)` | no open row with same `dedupe_key` |
| `pending` → `sending` | `Dispatcher.claim` | eligible; atomic `UPDATE … RETURNING` |
| `sending` (lease expired) → `sending` | another dispatcher | `lease_expires_at < now` |
| `sending` → `sent` / `pending` / `failed` | lease holder | `WHERE id=? AND lease_owner=?` |
| `pending` → `cancelled` | rules (condition closed), stale-cert path instead of DELETE | `status='pending'` |
| `failed` → `pending` | operator "Retry failed" | resets `attempt_count` |

A completion write that updates 0 rows means the lease was lost: log, don't retry.

```sql
UPDATE alerts SET status='sending', lease_owner=:owner, lease_expires_at=:exp
WHERE id IN (SELECT id FROM alerts
  WHERE (status='pending' AND (next_attempt_at IS NULL OR next_attempt_at<=:now))
     OR (status='sending' AND lease_expires_at<:now)
  ORDER BY created_at LIMIT :n)
RETURNING *;
```

Lease = cycle budget + 120 s, renewed between waves. Flush builds the same
`Dispatcher` with a scope predicate and `ignore_backoff=True`; the cycle lock
becomes a second line of defence.

Attempts: in-cycle waves unchanged (3 retries, 2 s gap, budget).
`attempt_count` increments once per wave that reached a transport. At cycle
end an undelivered alert becomes `failed` at `ALERT_MAX_ATTEMPTS = 12`,
otherwise `pending` with `next_attempt_at = now + [1h, 4h, 12h][round]`.
Evidence deferral keeps its separate 72 h clock.

Per-channel outcomes stay in the append-only `alert_delivery_events` ledger;
`latest_outcomes()` generalises to `{alert_id: {channel: outcome}}`. The
alerts row carries only aggregate state (`attempt_count`, `last_attempt_at`,
`failure_reason`, sanitized `error_message`). `started` details gain
`claim_owner`.

Migration 0036 adds `attempt_count`, `next_attempt_at`, `last_attempt_at`,
`lease_owner`, `lease_expires_at`, `failure_reason` and
`idx_alerts_dispatch(status, next_attempt_at)`; backfills `last_attempt_at`
from the ledger. No CHECK on `status`, so no table rebuild.

## 3. One dedupe policy per alert type

Rule: at most one un-closed alert per `dedupe_key`. Rules set `closed_at` when
the condition stops holding; a pending row is cancelled, a sent row becomes
eligible to fire again. Keys use the certificate fingerprint, not the row id.

Migration 0037 adds `dedupe_key`, `closed_at`, `routing`, a partial unique
index on open keys, and `rule_firings(dedupe_key PK, first_fired_at,
last_fired_at, fire_count)` for event-only rules; backfills keys (expiry via
fingerprint join, policy by parsing `[rule_id]`); collapses duplicate open rows
first.

| type | key | after sent | today |
|---|---|---|---|
| expiry | `expiry:{fp}:{type}:{threshold}` | never again for that key | row-id dedupe (bug, saved by #57); unlimited failed→pending revival (bug) |
| renewal_stalled | `renewal:{fp}` | not again until closed | re-created every cycle after a send (bug) |
| policy_violation | `policy:{fp}:{rule_id}` | not again while violation persists | substring match, re-alerts every scan (bug) |
| drift | `drift:{host}:{port}:{fp}:{sha(events)}`, closed at creation | edge alert | no dedupe; mostly intended |
| renewal_overdue | `overdue:{host}:{port}:{fp}` in `rule_firings` | again after 24 h | re-parses event_log JSON; right cadence, wrong mechanism |
| digests | `digest_deliveries` claims | once per period per target | claims + kv week + memory: redundant |

`evaluate_policy_alerts` runs inside the scan transaction; `enqueue(conn=…)`
keeps that, and the unique index turns a racing duplicate into a caught
`IntegrityError`. Resolves (PagerDuty/Alertmanager) fire on `closed_at` for
sent keys.

## 4. Routing resolved once and persisted

Rules call `routing.resolve_routing(db, cert_ids)` once per batch and store the
result in `alerts.routing` (JSON, versioned). `extra_recipients` is still
written for one release, then dropped. `alert_delivery._matching_groups`
(re-resolution at attempt time) is deleted. Transport configuration (global
recipients, webhook URL) stays resolved at send time: that is destination
config, and a mid-outage SMTP fix should apply to queued alerts. Policy and
drift alerts gain group/owner/role routing.

## 5. Transport interface

```python
@dataclass(frozen=True)
class SendResult:
    outcome: Literal["accepted", "partial", "failed", "blocked"]
    reason: str = ""                 # FAILURE_LABELS key
    reached_transport: bool = True
    accepted: tuple[str, ...] = ()
    refused: tuple[str, ...] = ()
    http_status: int | None = None
    operator_message: str = ""
    @property
    def delivered(self) -> bool: return self.outcome in ("accepted", "partial")

class Transport(Protocol):
    channel: str          # "smtp" | "webhook:<kind>"
    destination_id: str   # "smtp" | sha256(url|routing_key)[:16]
    def send(self, msg: OutboundMessage) -> SendResult: ...
```

Removes the `alert.error_message` side channel and the `_Observation`
ContextVar. Channel vocabulary: `smtp` or
`webhook:{generic|slack|discord|teams|pagerduty|alertmanager}`; the digest
claim key stays byte-identical to today's; legacy ledger names are mapped on
read by `model.normalize_channel()`.

## 6. One digest engine

```python
class DigestKind(Protocol):
    name: str                                 # "expiry" | "renewal" | "orphan"
    webhook_fanout: Literal["global", "per_target"]
    def targets(self, db, now, cadence) -> list[DigestTarget]: ...
    def render(self, t: DigestTarget) -> OutboundMessage: ...
DigestEngine(db, transports, budget).run(kind, period_key) -> DigestRunResult
```

The engine owns claim/renew/complete, per-recipient SMTP, refused-recipient
retry and webhook fallback, with one retry policy for both kinds, synchronous
within the alert budget. Removed: `send_expiry_digest`, `send_renewal_digest`,
the digest thread pool, `delivery_completion_callback`, the inflight-week state
in `SchedulerContext` (the #61 bug class) and the kv week keys. The orphan
notice becomes a claimed kind. `digest_period_key` keeps its format.

## 7. Migration path — five PRs

1. **Package skeleton and moves, no behaviour change.** Old modules become
   re-export shims. Retarget the 94 string monkeypatch targets in 8 test files
   mechanically; a guard test forbids new `cert_watch.alerts.` patch targets.
   Layering test lands.
2. **`SendResult` transports and unified channel names.** Contract table test
   per failure mode; `FakeTransport` fixture; `normalize_channel` over legacy
   rows. Two reviewers (external sinks).
3. **Migration 0036, claims, leases, backoff, give-up.** Two dispatchers on
   threads send each alert exactly once; lease reclaim; lost-lease no-op;
   injected-clock backoff; #38 tests unchanged; fresh-vs-upgraded schema check.
4. **Rules, dedupe keys, persisted routing (0037).** Per-type matrix (scan ×N,
   send, clear, reappear, renew) asserting alert counts;
   `test_unchanged_cert_does_not_realert.py` unmodified; backfill and collapse
   tests; routing-report parity. Changed assertions listed in the PR body.
5. **Digest engine; delete shims.** Engine tests with `FakeTransport`;
   same-period second run sends nothing; upgrade-week claims suppress resend;
   content goldens carried over.

New tests import only from `cert_watch.alerting` and its public submodules.

## 8. Decisions

Taken by the implementer under the owner's 2026-09-22 delegation; each is
revisitable and each is listed in UPGRADING.md where it changes behaviour.

1. `renewal_stalled` fires once per fingerprint. The weekly renewal digest is
   the reminder channel.
2. Give-up: 12 attempts, backoff 1 h / 4 h / 12 h, plus a "Retry failed" action.
3. Delivery stays at-least-once (today's behaviour). Losing an expiry alert is
   worse than a duplicate.
4. Channel policy unchanged: SMTP first, webhook only if SMTP did not deliver.
5. Policy and drift alerts route to groups, owners and roles like every other
   alert. Routing that silently excludes alert types is the surprise.
6. Stale pending alerts are `cancelled`, not deleted; retention removes them.
7. Renewal-digest webhooks run synchronously within the cycle budget
   (coordinated with W5).
8. The expiry digest header states the real cadence window.
9. The port-less `renewal_overdue` shim stays through 1.x and is removed in 2.0.
10. Policy rows whose certificate is gone backfill with a NULL key.
