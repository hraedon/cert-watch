# Plan 031: Durable SIEM Spooling (Workstream F2)

> **Status:** **Deferred (post-0.6.0).** Grounded in `siem.py` (the
> `SiemExporter` class with `ThreadPoolExecutor` for HEC and inline dispatch for
> syslog/Event Log) and `audit.py` (the `record_audit` post-commit hook).
> Extends Plan 028.
>
> **Reframed after review — the value is narrower than "crash-resilience"
> implies.** The audit row is written to cert-watch's own DB *first* (source of
> truth) and survives any crash; only the *real-time SIEM mirror* of in-flight
> events is at risk, on one sink (HEC), for a tool doing ~100 events/day. So
> this is **near-real-time SIEM continuity across restarts**, not data-loss
> prevention — the events are recoverable today by re-exporting from the audit
> log. Given the low event volume and the added complexity (a polling background
> worker, a new table, thread lifecycle), this is a nice-to-have, deferred until
> a SIEM-integrated operator actually asks for gap-free real-time delivery.

## Goal

Give the HEC sink **near-real-time continuity across process restarts**: events
generated between the last successful HEC POST and a restart/crash are delivered
on recovery instead of only living in the local audit log until a manual
re-export. Today the HEC sink uses an in-memory
`ThreadPoolExecutor(max_workers=2)`, so a restart drops un-flushed events from
the *real-time SIEM feed* (the underlying audit rows are already durable in the
DB). This plan adds a durable disk spool between event generation and HEC
delivery, using the existing SQLite WAL infrastructure.

The syslog and Windows Event Log sinks are inherently local/fast (inline
dispatch) and don't need spooling. This plan targets the **HEC sink** as the
only sink with non-trivial delivery latency.

## What already exists (build on, don't rebuild)

- **`SiemExporter`** (`siem.py:66`): `ThreadPoolExecutor` with `_to_hec` worker.
  The `export(event)` method dispatches to all enabled sinks. Fail-open at
  every level.
- **`record_audit`** (`audit.py:16`): inserts the DB row first (source of
  truth), then calls `export_audit_event` post-commit. The audit row survives
  crashes; only the SIEM mirror is at risk.
- **SQLite WAL** (`database/connection.py`): the app already uses WAL mode for
  all tables. A new `siem_spool` table in the same database is crash-safe by
  default (WAL checkpoint semantics).
- **`_to_hec`** (`siem.py:137`): single POST per event via `ssrf_safe_urlopen`.
  No batching, no retry. Logs WARNING on non-2xx.
- **Maintenance cycle** (`scheduler.py`): already runs history/alert/audit
  purges. Spool cleanup is a natural addition.

## Design

Replace the in-memory `ThreadPoolExecutor` with a **write-through spool**:

1. `export()` writes the event to a `siem_spool` SQLite table (one row per
   event, with `status=pending`). This is synchronous and fast (local WAL
   write).
2. A **background worker thread** reads pending events, POSTs to HEC, and
   marks them `sent` or `failed`.
3. On startup, the worker re-drains any `pending` rows left from a previous
   crash (the "replay" path).
4. Periodic cleanup purges `sent` rows older than a retention window.

This is the same pattern used by the existing `alerts.py` pending/sent/failed
model — proven in the codebase already.

### Spool table schema

```sql
CREATE TABLE IF NOT EXISTS siem_spool (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',  -- pending | sent | failed
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    sent_at TEXT,
    error_message TEXT,
    retry_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_siem_spool_status ON siem_spool(status);
```

### Worker thread

- Runs in the app lifespan (started alongside the scheduler).
- Polls for `pending` rows every `SIEM_SPOOL_POLL_SECONDS` (default 5).
- POSTs each event to HEC via `ssrf_safe_urlopen` (same as today).
- On success: `UPDATE status='sent', sent_at=now`.
- On failure: increment `retry_count`. After `SIEM_SPOOL_MAX_RETRIES` (default
  5): `UPDATE status='failed', error_message=...`. Log WARNING.
- Exponential backoff between retries (1s, 2s, 4s, 8s, 16s).
- On startup: immediately drain any `pending` rows (crash recovery).

### Cleanup

- In the maintenance cycle: `DELETE FROM siem_spool WHERE status='sent' AND
  sent_at < now - SIEM_SPOOL_RETENTION_HOURS` (default 24h).
- `failed` rows are kept for 7 days (for debugging) then purged.

## Non-goals

- Not batching HEC POSTs (each event is still one POST). Batching is a
  separate optimization that composes with spooling.
- Not spooling for syslog or Windows Event Log (local/fast, no crash-loss
  risk worth the complexity).
- Not a general-purpose message queue. The spool is append-only, single-
  consumer, and cleaned aggressively.

## Config

- `CERT_WATCH_SPOOL_ENABLED` — `1` to enable durable spooling (default 1 when
  HEC is configured; set to 0 to use the old in-memory queue).
- `CERT_WATCH_SPOOL_POLL_SECONDS` — worker poll interval (default 5).
- `CERT_WATCH_SPOOL_MAX_RETRIES` — max delivery attempts before marking failed
  (default 5).
- `CERT_WATCH_SPOOL_RETENTION_HOURS` — how long to keep sent rows (default 24).
  `failed` rows kept for 7x this value.

## Slices

1. **Spool table**: migration 0014 (or 0015 if ADCS plan takes 0014). Schema
   as above. Wire into `schema.py`.
2. **Spool writer**: replace `_pool.submit(_to_hec, event)` in `SiemExporter`
   with `INSERT INTO siem_spool`. Synchronous, local, fast. Preserve the
   existing fail-open contract.
3. **Spool worker thread**: `SpoolWorker` class with `start()`/`stop()` methods.
   Polls pending rows, POSTs to HEC, updates status. Crash-recovery drain on
   start. Background daemon thread (matching the scheduler pattern).
4. **App lifespan wiring**: start `SpoolWorker` alongside the scheduler in
   `app.py` lifespan. Graceful shutdown (drain in-flight, then stop).
5. **Cleanup**: add spool purge to the maintenance cycle. Purge sent rows after
   retention, failed rows after 7x retention.
6. **Fallback**: `CERT_WATCH_SPOOL_ENABLED=0` preserves the old in-memory
   `ThreadPoolExecutor` path for operators who prefer it.

## Testing

- **Write-through**: mock the HEC endpoint (return 500); write an event via
  `export()`; assert a `siem_spool` row exists with `status=pending`. Assert
  the event is eventually delivered when the mock returns 200.
- **Crash recovery**: insert `pending` rows directly into the table, start the
  worker, assert they are drained and delivered.
- **Retry + failure**: mock HEC to return 500 consistently; assert retry_count
  increments, status flips to `failed` after max retries, error_message is
  captured.
- **Cleanup**: insert old `sent` rows, run maintenance, assert they are purged.
  Assert `failed` rows are purged after 7x retention.
- **No-config fallback**: with `CERT_WATCH_SPOOL_ENABLED=0`, assert the old
  `ThreadPoolExecutor` path is used (existing behavior preserved).
- **Fail-open**: assert that a spool write failure (e.g., disk full) does not
  raise — the event is logged and lost, matching the existing contract.

## Risks / decisions

- **SQLite contention** — the spool table shares the database with all other
  tables. The write path is a single INSERT per event (fast); the worker reads
  and updates. With WAL mode and the single-writer model, this is safe. The
  worker should use a separate connection (not the request-path connection) to
  avoid holding locks.
- **Spool growth under sustained HEC outage** — if HEC is down for days, the
  spool grows. Mitigated by the retry limit (mark `failed` after max retries)
  and retention purge. Document that a prolonged HEC outage means event loss
  after `max_retries * poll_interval`.
- **Database size** — each event is ~500 bytes JSON. At 100 events/day (typical
  SMB), the spool adds ~50KB/day. Negligible even with 7-day failed retention.
- **Thread lifecycle** — the spool worker thread must be started and stopped
  cleanly alongside the scheduler. Use the same `threading.Event` pattern as
  `scheduler.py` for clean shutdown.
