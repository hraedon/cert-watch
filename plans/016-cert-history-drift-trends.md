# Plan 016: Certificate History, Drift Detection & Trends

> **Status:** ready for implementation. Grounded in the code as of `881cbe8`.
> Theme: turn cert-watch from a current-state view into an observability tool
> with memory. This is the highest-leverage item from the competitive review —
> and it's one *foundation* decision that unlocks three features.

## The key realization

Two things the review treated as separate ("drift alerts" and "trending
charts") are actually **one decision + three views**:

- A renewal **diff engine already exists**: `replace_scanned`
  (`database/queries.py`) calls `_compute_renewal_diff(old_leaf, new_leaf)`
  whenever a re-scanned cert's fingerprint changes — but it only **logs** the
  result and discards it.
- There is **no historical retention today**: on re-scan, `replace_scanned`
  **deletes** the old leaf/chain rows and the matching `scan_posture` rows.
  `scan_history` keeps scan *status* (success/fail + timestamp), **not**
  days-to-expiry or grade. So there is no time-series to chart or diff against.

So the foundation is a deliberate decision the design has so far avoided:
**start retaining bounded, append-only per-scan snapshots.** Once that exists,
drift alerting, trending, and the calendar view all fall out of it cheaply.

> ⚠️ Also note a latent bug to fix while here: the new leaf's `replaces_cert_id`
> is set to the *old* leaf id, but the old leaf row is then **deleted** — so the
> lineage pointer dangles. The history table below is where that lineage should
> actually live.

---

## Slice 1 — Snapshot history foundation (do first)

### Schema — migration (next free number; coordinate with plans 014/015)
```sql
CREATE TABLE cert_history (
    id            TEXT PRIMARY KEY,
    hostname      TEXT,
    port          INTEGER,
    fingerprint_sha256 TEXT NOT NULL,
    issuer        TEXT NOT NULL,
    not_after     TEXT NOT NULL,
    key_algo      TEXT,           -- e.g. "RSA-2048", "EC-P256"
    sig_algo      TEXT,
    posture_grade TEXT,           -- snapshot of the grade at scan time
    protocol_version TEXT,
    san_count     INTEGER,
    scanned_at    TEXT NOT NULL
);
CREATE INDEX idx_cert_history_host_port_ts ON cert_history(hostname, port, scanned_at DESC);
CREATE INDEX idx_cert_history_fp ON cert_history(fingerprint_sha256);
```
Add to `_BASE_TABLES`/`_BASE_INDEXES` and a `m00NN_cert_history.py` migration.

### Write path
- Append one `cert_history` row on **every** successful leaf scan (in the
  scan/store path — `replace_scanned` and the manual-scan route both flow
  through `store_scanned`; pick the single chokepoint). Capture the posture
  grade from the posture evaluation that already runs.

### Retention (bound the growth — this is the part the review ignored)
- `CERT_WATCH_HISTORY_RETENTION_DAYS` (default e.g. 365, `0` = keep forever).
- Reuse the **existing** `maintenance_fn` hook in `start_scheduler` (added for
  audit retention) — add a `purge_old_history()` alongside `purge_old_audit()`.
- Keeps the single-SQLite-file design honest; document the growth expectation.

### Tests
- A row is written per scan; a fingerprint change yields a new row (old kept).
- Retention purges rows older than the window; `0` disables.

---

## Slice 2 — Drift detection & alerting (cheap, given slice 1 + existing diff)

### What counts as drift
Classify changes between the previous and current leaf for a host:port:
issuer changed, SAN added/removed, key size dropped, signature algorithm
weakened (e.g. SHA-256 → SHA-1), TLS version downgraded, posture grade dropped,
chain replaced, unexpected re-issue (fingerprint changed with no `renewal_status
= renewed` signal).

### Implementation
- Promote `_compute_renewal_diff` from "log only" to returning a structured
  list of `{field, old, new, severity}` (it already computes the comparison).
- On a detected change, create an `Alert` with `alert_type="drift"` through the
  **existing** alert pipeline so it inherits delivery **and alert-group routing**
  (plan 015) — a drift on a `team-web`-tagged cert reaches the web team. Respect
  a `CERT_WATCH_DRIFT_ALERTS` toggle (default on) and the alert cooldown.
- Severity: posture-grade drop / key-size drop / SHA-1 / unexpected re-issue =
  high; benign renewal (same issuer, longer validity) = info (or suppressed).
- Surface drift events in the cert detail page (read from `cert_history`).

### Tests
- Issuer change → high-severity drift alert created.
- Benign renewal (same issuer, later `not_after`) → no high alert.
- Drift alert routes through alert groups (depends on plan 015).
- No change → no alert.

### AC
- AC-1: A re-scan that changes issuer/key/SAN/grade produces a drift alert.
- AC-2: Drift alerts honor the global toggle, cooldown, and group routing.

---

## Slice 3 — Trending (API; UI in Claude Design)

Serve time-series from `cert_history` as JSON; the dashboard charts are built
separately.

- `GET /api/certificates/{id}/history` → `[{scanned_at, not_after,
  days_until_expiry, posture_grade, protocol_version}, ...]`.
- `GET /api/trends/tls-versions` → fleet protocol-version distribution over
  time (for "TLS adoption across the fleet").
- `GET /api/trends/grades` → fleet posture-grade distribution over time.
- Authed via `_require_api_auth`; paginate/limit by date range.

### Tests
- History endpoint returns ordered series; range filter works; 404 for unknown
  cert; fleet aggregates count correctly.

---

## Slice 4 — Calendar / timeline view (cheap; no history needed)

A "cert calendar" of upcoming expirations grouped by day/week/month — the
first thing managers ask for. Pure current-state pivot.

- `GET /api/calendar?from=&to=&bucket=day|week|month` → buckets with cert
  counts + ids, computed from `certificates.not_after` (leaf only).
- UI (Claude Design) renders the calendar/timeline.

### Tests
- Bucketing by day/week/month; empty ranges; leaf-only.

---

## Sequencing
1. Slice 1 (history foundation + retention) — everything else depends on it,
   except slice 4 which can ship anytime.
2. Slice 2 (drift) — depends on slice 1 and benefits from plan 015 routing.
3. Slice 3 (trending) — depends on slice 1.
4. Slice 4 (calendar) — independent; can be done first as a quick win.

Docs: README features + API rows; AGENTS.md note; new env vars
(`CERT_WATCH_HISTORY_RETENTION_DAYS`, `CERT_WATCH_DRIFT_ALERTS`). Fix the
dangling `replaces_cert_id` lineage as part of slice 1/2.

## Risk notes
- Unbounded history is the only real risk; the retention purge + a documented
  growth estimate mitigate it. At one snapshot per host per daily scan, even
  thousands of hosts stay small in SQLite for a year.
- Slice 2 changes alert volume; ship behind the toggle and with the cooldown,
  and keep "benign renewal = no high alert" well tested to avoid noise.
