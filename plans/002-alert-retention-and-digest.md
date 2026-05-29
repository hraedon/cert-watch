# Plan 002 — Alert Retention and Digest

**Status:** proposed 2026-05-28
**Author:** Opus 4.8 (portfolio review)
**Strategic role:** Smallest track of the 3-week grant plan. cert-watch is a
finished, deployed real tool and the stable comparison baseline for the sf2
factory experiment. It should stay in maintenance mode; this plan covers the
only v0.4-backlog item that is a genuine operational bug plus one small,
high-utility feature. Everything else in the v0.4 backlog is demand-driven.

## Why only this

The roadmap (`001-cert-watch-roadmap.md`) v0.4 backlog lists auth (already
implemented per README), JKS (no demand — skip), dashboard pagination (fine at
current scale), multi-host scheduler/leader election (only needed if scaled
horizontally — not yet), and alert-history cleanup. Of these, **alert-history
growth is the only unbounded-resource bug** — sent/failed alert rows accumulate
forever in the single-file SQLite DB. The rest is gold-plating absent real load.

The one feature worth adding because it materially improves the tool's actual
job (telling a human a cert is expiring): a **daily digest** so operators get
one summarizing email instead of relying on per-cert threshold crossings.

## Scope

### WI-1 — Alert retention
- Add a retention policy: delete `alerts` rows older than a configurable window
  (`CERT_WATCH_ALERT_RETENTION_DAYS`, default 90).
- Run the cleanup from the existing daily scheduler loop (`scheduler.py`), in the
  same transaction discipline as `replace_scanned()`.
- Keep it idempotent and safe on legacy DBs (follow the existing `init_schema`
  idempotency pattern that already guards against CrashLoopBackOff on old DBs).

### WI-2 — Daily expiry digest
- After the daily scan, compose one digest of certs crossing any configured
  threshold (grouped by host, color-coded like the dashboard), and send it via
  the existing SMTP + webhook alert paths.
- Gate behind `CERT_WATCH_DIGEST_ENABLED` (default off so behavior is unchanged
  for current deployers); honor existing per-host `threshold_days`.
- Reuse `humanize_expiry` and the existing alert delivery code; no new transport.

## Acceptance

- Alert rows older than the retention window are pruned on the daily cycle;
  unit test with seeded old/new rows; safe on a legacy DB fixture.
- With digest enabled and SMTP/webhook configured, a single daily digest is sent
  listing all threshold-crossing certs; with it disabled, behavior is identical
  to today.
- 0 lint errors; tests pass; no change to the dashboard or scan paths.

## Non-goals

- JKS support, dashboard pagination, Postgres backend, leader election,
  horizontal scaling. All demand-driven; do not pull in.
- Anything that changes cert-watch's behavior as the sf2 comparison baseline.
  Keep the spec-visible surface stable so the factory experiment stays clean.
