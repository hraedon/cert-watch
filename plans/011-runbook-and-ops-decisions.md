# Plan 011: Operator Runbook + Ops Decisions (Rollout Readiness Phases 5–6)

> Implements Plan 007 §Phase 5 and §Phase 6. Documentation + two deliberate
> exposure/scale decisions. Written once the behavior it describes (Plans
> 008–010) exists, so it can't drift from reality.

## Deliverable A — `docs/runbook.md` (Phase 5)

Aimed at whoever operates cert-watch at work:

- **Deploy + upgrade**, including the Plan 009 migration step (auto pre-migration
  backup, how to confirm `schema_version`).
- **Backup + restore** — the exact CI-tested Plan 009 procedure (`cert-watch
  backup`; stop → replace → start). Restore steps must match the tested path,
  no drift.
- **"A scan is failing"** — reading structured JSON logs, the scan-retry
  behavior, private-IP (`CERT_WATCH_ALLOW_PRIVATE_IPS`) and custom-DNS settings.
- **Config reference** — all env vars, with the secure-profile values (Plan 007
  §4.5) and the `*_FILE` secret convention called out.
- **Exposure summary** — the Phase 1 public-path list, the `/metrics` decision
  below, and which credentials live where.

## Deliverable B — Ops decisions (Phase 6)

- **`/metrics` exposure** — decide and document. Recommendation: keep open but
  state plainly that it leaks aggregate counts and **must be ingress-restricted**
  on the internal network; document how to put it behind auth/a scrape token if
  a reviewer requires it.
- **Scale ceiling** — document the single-writer SQLite envelope (rough
  host/scan volume it comfortably handles, WAL behavior) and the **explicit
  trigger** for revisiting Postgres/MSSQL (BC-031): fleet size, an HA
  requirement, or a multi-writer need. No code change — an honest-limits note so
  the rollout decision is informed.

## Acceptance criteria

Per 007 §5–6 (a reader can deploy/upgrade-with-migration/back-up/restore from
the runbook alone; restore steps match the tested procedure; the `/metrics`
decision and the scale ceiling + BC-031 trigger are both documented).

## Dependencies

Describes behavior delivered by Plans 008–010 — write last (or stub now, fill as
each lands).
