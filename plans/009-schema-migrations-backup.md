# Plan 009: Schema Migrations + Backup/Restore (Rollout Readiness Phase 3)

> Implements Plan 007 §Phase 3. Supersedes FEAT-006. Real data lands the moment
> this deploys; the next release *will* change the schema. A clean, tested
> upgrade-and-restore path is what keeps a populated production DB from becoming
> a manual-surgery liability.

## Goal

Versioned, forward-only migrations applied automatically and idempotently on
startup, plus a WAL-safe backup/restore procedure tested in CI.

## Design

- **Minimal in-repo runner over Alembic** (decide in a 1-hour spike, but the
  single-file / single-writer SQLite shape makes a hand-rolled runner the
  likely winner — Alembic's machinery doesn't earn its weight here).
- **`schema_version` table** records applied migration ids. Migrations are an
  ordered registry of `(id, apply_fn)` (or numbered `.sql` files).
- `init_schema` is refactored into **`ensure_base` + `run_pending_migrations`**.
  The existing ad-hoc `PRAGMA table_info` guards get folded into numbered
  migrations incrementally, starting with a **baseline migration `0001` that
  exactly snapshots today's schema** (so existing prod DBs reconcile cleanly).

## Implementation steps

1. **Spike** — minimal runner vs Alembic; record the call in the plan.
2. **`schema_version`** table + migration registry module.
3. **Baseline `0001`** = current schema; mark it already-applied for existing
   DBs (detect populated DB → stamp baseline rather than re-create).
4. **Refactor** `init_schema` → `ensure_base` + `run_pending_migrations`; route
   new schema changes (audit_log, App-Role/group columns, etc.) through
   numbered migrations from here on.
5. **Auto pre-migration backup** — timestamped copy / `VACUUM INTO` before
   applying any pending migration.
6. **Backup CLI** — `cert-watch backup <path>` using `VACUUM INTO` (WAL-safe,
   works while the app runs). Document restore: stop → replace file → start
   (k8s `Recreate` already serializes writers).

## Files

New `migrations/` module + registry, `schema.py` refactor, `__main__.py` /
CLI subcommand, `tests/test_migrations.py`.

## Acceptance criteria

Per 007 §3 AC-1…AC-5 (apply-on-old-DB idempotent; re-run no-op; auto pre-migration
backup produced; `cert-watch backup` restorable round-trip in CI; restore
procedure documented in the runbook).

## Risks

- **Baseline fidelity** — `0001` must match the deployed schema byte-for-byte in
  effect, or existing DBs will diverge. Mitigate with a schema-dump comparison
  test (fresh `ensure_base+migrate` vs baseline-stamped).
- Folding the `PRAGMA`-sniff guards without regressing existing-DB startup —
  do it incrementally, guard with tests against a pre-migration fixture DB.

## Dependencies

Plan 008's `audit_log` should land as the **first real migration** after the
baseline, exercising the runner end to end.
