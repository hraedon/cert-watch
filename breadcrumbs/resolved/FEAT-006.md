---
identifier: FEAT-006
title: Database migration tooling (alembic)
kind: feature
status: resolved
severity: low
---

**Resolved:** 2026-05-30

## Problem

Schema migrations are currently handled by ad-hoc `ALTER TABLE ... ADD COLUMN` statements in `init_schema()`. This approach has accumulated 8 migrations and is becoming fragile:

- Migrations are not versioned or reversible — there's no `downgrade` path.
- Column additions use `IF NOT EXISTS`-style checks that depend on `PRAGMA table_info`, which is SQLite-specific.
- As the schema grows (owner fields, renewal status, future indexes), the migration function will become a maintenance liability. Adding a column that needs a default or a data migration (e.g. backfilling `renewal_status` from a computed value) is awkward.
- Multi-database support (BC-031) is blocked because there's no way to apply migrations portably.

## Suggested fix

1. Introduce Alembic with auto-generated migrations from SQLAlchemy models.
2. Define the schema as SQLAlchemy `Table` objects or declarative models alongside the current `database.py` DDL strings (or replace the DDL strings).
3. `init_schema()` should check the current Alembic revision and stamp it rather than running raw DDL.
4. Keep SQLite as the default — Alembic supports SQLite's limited ALTER TABLE via batch operations.
5. This is a prerequisite for BC-031 (multi-database support).

## Resolution (2026-05-30)

Resolved by Plan 009: implemented a minimal in-repo migration runner instead of Alembic. The single-SQLite-file, single-writer deployment shape made Alembic overkill — a hand-rolled runner with `schema_version` table, numbered `m000X_*.py` migrations, and `run_pending_migrations()` is sufficient. The runner auto-stamps the baseline for existing DBs, creates pre-migration backups via `VACUUM INTO`, and supports the `cert-watch backup` CLI subcommand. See `src/cert_watch/migrations/` and Plan 009 for details.
