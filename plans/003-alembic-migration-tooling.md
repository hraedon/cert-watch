# FEAT-006: Database Migration Tooling (Alembic)

**Status:** draft
**Prerequisite for:** BC-031 (PostgreSQL/MSSQL support)
**Created:** 2026-05-29

---

## Problem

`init_schema()` in `database/schema.py` handles all schema creation and migration via ad-hoc `ALTER TABLE ... ADD COLUMN` gated by `PRAGMA table_info` checks. Eight migrations have accumulated. There is no versioning, no downgrade path, no audit trail, and no way to run data migrations. This blocks BC-031 (multi-database support) because the migration logic is SQLite-only.

## Approach

Introduce **SQLAlchemy Core** `Table` definitions and **Alembic** for migration management. Keep SQLite as the default and only required backend. The migration tooling is transparent to existing callers — `init_schema()` becomes a thin wrapper around Alembic's `upgrade head`.

### Why not full SQLAlchemy ORM?

The codebase uses raw SQL via `sqlite3` throughout `repo.py` and `queries.py`. Replacing all of that with ORM queries is a separate refactor (BC-031's territory). For FEAT-006, we only need SQLAlchemy Core `Table` objects so Alembic can auto-generate migrations. The repositories continue using raw SQL — they just get their connection from SQLAlchemy instead of `sqlite3.connect()`.

---

## Implementation Plan

### Phase 1: Add SQLAlchemy + Alembic dependencies

**Files changed:** `pyproject.toml`

1. Add `sqlalchemy>=2.0` to core dependencies (not optional — it becomes the migration engine).
2. Add `alembic>=1.13` to core dependencies.
3. Run `uv pip install -e ".[dev]"` and verify no conflicts.

### Phase 2: Define SQLAlchemy Table metadata

**New file:** `src/cert_watch/database/tables.py`

1. Create a `MetaData` object and define `Table` definitions for all 5 tables:
   - `certificates`
   - `alerts`
   - `scan_history`
   - `hosts`
   - `trust_anchors`
2. Column definitions must match the current DDL in `schema.py` exactly — same names, types, defaults, nullable, unique constraints.
3. Define all indexes (idx_cert_fp, idx_cert_parent, idx_cert_replaces, idx_alert_cert, idx_alert_status, ux_hosts_hostname_port) as `Index` objects on the metadata.
4. Export `metadata` and all table objects.

Types mapping:
| SQLite DDL | SQLAlchemy type |
|---|---|
| `TEXT` | `String` |
| `INTEGER` | `Integer` |
| `BLOB` | `LargeBinary` |
| `TEXT NOT NULL DEFAULT 'x'` | `String, nullable=False, server_default='x'` |
| `TEXT PRIMARY KEY` | `String, primary_key=True` |

### Phase 3: Initialize Alembic

**New directory:** `alembic/` (project root, alongside `src/`)

1. Run `alembic init alembic` to create the standard Alembic directory structure.
2. Configure `alembic.ini`:
   - `sqlalchemy.url` set to a sensible default SQLite path (overridden at runtime via `env.py`).
   - `script_location = alembic`.
3. Edit `alembic/env.py`:
   - Import `metadata` from `cert_watch.database.tables`.
   - Set `target_metadata = metadata`.
   - Read `DATABASE_URL` from environment (or fall back to `CERT_WATCH_DATA_DIR`-based path).
   - Configure `render_as_batch=True` for SQLite batch mode support.
   - Add `from alembic import context` and wire `run_migrations()` correctly.

### Phase 4: Create the initial migration (baseline)

1. Run `alembic revision --autogenerate -m "baseline"` to produce the initial migration capturing all 5 tables + indexes.
2. Review the generated migration to ensure it matches the current schema exactly.
3. This migration represents the **full current schema** — fresh installs run it from empty, existing databases get stamped.

### Phase 5: Replace `init_schema()` with Alembic

**File changed:** `src/cert_watch/database/schema.py`

1. Replace the body of `init_schema()`:
   ```python
   def init_schema(db_path: str | Path) -> None:
       from alembic.config import Config
       from alembic import command
       path_str = str(Path(db_path))
       if path_str in _initialized_paths:
           return
       Path(db_path).parent.mkdir(parents=True, exist_ok=True)
       cfg = Config()
       cfg.set_main_option("script_location", "alembic")
       cfg.set_main_option("sqlalchemy.url", f"sqlite:///{path_str}")
       command.upgrade(cfg, "head")
       _initialized_paths.add(path_str)
   ```
2. Keep `_TABLES_SCHEMA` and `_INDEXES_SCHEMA` as module-level constants for reference (and for the test that asserts DDL strings exist), but mark them as deprecated.
3. Remove all `ALTER TABLE ... ADD COLUMN` migration blocks.
4. Remove the `PRAGMA table_info` checks.
5. Keep `_initialized_paths` caching for performance (avoids running Alembic on every repo construction).

### Phase 6: Handle existing databases (stamp)

When an existing database already has all tables, Alembic needs to know it's at the latest revision without running DDL.

In `init_schema()`:
1. Check if the database file exists and has tables.
2. If it does AND there's no `alembic_version` table, run `command.stamp(cfg, "head")` before `upgrade`.
3. If `alembic_version` already exists, just run `upgrade` (no-op if at head).

### Phase 7: Make Alembic discoverable at runtime

**Problem:** Alembic's `script_location` is relative to the working directory. When cert-watch is installed as a package, the alembic directory may not be in CWD.

**Solution:**
1. Use `importlib.resources` (or `__file__`-relative path) in `env.py` and `init_schema()` to resolve the alembic directory relative to the package installation:
   ```python
   _ALEMBIC_DIR = str(Path(__file__).resolve().parent.parent.parent.parent / "alembic")
   ```
2. Alternatively, move the `alembic/` directory into `src/cert_watch/alembic/` so it ships with the package. This is cleaner for installed packages.
3. **Recommended approach:** Place alembic at project root but configure `init_schema()` to use `pkg_resources` or `importlib.resources` to find it. If not found (e.g. editable install), fall back to `Path(__file__).parent.parent.parent.parent / "alembic"`.

### Phase 8: Update tests

**Files changed:** `tests/test_database.py`, possibly other test files

1. `test_init_schema_idempotent` — update to verify Alembic stamp works. Calling `init_schema()` twice should still be a no-op.
2. `test_init_schema_migrates_old_database_without_replaces_cert_id` — this test creates a legacy DB and runs `init_schema()`. It should still pass because `stamp + upgrade` handles the "tables exist but no alembic_version" case.
3. Add a new test: `test_fresh_db_has_alembic_version` — verify that `init_schema()` on a fresh DB creates the `alembic_version` table with a valid revision.
4. Add a new test: `test_existing_db_gets_stamped` — create tables manually (no alembic_version), call `init_schema()`, verify `alembic_version` row exists.
5. Add a new test: `test_migration_upgrade_downgrade` — verify a migration can run upgrade and downgrade (basic Alembic health check).
6. Ensure all 246 existing tests still pass.

### Phase 9: Add a CLI command for migrations

**File changed:** `src/cert_watch/__main__.py` (or new `src/cert_watch/cli_migrate.py`)

1. Add `cert-watch migrate` subcommand that runs Alembic upgrade/downgrade/stamp.
2. Usage:
   - `cert-watch migrate upgrade [revision]` — default `head`
   - `cert-watch migrate downgrade [revision]` — one revision back, or specify
   - `cert-watch migrate stamp [revision]` — mark DB as at a given revision
   - `cert-watch migrate current` — show current revision
   - `cert-watch migrate history` — show migration history
3. This is useful for operators who want to run migrations outside of app startup.

### Phase 10: Update documentation and AGENTS.md

**Files changed:** `AGENTS.md`, `README.md` (if it exists)

1. Update AGENTS.md to mention Alembic:
   - How to create a new migration: `alembic revision --autogenerate -m "description"`
   - How to run migrations: `cert-watch migrate upgrade head`
   - Migration files live in `alembic/versions/`
2. Update the "Architecture notes" section to reflect the new migration system.

---

## File inventory

| Action | Path |
|---|---|
| Modify | `pyproject.toml` — add sqlalchemy, alembic deps |
| Create | `src/cert_watch/database/tables.py` — SQLAlchemy Table definitions |
| Modify | `src/cert_watch/database/schema.py` — replace init_schema with Alembic |
| Create | `alembic.ini` — Alembic config |
| Create | `alembic/env.py` — Alembic environment |
| Create | `alembic/versions/001_baseline.py` — initial migration |
| Create | `alembic/script.py.mako` — migration template |
| Modify | `src/cert_watch/__main__.py` — add migrate subcommand |
| Modify | `tests/test_database.py` — update migration tests, add new tests |
| Modify | `AGENTS.md` — document migration workflow |

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Existing deployments break if `init_schema()` changes behavior | Phase 6 handles stamping existing DBs; `upgrade head` is a no-op when already current |
| Alembic directory not found when installed as package | Phase 7 addresses discoverability; editable installs work via relative path |
| Batch mode limitations on SQLite (can't ALTER some things) | Alembic's batch mode recreates tables behind the scenes; test thoroughly |
| Performance regression on startup | `_initialized_paths` cache prevents re-running Alembic; first run is similar to current `executescript` |
| Schema drift between Table definitions and actual DDL | Auto-generated migrations catch drift; CI should run `alembic check` (or compare) |

## Success criteria

- [ ] All 246+ existing tests pass without modification to their assertions
- [ ] `init_schema()` on a fresh DB creates all tables with correct columns
- [ ] `init_schema()` on an existing (pre-Alembic) DB stamps and upgrades correctly
- [ ] `init_schema()` is idempotent (safe to call multiple times)
- [ ] A new column can be added via Alembic migration (not ALTER TABLE in schema.py)
- [ ] `cert-watch migrate upgrade head` works as a standalone CLI command
- [ ] `ruff check` and `pytest` both pass clean
