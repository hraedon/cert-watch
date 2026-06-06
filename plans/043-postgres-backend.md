# Plan 043 — Postgres Backend (BC-031)

**Status:** proposed 2026-06-06
**Author:** Opus 4.8 (portfolio review)
**Strategic role:** The biggest remaining structural blocker for horizontal scaling. The repository pattern is already in place; this plan adds a `Postgres` implementation of the repositories.

## Why now

The codebase is built with a clean repository pattern (`SqliteCertificateRepository`, `SqliteHostRepository`, etc.) and SQL-level query modules (`database/dashboard.py`, `database/repo.py`). However, the `sqlite3`-specific connection factory and `Row` factory usage leak into the routes. This plan:
- Introduces a `ConnectionFactory` abstraction.
- Implements `PostgresCertificateRepository`, `PostgresHostRepository`, etc.
- Adds `psycopg` (optional extra) and keeps SQLite as the default.
- Enables multi-writer deployments and drops the `Recreate` k8s rollout strategy.

## Scope

### WI-1 — Connection factory abstraction
- `cert_watch.database.connection` module gains a `ConnectionFactory` protocol:
  - `connect() -> Connection` (returns either `sqlite3.Connection` or `psycopg.Connection`).
  - `init() -> None` — runs schema creation / migrations.
  - `close() -> None`.
- `SqliteConnectionFactory` implements the protocol using the existing `sqlite3` path.
- `PostgresConnectionFactory` implements the protocol using `psycopg` (connect string from `CERT_WATCH_POSTGRES_DSN` or `DATABASE_URL`).
- The `Settings` dataclass gains `db_backend` (`sqlite` | `postgres`, default `sqlite`) and `postgres_dsn`.

### WI-2 — SQL dialect compatibility layer
- `cert_watch.database.dialect` module:
  - `DUCK` dataclass with `placeholder` (`?` vs `%s`), `lastrowid`, `row_factory`, `upsert`, `json`, `auto_increment`, `now`.
  - `sqlite_dialect` and `postgres_dialect` constants.
  - `param(n)` helper returns `?` or `$1`...`$n`.
  - `upsert(table, cols, conflict)` helper returns `INSERT OR REPLACE` or `INSERT ... ON CONFLICT ... DO UPDATE`.
- All SQL strings in `database/repo.py`, `database/dashboard.py`, etc. are parameterized through the dialect layer.

### WI-3 — Postgres repository implementations
- `PostgresCertificateRepository`, `PostgresHostRepository`, `PostgresAlertRepository`, `PostgresAlertGroupRepository`, `PostgresTrustAnchorRepository`:
  - Mirror the SQLite repositories exactly (same public methods, same return types).
  - Use `psycopg` with server-side cursors for large result sets.
  - Handle `UUID` primary keys where SQLite uses `TEXT` (use `gen_random_uuid()` in Postgres).
- Migration runner `database/migrations/runner.py` gains a `PostgresMigrationRunner` that applies `.sql` files using `psycopg` transactions.

### WI-4 — Dashboard query porting
- `database/dashboard.py` queries are the most complex SQL in the codebase.
  - Port `list_dashboard_page()` to use Postgres `LIMIT`/`OFFSET` with window functions for host counts.
  - Port `list_dashboard_grouped_page()` to use `GROUP BY` + `array_agg` for fingerprint grouping.
  - Port `list_unified_entries()` to use `EXISTS` subqueries (already the SQLite approach; Postgres optimizes these well).
- Return plain dicts (no `sqlite3.Row` leaks) — this discipline already exists in the codebase and is maintained.

### WI-5 — App factory and deployment updates
- `app.create_app()` accepts `connection_factory: ConnectionFactory | None`.
- `config.py` resolves the factory from env: if `CERT_WATCH_DB_BACKEND=postgres`, use `PostgresConnectionFactory`.
- `deploy/k8s/` adds an optional `postgres` StatefulSet and `ConfigMap` for the DSN.
- `deploy/docker-compose.yml` adds an optional `postgres` service.
- The `Recreate` rollout strategy in k8s is relaxed to `RollingUpdate` when Postgres is configured.

### WI-6 — CI and testing
- Add a `postgres` service to the GitHub Actions workflow (or docker-compose in CI).
- Run the full test suite against both SQLite and Postgres backends.
- The default local dev remains SQLite (no Docker required for unit tests).

## Acceptance

- The app starts and serves the dashboard with `CERT_WATCH_DB_BACKEND=postgres` and a valid DSN.
- All CRUD operations (host add, cert scan, alert create, settings save) work identically on Postgres.
- The scheduler scan+alert cycle runs without SQLite locking issues.
- Migration runner applies all 0014 migrations cleanly on a fresh Postgres DB.
- Unit tests pass with `pytest --db-backend=postgres` (or a similar opt-in flag).
- 0 lint errors; full suite passes on both backends.

## Non-goals

- MySQL / MSSQL backends; Postgres is the only target in this plan.
- Connection pooling (psycopg 3 has built-in pooling; we use it lightly in v1).
- Read replicas / query splitting; single-primary Postgres is sufficient.
- Multi-tenant schema isolation; the app is single-tenant.
- Changing the SQLite backend behavior; SQLite remains the default and is untouched.
