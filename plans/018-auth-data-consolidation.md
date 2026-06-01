# Plan 018: Auth & Data-Layer Consolidation

> **Status:** ready for implementation. Grounded in the code as of `d57cd3b`
> (Plan 015 landed). Replaces and refines Plan 012 Phase 4 (structural
> cleanup) with concrete sequencing informed by a codebase-wide review.

## Why this exists

Three concerns surfaced during a structural review of the codebase:

1. **Auth wiring is scattered.** Module-level globals (`_signing_key`,
   `_csrf_secret_val`), manual auth checks duplicated across 25+ route
   handlers in three files, and Plan 014's kv_store branch re-introduced
   provider-assembly into the lifespan. The auth layer works correctly but
   is hard to modify and fragile to test.

2. **The "load everything" pattern keeps resurfacing.** Six past bugs
   (BC-044/047/048/050/052 and the dashboard pivot) were all the same
   problem: a query materializing the full table in Python. Targeted fixes
   addressed individual callers, but `_list_unified_entries_raw()` still
   exists and `evaluate_all_certs()` still opens N+1 DB connections for
   group routing.

3. **Test isolation is expensive.** The conftest `_isolated_data_dir` fixture
   (20 lines) reloads modules, sets env vars, calls `set_signing_key()` and
   `set_csrf_secret()`, and clears `needs_setup`. The `reload_app` fixture
   adds another reload cycle. Twelve test files depend on these patterns.

These are structural problems, not feature gaps. The features work. This plan
makes the codebase easier to extend safely.

---

## Sequencing rationale

The work splits into two phases with a deliberate boundary:

- **Phase A** (now): changes that touch feature code but not the test
  harness. Low blast radius, can land on top of in-flight feature branches
  without merge conflicts.
- **Phase B** (after current feature branches land): changes that touch the
  test harness and app initialization. Higher blast radius, needs a clean
  tree.

This sequencing comes from the observation that Plan 014 (onboarding),
Plan 015 (alert groups), and whatever comes next all edit the same test
files (conftest.py, test_auth.py, test_setup_bootstrap.py) that Phase B
must rewrite. Interleaving a test-harness refactor with active feature
branches is how you get merge hell and subtle auth regressions.

---

## Phase A — Low blast radius, do now

### A1. Fold kv_store into `build_auth_provider`

**Problem:** Plan 014 introduced a 40-line branch in `app.py` lifespan
(lines 106–146) that hand-calls `build_auth_provider()` with 20+ parameters
when kv_store provides local admin credentials that env vars don't. This
duplicates the logic in `Settings.build_auth_provider()` (`config.py:289`).

**Fix:** Move the kv_store fallback for `local_admin_user` and
`local_admin_password_hash` into `Settings.build_auth_provider()` (or
`Settings.from_env()`). The lifespan always calls
`s.build_auth_provider()` — one line, no branch.

Concretely: `Settings.build_auth_provider()` already reads
`self.local_admin_user` / `self.local_admin_password_hash`. Add a check:
if both are empty, consult `kv_get(self.db_path, "local_admin_user")` and
`kv_get(self.db_path, "local_admin_password_hash")` as fallbacks. This
mirrors what the lifespan does today.

The lifespan's kv_store branch (app.py:106–146) collapses to:

```python
auth = s.build_auth_provider()
```

**Files:** `config.py` (build_auth_provider method), `app.py` (remove
branch).

**Tests:** existing test_setup_bootstrap.py tests must stay green — they
verify kv_store local admin creation and subsequent auth provider
rebuild. The lifespan behavior is unchanged; only the code location
moves.

**AC:** AC-1: `/setup` wizard still creates a working local admin that
survives a reload. AC-2: `s.build_auth_provider()` returns a provider
with kv_store-sourced local admin when env vars are unset.

---

### A2. Batch group-recipient resolver

**Problem:** `evaluate_all_certs()` (`alerts.py:176`) calls
`resolve_group_recipients()` per leaf cert. Each call opens a DB
connection, queries groups, computes effective tags via SQL join, and
matches in Python. For N certs × G groups this is N+1 queries per
evaluation cycle. Fine today (hundreds of certs, few groups); a latent
scaling issue.

**Fix:** Replace the per-cert resolver with a batch version:

```python
def resolve_all_group_recipients(
    db_path: str | Path,
) -> dict[str, list[str]]:
    """Return {cert_id: [recipients]} for all leaf certs in one pass.

    Queries:
    1. All groups (name, id, match_tags, recipients) — one query.
    2. All leaf cert effective tags — one query joining certificates
       with hosts, returning (cert_id, cert_tags, host_tags).
    3. All manual assignments — one query on alert_group_certs.

    Matches in Python. Returns dict keyed by cert_id.
    """
```

Three queries instead of N+1. `evaluate_all_certs()` calls the batch
resolver once, then looks up recipients by cert_id in the loop.

Keep `resolve_group_recipients()` (single-cert) for the
`/api/certificates/{id}/alert-routing` preview endpoint — it's fine for
single-cert lookups.

**Files:** `alerts.py` (new `resolve_all_group_recipients`), update
`evaluate_all_certs()`.

**Tests:** existing test_alert_groups.py routing tests must stay green.
Add a test that the batch resolver returns the same results as
per-cert resolution for a multi-cert scenario.

**AC:** AC-3: `evaluate_all_certs()` makes ≤3 DB queries regardless of
cert count. AC-4: routing results are identical to per-cert resolution.

---

### A3. `Depends(require_auth)` / `Depends(require_write)` sweep

**Problem:** Auth is checked manually in 25+ route handlers across three
files: `api.py` (21 call sites using `_require_api_auth` /
`_require_api_write`), `certificates.py` (inline checks at lines
279–281, 302, 320, 349, 396, 442), and `hosts.py` (inline checks at
lines 117, 177, 300, 316, 365–367). Each is a copy of the same pattern:
check NoAuthProvider, validate session cookie, return 401 or call
check_csrf.

**Fix:** Create FastAPI dependencies in `middleware.py` (or a new
`deps.py`):

```python
async def require_auth(request: Request) -> str:
    """FastAPI dependency. Returns username or raises 401.

    Returns "" (not 401) under NoAuthProvider so the "auth disabled
    = open" contract survives.
    """
    auth = getattr(request.app.state, "auth_provider", None)
    if auth is None or isinstance(auth, NoAuthProvider):
        return ""
    token = request.cookies.get(SESSION_COOKIE, "")
    username = validate_session(token)
    if not username:
        raise HTTPException(status_code=401, detail="unauthenticated")
    return username


async def require_write(request: Request) -> str:
    """Auth + CSRF. Returns username or raises 401/403."""
    username = await require_auth(request)
    csrf_err = await check_csrf(request)
    if csrf_err:
        raise HTTPException(status_code=403, detail=csrf_err)
    return username
```

Migrate all handlers to use `Depends(require_auth)` or
`Depends(require_write)` instead of manual checks. Remove
`_require_api_auth` and `_require_api_write` from `api.py`.

The middleware stays as a safety net for UI routes (redirect to login).
Route-level dependencies are defense-in-depth for API routes.

**Critical invariant:** `require_auth` returns `""` (not 401) when auth
is disabled via `NoAuthProvider`. Every existing test asserting "auth off
= open" must stay green. The `Depends` version must behave identically
to the manual checks it replaces.

**Files:** new `middleware.py` section or `deps.py`, `routes/api.py`,
`routes/certificates.py`, `routes/hosts.py`.

**Tests:** all existing API auth tests must stay green. The sweep is
mechanical — same behavior, different syntax. No new acceptance criteria
beyond "everything still passes."

**AC:** AC-5: all `/api/*` routes return 401 without valid session when
auth is enabled. AC-6: all `/api/*` routes return 200 when auth is
disabled. AC-7: mutating endpoints return 403 on missing/invalid CSRF.
AC-8: `_require_api_auth` and `_require_api_write` are deleted; no
manual auth checks remain in route handlers.

---

## Phase B — Dedicated PR, after feature branches land

### B1. SecurityContext + create_app factory + test-fixture migration

> These three are one atomic change. Doing any one without the others is
> half a refactor.

**Problem:** Auth cryptographic state lives in two module-level globals:

- `auth.py:30` — `_signing_key = read_secret("CERT_WATCH_AUTH_SECRET") or
  secrets.token_hex(32)`
- `middleware.py:27` — `_csrf_secret_val = os.environ.get(...) or
  secrets.token_hex(32)`

Both are initialized at import time and mutated at lifespan startup via
`set_signing_key()` / `set_csrf_secret()`. Tests must call these setters
in the right order after module reloads. The conftest
`_isolated_data_dir` fixture (20 lines) and `reload_app` fixture (15
lines) exist primarily to manage this state.

**Fix — three parts, one PR:**

#### Part 1: SecurityContext dataclass

```python
@dataclass
class SecurityContext:
    signing_key: str
    csrf_secret: str
```

Created once in the lifespan, stored on `app.state.security`. All
sign/verify/make_csrf_token functions accept a `SecurityContext`
parameter instead of reading module globals. The module-level defaults
become fallbacks only (for the case where lifespan hasn't run).

Thread the context through these call sites:
- `auth.py:46/56/66/86` — `hmac.new(_signing_key, ...)`
- `middleware.py:43/53` — `hmac.new(_CSRF_SECRET, ...)`
- `validate_session()`, `make_session_token()`, `make_csrf_token()`,
  `validate_csrf_token()`

Each gains a `security: SecurityContext | None = None` parameter;
when None, falls back to the module global (backward compat for any
callers not yet migrated).

#### Part 2: create_app() factory

```python
def create_app(
    *,
    security: SecurityContext,
    auth_provider: AuthProvider,
    settings: Settings,
) -> FastAPI:
    """Construct and configure the FastAPI application."""
```

Replaces the current pattern where `app.py` creates a module-level
`app = FastAPI(...)` and the lifespan attaches state to it. The factory
takes all dependencies as explicit parameters. The lifespan becomes a
thin wrapper that constructs the dependencies and calls `create_app()`.

The module-level `app` still exists for backward compat (uvicorn
imports it), but it's constructed by calling `create_app()` with
defaults.

#### Part 3: Test-fixture migration

Replace the `reload_app` / `_isolated_data_dir` patterns with:

```python
@pytest.fixture
def app(tmp_path):
    """Construct a test app with isolated data dir and no auth."""
    from cert_watch.app import create_app
    from cert_watch.auth import NoAuthProvider
    from cert_watch.config import Settings
    from cert_watch.middleware import SecurityContext

    settings = Settings(db_path=tmp_path / "cert-watch.sqlite3", ...)
    security = SecurityContext(signing_key="test-key", csrf_secret="test-csrf")
    auth = NoAuthProvider()
    return create_app(security=security, auth_provider=auth, settings=settings)
```

No module reloading. No monkeypatching globals. No `set_signing_key()`.
Each test gets a fresh app instance with injected dependencies.

The conftest `_isolated_data_dir` fixture shrinks to setting
`CERT_WATCH_DATA_DIR` and calling `init_schema`. The `reload_app`
fixture becomes `create_test_app` — a function that constructs an app
with specific config overrides.

**Migration strategy:** Move test files one at a time. Each file that
currently uses `reload_app` gets updated to use the new `app` fixture.
Run the full suite after each file migration. The old fixtures stay
until all files are migrated, then get deleted.

**Files touched:** `auth.py`, `middleware.py`, `app.py`,
`conftest.py`, and all 12 test files that use `reload_app` or the
module-global app.

**Risk:** This is the security path. A "purely structural" refactor here
can still regress:
- "auth off = open" passthrough (NoAuthProvider → return "")
- 401-for-API vs redirect-for-UI split
- CSRF-on-mutation ordering
- Existence-check-vs-auth-check order (info leak on 404 vs 401)

Mitigation: land behind the full existing auth test suite green. Migrate
test files in lockstep with the code changes — don't do the code change
first and tests later.

**AC:** AC-9: no module-level `_signing_key` or `_csrf_secret_val`
mutations in production code paths (lifespan uses SecurityContext on
app.state). AC-10: `reload_app` fixture is deleted; all tests use
`create_test_app` or the new `app` fixture. AC-11: full test suite
passes without module reloading in conftest.

---

### B2. Purpose-built dashboard queries

**Problem:** `_list_unified_entries_raw()` (`queries.py:606`) loads all
certificates, all hosts, all scan_posture rows, and all scan_history
rows into Python, then merges them. It's the foundation for the
dashboard (both grouped and ungrouped), and the callers that were
already fixed (healthz, metrics, pivot views) each implemented their
own targeted query. The remaining callers still go through the
materialize-everything path.

**Fix:** Replace `_list_unified_entries_raw()` callers one at a time
with purpose-built SQL queries:

| Caller | Current behavior | Target |
|--------|-----------------|--------|
| Dashboard (ungrouped) | `list_unified_entries_page()` materializes all, filters/sorts/paginates in Python | SQL query with WHERE + ORDER BY + LIMIT + OFFSET |
| Dashboard (grouped) | Same + `group_entries_by_fingerprint()` in memory | SQL GROUP BY with aggregate subquery for host count + worst urgency |
| CSV export | `list_dashboard_rows()` loads all | Acceptable (export needs all rows), but use cursor iteration |
| Cert detail | `list_unified_entries()` loads all to find one | `get_cert_detail(cert_id)` — targeted JOIN |

New query methods in `queries.py`:

```python
def list_dashboard_page(
    db_path, *, urgency=None, source=None, sort="expiry",
    page=1, per_page=50,
) -> tuple[list[dict], int]:
    """SQL-level filtered, sorted, paginated dashboard rows."""

def list_dashboard_grouped_page(
    db_path, *, sort="expiry", page=1, per_page=50,
) -> tuple[list[dict], int]:
    """SQL-level grouped dashboard with host count + worst urgency."""

def get_cert_detail(db_path, cert_id) -> dict | None:
    """Single cert with chain, posture, and host context."""
```

`_list_unified_entries_raw()` stays as a compatibility shim until all
callers migrate, then gets deleted. `list_unified_entries()` and
`list_unified_entries_page()` become thin wrappers that call the new
methods during the transition.

**Files:** `database/queries.py`, `routes/views.py`, `routes/api.py`.

**Tests:** existing dashboard tests must render identically. Add tests
for each new query method (correct filtering, sorting, pagination,
empty results).

**AC:** AC-12: dashboard renders identically using new query methods.
AC-13: `_list_unified_entries_raw()` is deleted (or reduced to a
deprecated wrapper). AC-14: no caller materializes the full
certificates table except CSV export.

---

## What this plan deliberately does NOT cover

- **BC-031 (PostgreSQL/MSSQL).** The SQLite abstraction is a separate,
  larger concern. This plan makes the data access patterns cleaner, which
  makes a future database backend swap easier, but does not attempt it.

- **Alert retention purge (Plan 002 WI-1).** The `alerts` table still
  grows unbounded. This is a separate concern (a scheduler change, not a
  structural refactor).

- **Health banner in UI (Plan 012 Phase 2.1).** UI feature, not
  structural cleanup.

- **Documentation updates.** README "First run" section, alert groups
  docs, troubleshooting guide. These are tracked in Plan 012 Phase 5
  and should be done separately.

---

## Sequencing

```
Phase A (now, low blast radius):
  ├── A1  fold kv_store into build_auth_provider  (config.py, app.py)
  ├── A2  batch group-recipient resolver           (alerts.py)
  └── A3  Depends(require_auth) sweep              (middleware.py, routes/*.py)

Phase B (later, dedicated PR, after feature branches land):
  ├── B1  SecurityContext + create_app + test fixtures  (auth.py, middleware.py,
  │       app.py, conftest.py, 12 test files)
  └── B2  purpose-built dashboard queries                (queries.py, views.py)
```

A1 and A2 are independent — they can be done in either order or in
parallel. A3 depends on A1 only in the sense that it's cleaner to do
the Depends sweep after the lifespan is simplified.

B1 and B2 are independent of each other but both depend on the feature
branches being stable. B1 is the higher-risk change (security path +
test harness rewrite) and should be reviewed carefully. B2 is
lower-risk (data access only, no auth surface).

---

## Acceptance criteria

### Phase A
- AC-1: `/setup` wizard creates a working local admin; lifespan calls
  `s.build_auth_provider()` with no kv_store branch.
- AC-2: `evaluate_all_certs()` makes ≤3 DB queries regardless of cert
  count; routing results identical to per-cert resolution.
- AC-3: `_require_api_auth` and `_require_api_write` are deleted; all
  API routes use `Depends(require_auth)` or `Depends(require_write)`.
- AC-4: full test suite green after each slice.

### Phase B
- AC-5: no module-level signing key / CSRF secret mutations in
  production code paths.
- AC-6: `reload_app` fixture deleted; all tests use dependency
  injection.
- AC-7: `_list_unified_entries_raw()` deleted; dashboard uses
  purpose-built SQL queries.
- AC-8: full test suite green after each slice.
