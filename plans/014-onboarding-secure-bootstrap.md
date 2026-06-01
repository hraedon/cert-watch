# Plan 014: Onboarding & Secure Bootstrap

> **Status:** ready for implementation. Supersedes/implements **Plan 012 Phase
> 1**. Self-contained: a developer should be able to implement this without
> further design input. Grounded in the code as of commit `881cbe8`.

## Goal

A fresh install is **safe and usable without reading docs**: signing keys
persist across restarts, a first-run wizard stands up a local admin + first
host, and an operator who forgets to configure auth is warned loudly.

## Why this matters here

On k8s the secrets come from a Secret (already wired in `deploy/k8s`), but a
bare `docker run` / Windows-IIS / Compose install today gets **ephemeral**
signing keys — every restart logs everyone out. The setup wizard also makes
local-admin auth reachable without the `cert-watch hash-password` CLI dance.

---

## Slice 1 — Persisted signing keys (do first; highest leverage)

### The gotcha (read before coding)

Both keys are initialized at **module import time**, before the app lifespan
runs and before `Settings` is read:

- `auth.py:30` — `_signing_key = read_secret("CERT_WATCH_AUTH_SECRET") or None`,
  then falls back to `secrets.token_hex(32)`.
- `middleware.py:27` — `_csrf_secret_val = os.environ.get("CERT_WATCH_CSRF_SECRET") or None`,
  then `secrets.token_hex(32)`.

Both are read at **call time** by the sign/verify functions (`middleware.py:36/46`,
the session signer in `auth.py`), so **re-assigning the module globals during
lifespan startup is safe** as long as it happens before the first request.

### Changes

1. **`config.py`** — add a helper (mirrors the existing `read_secret`):
   ```python
   def resolve_or_persist_secret(env_name: str, data_dir: Path, filename: str) -> str:
       """Return env/_FILE secret if set (treating empty/whitespace as unset);
       else read data_dir/filename; else generate 32-byte hex, persist 0600, return it."""
   ```
   - Treat empty/whitespace-only as unset (closes **BC-054**).
   - Persist with `0o600` (best-effort on Windows; rely on dir ACLs there).
   - Log INFO on generate, WARNING when using a persisted key with no env var
     (so operators know they *can* pin it).

2. **`auth.py`** — add `set_signing_key(value: str) -> None` that assigns the
   module global `_signing_key`. (Keep the import-time default as the dev/test
   fallback.)

3. **`middleware.py`** — add `set_csrf_secret(value: str) -> None` assigning
   `_CSRF_SECRET` (and `_csrf_secret_val`). Derive CSRF from the auth secret
   when `CERT_WATCH_CSRF_SECRET` is unset (HKDF or `hashlib.sha256(auth+b"csrf")`).

4. **`app.py` lifespan** (before `start_scheduler`, after `init_schema`):
   ```python
   auth_secret = resolve_or_persist_secret("CERT_WATCH_AUTH_SECRET", s.data_dir, ".auth_secret")
   set_signing_key(auth_secret)
   csrf_secret = os.environ.get("CERT_WATCH_CSRF_SECRET") or _derive(auth_secret)
   set_csrf_secret(csrf_secret)
   ```

### Tests (`tests/test_secrets_bootstrap.py`)
- Generates + persists when unset; second call reads the same value back.
- Empty string / whitespace treated as unset.
- Explicit env var takes precedence over the persisted file.
- `set_signing_key` / `set_csrf_secret` actually change sign/verify output.

### AC
- AC-1: Fresh install, no env → key generated, persisted, **survives restart**
  (sessions stay valid across a process bounce).
- AC-2: `CERT_WATCH_AUTH_SECRET=""` is treated as unset.

---

## Slice 2 — `kv_store` table + local admin without CLI

The wizard must create a local admin **without** the operator setting env vars.
Today local admin comes only from `CERT_WATCH_LOCAL_ADMIN_USER` /
`CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH` (`config.py:211-212`, consumed by
`build_auth_provider` → `LocalAdminProvider` at `auth.py:746`). We add a DB
fallback.

### Schema — migration 0007 (or next free number; current max is 0006)
```sql
CREATE TABLE kv_store (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
```
Add to `_BASE_TABLES` in `schema.py` **and** a new
`migrations/m0007_kv_store.py` registered in `registry.py`. Keys used:
`setup_complete`, `local_admin_user`, `local_admin_password_hash`.

> **Migration-number coordination:** Plan 015 (alert groups) also adds a
> migration. Whichever is implemented first takes `0007`; the second takes
> `0008`. Assign the next free integer at implementation time — do not hardcode
> assuming the other hasn't landed.

### KV helpers — `database/queries.py`
`kv_get(db_path, key) -> str | None`, `kv_set(db_path, key, value)`,
`kv_all(db_path) -> dict`. Export via `database/__init__.py`.

### Auth integration
- `config.Settings.from_env` already loads env local-admin creds. Add a way for
  the auth provider to **also** consult `kv_store` when the env vars are empty.
  Cleanest: in the lifespan, after building settings, if env local-admin is
  unset, read `kv_store` (`local_admin_user` / `local_admin_password_hash`) and
  pass those into `build_auth_provider`. Keep env as the override.
- Reuse the existing scrypt hashing (`auth._scrypt_hash`, exposed via the
  `cert-watch hash-password` CLI) for the wizard's password.

---

## Slice 3 — First-run `/setup` wizard

### Detection
- In lifespan, set `app.state.needs_setup = (host_count == 0 AND auth is
  NoAuthProvider AND kv_get("setup_complete") != "1")`.
- Recompute is not needed per-request; flip `needs_setup=False` in-process when
  setup completes.

### Routes — new `routes/setup.py` (register in `routes/__init__.py` `api` list)
- `GET /setup` → render `templates/setup.html` (3 steps).
- `POST /setup` (CSRF-protected) → handle step submissions:
  - **Step 1 (local admin):** validate username + password, store
    `kv_set("local_admin_user")` + `kv_set("local_admin_password_hash",
    _scrypt_hash(pw))`, rebuild `app.state.auth_provider` to include the local
    admin, set `kv_set("setup_complete","1")`, clear `needs_setup`.
  - **Step 2 (SMTP, optional):** test-send button → reuse
    `alerts.send_alert`/SMTP path; persist via env guidance or `kv_store`
    (SMTP can stay env-only for MVP — document that).
  - **Step 3 (first host):** reuse the existing add-host form/handler in
    `routes/hosts.py`.

### Redirect middleware — `middleware.py`
- In `auth_middleware` (or a small dedicated middleware ahead of it), when
  `app.state.needs_setup` is true, redirect everything to `/setup` **except**
  `is_public_path(...)` and `/setup` itself. `_PUBLIC_PATHS` is at
  `middleware.py:259`; add `/setup` to the allowed set for this redirect.
- Never redirect `/healthz`, `/metrics`, `/static/*`.

### Tests (`tests/test_setup.py`)
- Redirect fires on fresh DB (no hosts, no auth); `/healthz` never redirected.
- Completing step 1 creates a working local admin (subsequent `/login` works)
  and clears the redirect.
- `setup_complete` persists across a reload.

### AC
- AC-3: `/setup` creates a local admin with no CLI interaction.
- AC-4: After setup, the app is auth-protected and the redirect stops.

---

## Slice 4 — Unauthenticated-mode warning (Plan 012 §1.3)

In lifespan startup, when `auth` is `NoAuthProvider` **and** `CERT_WATCH_HOST`
is non-loopback (default `0.0.0.0`):
```
CERT-WATCH WARNING: running without authentication on <host>:<port>.
All certificate and host data is publicly accessible.
Set AUTH_PROVIDER + a local admin (visit /setup) to secure this instance.
Set CERT_WATCH_ALLOW_UNAUTH=1 to suppress this warning.
```
- Do **not** hard-fail (preserves dev + air-gapped demos).
- Add `CERT_WATCH_ALLOW_UNAUTH` to `config.py` to suppress.

### Tests
- Warning emitted: auth off + non-loopback. Silent on loopback, when
  `ALLOW_UNAUTH=1`, or when `AUTH_PROVIDER` set.

---

## Sequencing & docs
1. Slice 1 (keys) → 2 (kv_store + admin) → 3 (wizard) → 4 (warning).
2. README: new "First run" section; document `CERT_WATCH_ALLOW_UNAUTH`.
3. AGENTS.md "Known issues": close BC-054 reference.
4. Resolve the relevant Plan 012 ACs (AC-1..AC-4, AC-8).

## Risk notes
- The import-time key globals are the only subtle part — verify no request can
  be served before the lifespan sets them (FastAPI runs lifespan before
  accepting traffic, so this holds).
- `reload_app`-style tests reload modules; ensure `set_signing_key` is
  idempotent and the autouse data-dir fixture is respected.
