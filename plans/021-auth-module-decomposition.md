# Plan 021: Auth Module Decomposition

> **Status:** ready for implementation
> **Prereq:** Plan 020 Slice 1 (`Depends(require_auth)` sweep) should land
> first to avoid merge conflicts in routes.

## Why this exists

`auth.py` is 877 lines doing six distinct jobs:

| Job | Lines | Concern |
|-----|-------|---------|
| Session signing/verification | 30–93 | HMAC tokens, TTL, username parsing |
| AuthProvider protocol + NoAuth | 96–155 | Abstract base, passthrough |
| LDAPAuthProvider | 160–344 | LDAP bind, TLS config, group search |
| OAuthProvider | 346–636 | OIDC discovery, JWKS, token exchange |
| LocalAdminProvider + _CompositeProvider | 688–779 | Scrypt hashing, composite delegation |
| Factory (build_auth_provider) | 785–877 | Provider assembly from env vars + kv_store |

The adversarial review found issues across all six: session tokens with
over-truncated MACs, LDAP STARTTLS cert fallbacks, OAuth state bypass,
scrypt parameter validation, silent NoAuthProvider degradation (now fixed
— raises ValueError). Each fix required understanding the full 877-line
file because the concerns are tangled (e.g., `build_auth_provider` creates
`LocalAdminProvider` which references `_scrypt_hash` which is near the
protocol definition).

The Plan 018 A1 change (fold kv_store into `build_auth_provider`) will add
another 15–20 lines to the factory. The factory is already hard to test
in isolation because it imports `ldap3` and `authlib` at module level.

Decomposition makes each concern independently testable, independently
reviewable, and independently modifiable. It also makes the auth surface
auditable — a security reviewer can read `session.py` (80 lines) instead
of scrolling past OAuth and LDAP to find the signing logic.

---

## Target structure

```
src/cert_watch/auth/
    __init__.py      — re-exports public API (backward-compat)
    session.py       — create_session, validate_session, SESSION_COOKIE, SESSION_TTL
    protocol.py      — AuthProvider, AuthResult
    ldap_provider.py — LDAPAuthProvider
    oauth_provider.py — OAuthProvider, OAuthConfig
    local_admin.py   — LocalAdminProvider, _scrypt_hash, verify_scrypt_hash
    composite.py     — _CompositeProvider
    factory.py        — build_auth_provider, check_authz
```

The public API (what routes import) stays the same:

```python
from cert_watch.auth import (
    SESSION_COOKIE, SESSION_TTL,
    AuthProvider, AuthResult, NoAuthProvider,
    LDAPAuthProvider, OAuthProvider, OAuthConfig,
    LocalAdminProvider, _CompositeProvider,
    build_auth_provider, check_authz,
    create_session, validate_session,
)
```

These imports now come from `auth/__init__.py` re-exports. No route file
changes.

---

## Slice 1 — Package scaffolding + `session.py`

Move session-related code into `auth/session.py`:

- `_signing_key`, `_sign_state`, `_verify_state`
- `_sign_session`, `create_session`, `validate_session`
- `SESSION_COOKIE`, `SESSION_TTL`
- `set_signing_key()` (called by lifespan)

`auth/__init__.py` re-exports: `SESSION_COOKIE`, `SESSION_TTL`,
`create_session`, `validate_session`, `set_signing_key`.

**Testing:** Existing `test_session_*` and `test_auth.py` session tests
must pass without modification. The re-exports mean `from cert_watch.auth
import create_session` still works.

**AC:** AC-S1a: `auth/__init__.py` re-exports all session symbols.
AC-S1b: `from cert_watch.auth import create_session` works identically.
AC-S1c: All session-related tests pass without modification.

---

## Slice 2 — `protocol.py` + `NoAuthProvider`

Move the abstract protocol and passthrough:

- `AuthProvider` (ABC)
- `AuthResult` (dataclass)
- `NoAuthProvider`

`auth/__init__.py` adds re-exports: `AuthProvider`, `AuthResult`,
`NoAuthProvider`.

**AC:** AC-S2a: `NoAuthProvider` is importable from `cert_watch.auth`.
AC-S2b: All auth tests pass.

---

## Slice 3 — `local_admin.py`

Move scrypt and break-glass:

- `_scrypt_hash`, `verify_scrypt_hash`
- `LocalAdminProvider`
- `_CompositeProvider`

`_CompositeProvider` depends on `AuthProvider` (from `protocol.py`) and
`LocalAdminProvider` (same file). Keep it in the same module because it's
small (20 lines) and closely coupled.

`auth/__init__.py` re-exports: `LocalAdminProvider`, `_CompositeProvider`,
`verify_scrypt_hash`, `_scrypt_hash`.

**AC:** AC-S3a: Scrypt hash round-trip works via import from `cert_watch.auth`.
AC-S3b: `_CompositeProvider.authenticate` tries local admin first, then primary.
AC-S3c: `build_auth_provider` with local admin returns `_CompositeProvider`.

---

## Slice 4 — `ldap_provider.py`

Move LDAP:

- `LDAPAuthProvider` and its `_build_tls`, `_resolve_ca_cert`, `authenticate`

This module imports `ldap3` at `__init__` time (the `try: import ldap3`
pattern). The import guard stays in `LDAPAuthProvider.__init__`.

`auth/__init__.py` re-exports: `LDAPAuthProvider`.

**AC:** AC-S4a: `LDAPAuthProvider` importable from `cert_watch.auth`.
AC-S4b: LDAP auth tests (mocked) pass.
AC-S4c: Missing `ldap3` raises `RuntimeError` at provider init, not at
    module import.

---

## Slice 5 — `oauth_provider.py`

Move OAuth:

- `OAuthConfig`, `OAuthProvider`
- `_verify_id_token`, `_validate_claims_manual`

This module imports `authlib` at `__init__` time. The import guard stays.

`auth/__init__.py` re-exports: `OAuthProvider`, `OAuthConfig`.

**AC:** AC-S5a: `OAuthProvider` importable from `cert_watch.auth`.
AC-S5b: OAuth flow tests pass.
AC-S5c: Missing `authlib` raises `RuntimeError` at provider init.

---

## Slice 6 — `factory.py` + `check_authz`

Move the factory and authorization:

- `build_auth_provider`
- `check_authz`

After slices 1–5 land, `factory.py` imports from the other five modules:
`from .session import set_signing_key` (no longer needed — factory doesn't
touch signing keys), `from .protocol import AuthResult, NoAuthProvider`,
`from .ldap_provider import LDAPAuthProvider`,
`from .oauth_provider import OAuthProvider, OAuthConfig`,
`from .local_admin import LocalAdminProvider, _CompositeProvider`.

**AC:** AC-S6a: `build_auth_provider` is importable from `cert_watch.auth`.
AC-S6b: Misconfigured provider raises `ValueError` (not silent NoAuth).
AC-S6c: `check_authz` enforces group/role gates.

---

## Slice 7 — Delete `auth.py`, update all imports

Remove `src/cert_watch/auth.py`. All internal imports already use
`from cert_watch.auth import ...` which resolves to `auth/__init__.py`.
Update `conftest.py` and `test_auth.py` if they import from the file path.

**AC:** AC-S7a: `src/cert_watch/auth.py` no longer exists.
AC-S7b: All 403 tests pass.
AC-S7c: `from cert_watch.auth import build_auth_provider` works.

---

## Slice 8 — Move `auth_routes.py` helpers closer to their module

This is optional cleanup, not strictly part of the decomposition. After
slices 1–7, the auth route file at `routes/auth.py` imports from
`cert_watch.auth` (the package). The `_get_base_url` helper, the login
rate limit, and the break-glass detection are all in the route file,
which is their proper home. No change needed unless it helps readability.

**Skip for now.** Mark as "not planned" in this iteration.

---

## What this plan does NOT cover

- **SecurityContext / create_app factory** — that's Plan 018 B1. It removes
  module-level globals from `session.py` and `middleware.py`. This plan
  moves the globals into their own module, which makes B1's change easier
  (only `session.py` and `local_admin.py` need the SecurityContext
  injection, not the full 877-line monolith).

- **The `_require_api_auth` → Depends sweep** — that's Plan 020 Slice 1.
  Do it before or after this plan; it doesn't conflict because it changes
  route files, not auth internals.

- **LDAP config validation** — the STARTTLS / CERT_REQUIRED fix is already
  landed. Future improvements (e.g., connection pooling, timeout tuning)
  belong in `ldap_provider.py` after decomposition.

---

## Sequencing

```
Slice 1  session.py       (smallest, highest-value — session logic is
  │                         the most security-critical and most referenced)
  ├── Slice 2  protocol.py
  ├── Slice 3  local_admin.py
  ├── Slice 4  ldap_provider.py
  ├── Slice 5  oauth_provider.py
  ├── Slice 6  factory.py
  └── Slice 7  delete auth.py
```

Slices 1–5 are independent of each other (each moves code out of `auth.py`
into its own module). Slice 6 depends on 1–5 (the factory imports from
them). Slice 7 is the final cleanup.

Each slice should be a separate commit. Run the full test suite after
each slice. If any slice breaks, revert and fix before proceeding.

---

## Acceptance criteria (summary)

- AC-S1: Session symbols importable from `cert_watch.auth`; tests pass.
- AC-S2: Protocol + NoAuth importable; tests pass.
- AC-S3: Local admin + composite importable; scrypt tests pass.
- AC-S4: LDAP provider importable; mocked LDAP tests pass.
- AC-S5: OAuth provider + config importable; OAuth tests pass.
- AC-S6: Factory + check_authz importable; ValueError on misconfig.
- AC-S7: `auth.py` deleted; all 403 tests pass.