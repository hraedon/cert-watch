# Plan 035: Extensible Role-Based Authorization (bug 2b)

**Created:** 2026-06-05
**Status:** proposed
**Depends on:** claim extraction (done — `oauth_provider.py` populates
`AuthResult.roles`/`groups`; LDAP populates `groups`).
**Relates to:** Plan 034 (E2E validates this), BC-136.

---

## Goal

Let cert-watch grant **different privilege levels by IdP group / app-role**, for
both LDAP and Entra. Ship admin vs read-only now, but **model it so adding more
roles and finer permissions later is config + a lookup-table edit — never a
session-format or call-site rewrite.**

The explicit anti-requirement: do not bake a binary `write`/`no-write` boolean
into the session or the data model. That is the lock-in we're avoiding.

---

## What exists today (and why it's not enough)

- `check_authz` (`auth/factory.py`) — **access** gate only: in `allowed_groups`
  OR `allowed_roles` → allowed, else denied. No notion of *which* privilege.
- `_may_write` (`middleware.py:560`) — binary, **username-list** based
  (`write_users` / `admin_users`). Per-request it only has `username` from the
  session token; the login-time `roles`/`groups` are **not carried**.
- `create_session`/`validate_session` (`auth/session.py`) — HMAC-signed token
  carrying username + version. No role/permission data.
- `AuthResult.roles` / `.groups` — now populated at login but dropped after the
  authz gate.

So privilege today is a username allowlist. We need privilege derived from IdP
identity, carried per-request, and extensible.

---

## Model (the extension points are the point)

Three layers, each independently extensible:

1. **Permissions** — an enumerated, open-ended set of capabilities. Start coarse,
   carve finer later **without touching the session or config schema**:
   ```
   class Permission(StrEnum):
       CERT_READ   = "cert.read"
       CERT_WRITE  = "cert.write"     # add/upload/delete, edit owner/notes, scan-now
       SETTINGS_ADMIN = "settings.admin"
       # future: ALERT_MANAGE, AUDIT_READ, HOST_DELETE, TAG_MANAGE, ...
   ```

2. **Roles → permission sets** — a single in-code lookup table (`ROLE_PERMISSIONS`).
   Built-ins shipped now: `admin` (all), `viewer` (read-only). Adding `operator`
   later = one dict entry. Roles are *data*, not branches.
   ```
   ROLE_PERMISSIONS: dict[str, frozenset[Permission]] = {
       "admin":  frozenset(Permission),                 # everything
       "viewer": frozenset({Permission.CERT_READ}),
       # future: "operator": {CERT_READ, CERT_WRITE}, "auditor": {CERT_READ, AUDIT_READ}
   }
   ```

3. **IdP identity → cert-watch roles** — provider-agnostic mapping config, the
   only thing an operator edits to onboard a new role:
   ```
   CERT_WATCH_ROLE_MAP = {
     "admin":  {"groups": ["<admins-guid>", "CN=cert-watch-admins,..."], "roles": ["admin"]},
     "viewer": {"groups": ["<users-guid>",  "CN=cert-watch-users,..."],  "roles": ["viewer"]}
   }
   ```
   Matches an `AuthResult.groups` GUID/DN or `AuthResult.roles` app-role value to
   a cert-watch role. **Many IdP groups → one role; many roles → one user.**

**Resolution = union.** A user matching several roles gets the **union** of their
permissions (least surprise; future-proof — never have to invent precedence when
a 3rd role lands). Local break-glass admin and NoAuth keep full permissions.

**Carry roles, not permissions, in the session.** The signed token stores the
resolved **role names** (short, stable); permissions are resolved per-request via
`ROLE_PERMISSIONS`. So expanding/retuning permissions later changes behavior for
already-issued tokens **without a token-format change or re-login**.

**Single enforcement choke point.** `has_permission(request, Permission.X)` is the
one check; everything else is a thin wrapper:
- `_may_write(...)` ≡ `has_permission(request, Permission.CERT_WRITE)` (so all
  existing call sites keep working unchanged).
- new `require_permission(perm)` dependency mirrors `require_write`.
Adding a finely-gated action later = reference a (possibly new) `Permission` at
that route — no plumbing.

---

## Config

| Var | Meaning |
|---|---|
| `CERT_WATCH_ROLE_MAP` | JSON: role → `{groups: [...], roles: [...]}`. Empty/unset = role-gating **off**. |
| `CERT_WATCH_DEFAULT_ROLE` | role for an authed user matching no mapping (default `viewer` when role-gating on). |
| existing `write_users` / `admin_users` | retained as an **override layer** (username → write/admin) on top of role resolution, for break-glass/exceptions. |

**Back-compat (must not change existing deployments):** when `CERT_WATCH_ROLE_MAP`
is empty, behavior is exactly today's — all authenticated users get `CERT_WRITE`
(and `_may_write` still honors `write_users`/`admin_users`). Role-gating is opt-in.

---

## Slices

1. **Permission/role core** — `auth/rbac.py`: `Permission`, `ROLE_PERMISSIONS`,
   `permissions_for_roles(roles) -> set`, `has_permission`. Reimplement `_may_write`
   on top. **No behavior change when unconfigured.** Unit tests for the table +
   union + back-compat.
2. **Role resolution at login** — `resolve_roles(auth_result, role_map, default)`
   in the factory; called in `routes/auth.py` (form + OAuth callback) right after
   `check_authz`. Provider-agnostic (LDAP groups, Entra roles+groups). Tests for
   GUID match, DN match, app-role match, multi-match union, no-match→default.
3. **Session carries roles** — extend `create_session`/`validate_session`
   (`auth/session.py`) with a roles field; signed; **legacy tokens without it →
   default role when gating on, full-write when off**. Middleware puts resolved
   roles + permissions in `request.scope` and `get_auth_context`. Version-bump
   tokens so old 3-part tokens phase out cleanly (mirror BC-029/BC-081 handling).
4. **Wire enforcement** — `_may_write` via `has_permission(CERT_WRITE)`; gate the
   settings/auth pages on `SETTINGS_ADMIN` (keeping `admin_users` as an override).
   Surface `may_write`/role in templates for the UI controls.
5. **Config + docs + samples** — README/AGENTS env docs; lab sample `ROLE_MAP`
   (admins GUID→admin, users GUID→viewer; LDAP group-DN equivalents).
6. **E2E** (lives in Plan 034 Slice 1) — admin writes; viewer sees read-only UI
   and gets 403 on mutation endpoints.

---

## Testing

- Unit: permission table, role union, resolution from each provider shape,
  back-compat (no map → open), legacy-token defaulting.
- Integration: `_may_write`/`require_permission`/`require_write_form` honor
  resolved roles; settings page gated by `SETTINGS_ADMIN`.
- E2E: per Plan 034. Coverage ratchet (88%) applies to unit suite.

## Risks / decisions

- **Session token format change** — security-sensitive. Mitigate: signed field,
  safe legacy defaulting, version bump (reuse existing session-version machinery).
- **Default-open preserved** — no `ROLE_MAP` ⇒ identical to today; role-gating is
  strictly opt-in. This is the single most important regression guard.
- **Union vs precedence** — chose union of permissions (extensible; no precedence
  table to maintain as roles grow).
- **Source of truth = IdP groups/roles** (not a cert-watch role DB). A roles
  *admin UI* and per-object/tag ACLs are explicit **non-goals** here, but the
  permission choke point + role table leave the door open for both.
- **Stale claims** — roles reflect login-time group membership (same caveat as
  any token-claim system); acceptable for the session TTL.
