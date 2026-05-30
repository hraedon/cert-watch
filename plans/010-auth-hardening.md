# Plan 010: Auth Hardening (Rollout Readiness Phase 4)

> Implements Plan 007 §Phase 4 — see there for the full design rationale
> (provider strategy, break-glass reasoning, trust separation). This plan is the
> **implementation slicing**: four independently reviewable/testable slices.
> Entra OIDC (+MFA) is primary, LDAPS the fallback, local break-glass the last
> resort.

## Slice 1 — Authorization foundation + `*_FILE` secrets

The spine every other slice plugs into.

- `AuthResult` carries `groups: list[str]` and `roles: list[str]`.
- Config: `CERT_WATCH_ALLOWED_GROUPS` / allowed roles (provider-agnostic).
- **`read_secret(name)`** config helper: returns `$NAME`, else contents of
  `$NAME_FILE` (trimmed) — used by every credential (k8s/Docker secret mounts).
- Login handler enforces the **gate**: authN success grants access only if the
  identity holds ≥1 allowed group/role; else deny with a clear message.
- Session carries `actor` + role; available to Phase 2 audit.
- **Files:** `auth.py`, `config.py`, `routes/auth.py`/`middleware.py`, tests.
- **Tests:** gate denies a valid-creds user lacking the group; allows a member;
  `read_secret` resolves both env and `_FILE`.

## Slice 2 — Local break-glass admin

Self-contained; no external systems to mock.

- Config: `CERT_WATCH_LOCAL_ADMIN_USER` + `CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH`
  (+ `_FILE`). Disabled unless both set.
- Hash: stdlib `hashlib.scrypt`, per-account salt, stored as
  `scrypt$n$r$p$salt_b64$hash_b64`; verify with `hmac.compare_digest`.
- **`cert-watch hash-password`** CLI helper (plaintext never enters config).
- **Evaluation order:** submitted username == local-admin → verify hash (works
  regardless of provider state) → else provider flow → group/role gate.
- **Always-on when configured, not health-gated** (see 007 §4.4 for why).
- Every use → **WARNING log + audit row `break_glass=true`** (needs Plan 008).
- Bypasses group gate (implicit admin) and MFA (inherent); documented tradeoff.
- **Login UX:** OIDC login page renders a secondary local-admin form when a
  local admin is configured.
- **Tests:** disabled when unset; succeeds while provider unreachable; constant-
  time compare; WARNING + flagged audit row emitted; wrong password rejected.

## Slice 3 — LDAPS hardening

- **Private-CA TLS:** `ldap3.Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=… |
  ca_certs_data=…)` from `LDAP_CA_CERT[_FILE]`. `CERT_REQUIRED` is load-bearing
  (ldap3 defaults to `CERT_NONE`). Missing/untrusted CA on `ldaps://` →
  **fail closed** with a clear error. Connect by FQDN matching the cert SAN.
- **DC failover:** `LDAP_SERVER` accepts a comma-separated list →
  `ldap3.ServerPool(pool_strategy=FIRST, active=True)` sharing one `Tls`, with a
  short `connect_timeout` so a dead DC fails fast.
- **Transitive group filter:** `(&(sAMAccountName={u})(memberOf:1.2.840.113556.
  1.4.1941:=<group-DN>))` against `LDAP_REQUIRED_GROUPS`.
- Least-privilege bind account; `LDAP_BIND_PASSWORD_FILE`; TLS enforced.
- **Tests (mock ldap3):** missing-CA fails closed; failover to DC2 when DC1
  unreachable; non-member excluded by the group filter; member admitted.

## Slice 4 — Entra OIDC hardening

- **App Roles** over raw `groups` claim → gate on the `roles` claim.
- **JWKS signature verification:** replace the manual base64 payload decode with
  real JWT verification (authlib + `jwks_uri` from discovery); then check
  `iss`/`aud`/`exp`/nonce on the **verified** claims.
- Client secret/cert via `read_secret`.
- **Tests:** token signed with an unknown key rejected; missing required role
  denied; valid token + role admitted.

## Sequencing

Plan 008 (audit) → Slice 1 → Slice 2 → Slices 3 & 4 (independent).

## Acceptance criteria

Per 007 §4 AC-1…AC-7.
