# Interface Specification: FR-05 Authentication & Authorization

## Dependencies

- `interface_ref`: `database_layer`
- `interface_ref`: `dashboard`

## AC-01: Auth Provider Protocol

An `AuthProvider` protocol must define:
- `authenticate(username: str, password: str) -> AuthResult`
- `provider_name: str` (e.g., "local", "ldap", "oauth")
- `get_groups(username: str) -> list[str]` (optional, for RBAC)

`NoAuthProvider` must satisfy the protocol with a no-op `authenticate` that always returns `AuthResult(success=True, username="", groups=[])` so unauthenticated routes stay open.

## AC-02: Local Admin Provider

`LocalAdminProvider` must:
- Store credentials as scrypt hashes (not plaintext).
- Use `_dummy_verify()` on username mismatch to equalize timing (prevent timing oracles).
- Read from `kv_store` (falling back from env vars) so GUI-created admins survive restart.

## AC-03: LDAP/AD Provider

`LDAPAuthProvider` must:
- Perform a service-bind → user-search → user-bind flow.
- Support STARTTLS with `CERT_REQUIRED` verification.
- Use `LDAP_GROUP_FILTER` with a `{group}` placeholder (default: AD transitive-membership OID `1.2.840.113556.1.4.1941`).
- Support `LDAP_CA_CERT` pinning for LDAPS.
- Return the user's `memberOf` groups as a list of DNs.
- **Fail closed** on bind failure: check `ldap3.bind()` return value, reject when `False`.

## AC-04: OAuth/OIDC Provider

`OAuthProvider` must:
- Support OIDC discovery via `.well-known/openid-configuration`.
- Cache JWKS with TTL (`CERT_WATCH_JWKS_CACHE_TTL`).
- Verify ID tokens with an asymmetric algorithm allowlist (RS/ES/PS only; `none` and `HS*` rejected).
- Validate `nonce` in the ID token claims (matches the nonce generated in the authorization request and embedded in signed state).
- Fall back to `userinfo` only when ID-token verification fails, and verify the nonce claim there too.
- Require `CERT_WATCH_BASE_URL` for redirect URI construction (never trust the Host header).
- Route discovery, JWKS, and userinfo requests through the SSRF-safe HTTP opener.

## AC-05: Session Management

Sessions must be:
- HMAC-signed with `SecurityContext.signing_key`.
- Embed a per-user `version` field (BC-081): `{username}:{version}:{timestamp}:{nonce}:{sig}`.
- Checked against `session_versions` DB table on validation.
- Invalidated on logout / credential change (bump stored version).
- Old-format tokens (no version field) accepted with version 0.
- `Secure` and `HttpOnly` flags set on the `cw_auth` cookie.
- `SameSite=strict` on the `cw_auth` cookie.

## AC-06: RBAC (Role-Based Access Control)

- `CERT_WATCH_ROLE_MAP` must be a JSON dict mapping IdP group names to cert-watch roles (`admin`, `operator`, `viewer`).
- Session tokens must carry only the groups/roles named in `CERT_WATCH_ROLE_MAP` (not the full `memberOf` list) to avoid cookie overflow.
- Group values must be encoded with lossless base64url(JSON) (not comma-join) to preserve AD DN structure.
- `require_auth` dependency returns `str` (username) or raises 401.
- `require_write` dependency returns `str` or raises 403 for viewers.
- Write controls must be hidden from viewers in the UI (dashboard, detail pages).
- Form-POST routes must reject viewer writes with 403.

## AC-07: API Keys

- `POST /api/api-keys` creates a bearer token (raw token shown once, prefixed `cwk_`).
- Stored as SHA-256 hash only.
- Scopes: `read` → `viewer`, `write` → `operator`, `admin` → `admin`.
- `Authorization: Bearer cwk_...` header accepted on `/api/*` routes.
- Key creation/revocation and state-changing API calls logged in audit log under the key's name.

## AC-08: Secure-by-Default Boot

- Network-exposed instance (non-loopback bind or loopback + `TRUST_PROXY=1`) with no `AUTH_PROVIDER` and no `ALLOW_UNAUTH` must auto-provision a local `admin` with a generated password.
- Password written to `data_dir/initial-admin-password` (mode 0600) and logged.
- If provisioning can't persist the admin, `SystemExit` (fail closed) rather than serve open.
- Bare loopback (no proxy) stays open and serves `/setup` wizard.

## AC-09: Rate Limiting

- SQLite-backed rate limiting per client IP.
- Proxy-aware: extract client IP from `X-Forwarded-For` / `X-Real-IP` when `TRUST_PROXY=1`.
- Rightmost `X-Forwarded-For` entry used when no `TRUSTED_PROXIES` configured (the hop the trusted proxy appended).
- Rate-limited API routes use `Depends(rate_limit("prefix", max, window))`.
- Form-POST/redirect routes (`/hosts`, `/login`, `/upload`) keep manual `check_rate_limit`.

## AC-10: CSRF Protection

- Double-submit cookie: token accepted via `x-csrf-token` header or `_csrf_token` form field only.
- Never accept CSRF token from query string.
