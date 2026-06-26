# Plan 029: Security-Review Hardening Backlog

> **Status:** draft for review. Captures the findings from the Minimax-M3
> adversarial review (and the earlier high/medium batch) that were **not** fixed
> inline, with severities re-calibrated against the actual code. Grounded in
> `release/0.5.0`. The trivial, unambiguous fixes were already implemented (see
> "Already done"); this plan covers the items that need a design decision, carry
> a behavior/operational tradeoff, or touch CI/deploy.

## Already done (fixed inline, not in this plan)

- OAuth JWT **algorithm allowlist** — discovered algs are intersected with an
  asymmetric allowlist; `none`/`HS*` can never be accepted (#2); the authlib
  fallback decode is pinned to that list (#9).
- **`runbook_url` scheme validation** — http(s)-only on write, closing the
  stored-XSS-via-`javascript:` vector (#5). *(This was the most serious finding;
  the XSS runs in the victim's session — the "exfiltrate cw_sid" framing
  undersold it.)*
- **Compliance report fails closed** (HTTP 503) instead of signing with `""`
  when the signing key is unavailable (#10).
- **`cw_sid` is now HttpOnly** (#4) and `/api/ct/reconciliation` has a dedicated
  rate limit (#17, partial).
- **Response headers**: `Referrer-Policy`, `Permissions-Policy`,
  `X-Permitted-Cross-Domain-Policies`.

## Known false positives (do NOT chase)

- **#6 session fixation of `cw_sid`** — `cw_sid` is not an auth token (auth is
  `cw_auth`, freshly minted on login, HttpOnly+SameSite=strict), and CSRF tokens
  are HMAC'd with a **server-side** secret, so fixing/knowing `cw_sid` grants no
  forgery. The described attack doesn't work. (Rotating `cw_sid` on login is
  harmless tidiness, not a fix — see App items below if we do it anyway.)
- **#12 Content-Disposition `cert_id[:8]` injection** — `cert_id` must match an
  existing server-generated hex id (`get_by_id` → 404) before the filename is
  built, and uvicorn rejects CR/LF in header values. Not reachable.
- **#17 `caa-check` unthrottled** — `/caa-check` and `/ct-lookup` already carry
  `Depends(rate_limit(...))`; only `/api/ct/reconciliation` lacked one (now
  fixed). M3's claim was half-wrong.
- **#14 webhook/OCSP DNS-rebinding** — real residual, but already documented in
  the `http_client` module docstring as a deliberate, accepted limitation.

## Application hardening (this plan)

### A. OAuth IdP-fetch SSRF (#8) — Medium
The discovery (`oauth_provider.py:77`), JWKS (`:115`), and userinfo (`:319`)
fetches use raw `urllib`/authlib clients, **not** the SSRF-guarded opener. A
malicious/compromised IdP could point any of these at `169.254.169.254` etc.
Route them through `http_client.ssrf_safe_urlopen` (or `_validate_url` first),
threading `allow_private`/`allowed_subnets`. **Care:** legitimate private IdPs
must still work, so gate on the same policy the scanner uses, not a hard block.
*M3 only flagged userinfo; discovery + JWKS share the exposure.*

### B. OAuth redirect_uri pinning (#3) — Medium (mitigated in practice)
`_get_base_url` falls back to `request.base_url` (Host header) when
`CERT_WATCH_BASE_URL` is unset (`routes/auth.py:133`). Exact-match
`redirect_uri` registration at the IdP mitigates this in practice, but
defense-in-depth: **refuse to start the OAuth flow when `CERT_WATCH_BASE_URL` is
unset** (or pin the redirect_uri to it regardless of headers). Small.

### C. Proxy IP trust (#7) — Medium
With `CERT_WATCH_TRUST_PROXY=1` and empty `CERT_WATCH_TRUSTED_PROXIES`,
`_extract_client_ip` returns the **leftmost** (client-controlled) XFF entry
(`middleware.py:127`), defeating per-IP rate limits and lockout. Fix: when
`TRUST_PROXY=1` and `TRUSTED_PROXIES` is empty, **log a startup warning and use
the rightmost XFF entry** (the hop the trusted proxy appended), or refuse to
start. The leftmost choice is simply wrong for a spoofing-resistant read.

### D. Legacy session tokens (#16) — Low/Medium
`get_session_version` returns 0 for users who never rotated, so an old 3-part
token still validates (`auth/session.py`). Fix: on successful login, ensure the
stored version is ≥ 1 (`bump_session_version`); in a follow-up, **reject 3-part
tokens outright**. Phase it so existing sessions aren't mass-invalidated without
warning.

### E. Login CSRF (#19) — Low — **DONE**
`POST /login` skipped the double-submit check (public path, no session yet).
**Fixed** by reusing the existing `cw_sid` + CSRF-token machinery (the better
call — a per-IP nonce is fragile under NAT/VPN/IPv6 and adds state): `GET /login`
now renders the token, both login forms carry it, and `login_submit` calls
`check_csrf`. **Correction to the "~2 lines" framing:** the login page did **not**
previously render a CSRF token (`login_page` didn't pass `get_csrf_context`, and
`login.html` had no field), so naively adding only `check_csrf` would have
rejected *every* login. The real change was three touch-points (handler context +
both form fields + the check). Existing login tests are unaffected because the
test env sets `_CSRF_BYPASS=True` (was `CERT_WATCH_CSRF_DISABLED=1`, removed in WI-097).

### F. scrypt parameters (#11) — Low
- **F#1 timing leak — DONE.** `_dummy_verify` hardcoded `n=2**14` while the
  verify path uses the *stored* hash's `n`, so a custom-cost admin hash made the
  username-match path measurably slower than a mismatch — a username oracle.
  `_dummy_verify` now reads the stored hash's `n/r/p`. (Sharp catch; neither M3
  nor the original plan had it.)
- **F#2 default cost bump — still open, NOT a one-liner.** Two blockers M3/Kimi
  glossed: (a) `_scrypt_hash`/`verify_scrypt_hash` pass **no `maxmem`**, so
  OpenSSL's ~32 MB default already rejects `n≥2**15`; bumping the default
  requires threading `maxmem` through both. (b) Tests call `_scrypt_hash` at the
  default cost in several places, so the bump quadruples suite/CI memory
  (16→64 MB/hash) and time unless those call sites pass a low cost. `2**16`
  (~64 MB) is the right target over M3's `2**17` (~134 MB), but it needs the
  `maxmem` + test-cost work first. Decide deliberately.
- **F#3 weak-hash UI banner — open.** Reuse the `local_admin_autogenerated`
  banner pattern (BC-102) to prompt rotation via the existing change-password
  flow, rather than a migration framework.
- **F#4 — affirmed: do NOT add a rejection floor.** Rejecting a weak stored hash
  locks the break-glass operator out at the worst moment. Warn + rotate.

### G. Cleartext password in log (#1) — Low (narrow trigger, deliberate fallback)
`app.py:147` logs the cleartext one-time admin password **only when the 0600
file write fails** — a deliberate "don't lock the operator out" fallback.
Preferred fix that keeps recoverability: on file-write failure, **don't log the
password**; instead log clear instructions to set
`CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH` (via `cert-watch hash-password`) or fix
the data dir and restart. The operator recovers without a credential in the log.

### H. Endpoint hygiene (Low)
- **#13 `/discover`** still does serial synchronous CT calls; add a short-TTL
  cache and/or `run_in_executor` fan-out (rate limit already added).
- **`/healthz` version/commit disclosure** (`views.py:53`) — move build metadata
  behind auth or drop it from the public body (keep liveness semantics intact for
  k8s probes — don't break the probe contract).
- **`/metrics` rate-limit** — exempt from the limiter; if unauthenticated
  (`CERT_WATCH_METRICS_TOKEN` unset), scraping is unmitigated. Apply a limit or
  document that `/metrics` should be network-restricted.
- **#20 CT log URL hardcoded** (`ct_lookup.py:40`) — add `CERT_WATCH_CT_LOG_URL`
  (validated) so private CT logs work. Operational, not security.

## Supply-chain / CI / deploy (this plan)

- **`pip-audit` in CI** — add `pip-audit --strict` against `uv.lock`; Trivy
  catches OS CVEs, not transitive Python ones.
- **Pin the base image by digest** — `python:3.13-slim` (`Dockerfile:2,21`) →
  `python:3.13-slim@sha256:…`. Pin to the *current* digest at edit time.
- **Pin GitHub Actions by SHA** — `aquasecurity/trivy-action@v0.36.0` and
  `actions/checkout@v6` are mutable tags. **Verify `checkout@v6` first:** it is
  used consistently across all three workflows, so if CI is green it resolves
  (M3's "latest is v4/v5" looks like stale knowledge — don't downgrade blindly);
  pin whatever the green SHA is.
- **Kustomize download integrity** (`release.yml`, `curl | tar`) — verify against
  the release's `*_checksums.txt`.
- **k8s NetworkPolicy** — ingress currently admits any namespace carrying the
  traefik label; restrict to the ingress namespace.
- **Dependency upper bounds** — `pyproject.toml` uses open-ended `>=`; `uv.lock`
  saves the uv path, but a bare `pip install -e .` re-resolves. Rely on `uv.lock`
  explicitly (document) or add upper bounds.

## Sequencing / recommendation

1. **A (OAuth SSRF)**, **C (proxy IP)**, **G (password log)** first — concrete,
   contained, real. 
2. **B (redirect_uri)**, **D (legacy tokens)** next — small auth hardening.
3. **CI/supply-chain batch** — independent, high leverage, low risk; can land
   anytime.
4. **E (login CSRF)** — **done.** **F#1 scrypt timing leak** — **done.** Remaining
   F (default-cost bump + `maxmem`, weak-hash UI banner) are deliberate design
   calls; don't rush the default bump.
5. **#18 audit append-only** is folded into **Plan 026** (DB `BEFORE
   DELETE/UPDATE` triggers as a defense-in-depth layer alongside the hash chain).

None of these is release-blocking for 0.5.0 given the inline fixes already
landed; this is the 0.5.1 security backlog.
