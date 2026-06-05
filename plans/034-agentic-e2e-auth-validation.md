# Plan 034: Agentic + Scripted E2E UI Validation (Auth-first)

**Created:** 2026-06-05
**Status:** proposed
**Owner:** TBD (slices routable to separate agents)

---

## Goal

Stand up end-to-end UI validation that covers the **authenticated** product, not just
the open-access (`ALLOW_UNAUTH=1`) paths the current E2E suite exercises. Two
delivery modes, per the agreed direction:

1. **Scripted (deterministic, every PR)** — Playwright drives the real browser
   against a real app instance backed by a **synthetic LDAP** that needs no
   secrets and no corporate network. This is the default gate.
2. **Agentic (adaptive, on demand / pre-release)** — an agent drives the live UI
   in natural language against the synthetic server *and* the real staging
   directory, adapting to markup drift instead of hard-coded selectors.

Secondary win: the synthetic LDAP seeds an admins group and a users group, which
is the exact test bed [bug 2b — group→role mapping] needs to be *proven* rather
than eyeballed.

---

## What already exists (build on, don't rebuild)

- **E2E harness** — `tests/e2e/conftest.py` boots real uvicorn against a temp
  data dir and yields a base URL; `tests/e2e/test_auth_flows.py` already drives
  login/logout/session against a **local break-glass admin** (`_start_server`
  with `CERT_WATCH_LOCAL_ADMIN_USER`). Verified green (Playwright + Chromium).
- **CI** — `.github/workflows/e2e.yml` already installs `[dev,e2e]`,
  `playwright install --with-deps chromium`, and runs `pytest -m e2e tests/e2e
  -n0` on every PR (ubuntu, chromium). We extend this, not replace it.
- **LDAP provider** — `src/cert_watch/auth/ldap_provider.py`: multi-DC
  `ServerPool` failover, `LDAP_CA_CERT` pinning, transitive group filter
  (`memberOf:1.2.840.113556.1.4.1941`), real service-bind → user-search →
  user-bind flow.
- **Config surface** — `src/cert_watch/config.py` `Settings.from_env`: all the
  `LDAP_*` env vars below are already read.

---

## Non-goals

- Entra/OAuth E2E as the *first* deliverable — LDAP ships first. But the Entra
  MVP is now scoped in the appendix below (operator has a lab tenant).
- Replacing unit tests — the mocked `test_auth.py` / `test_settings.py` suites
  stay; this adds a layer above them.
- Putting any real credential in the repo, the image, or CI logs (see Secrets).

---

## Integration topology (NON-SECRET config — passwords live only in the secret store)

Real staging directory provided by the operator. Recorded here as *configuration*;
every password is a placeholder pointing at a secret name.

| Item | Value |
|---|---|
| Domain / realm | `ad.hraedon.com` |
| Base DN | `DC=ad,DC=hraedon,DC=com` |
| Domain controllers | `mvmdc01`, `mvmdc02`, `mvmdc03` (`.ad.hraedon.com`) |
| `LDAP_SERVER` | `ldaps://mvmdc01.ad.hraedon.com,ldaps://mvmdc02.ad.hraedon.com,ldaps://mvmdc03.ad.hraedon.com` |
| Service account DN (`LDAP_BIND_DN`) | `CN=cert-watch,OU=Service,OU=Accounts,DC=ad,DC=hraedon,DC=com` |
| Service account UPN | `cert-watch@ad.hraedon.com` |
| `LDAP_BIND_PASSWORD` | → secret `CW_LDAP_BIND_PASSWORD` |
| `LDAP_CA_CERT` | → secret `CW_LDAP_CA_CERT` (enterprise root, PEM — pins LDAPS) |
| Allowed groups (`LDAP_REQUIRED_GROUPS`) | `CN=cert-watch-users,OU=Groups,DC=ad,DC=hraedon,DC=com`, `CN=cert-watch-admins,OU=Groups,DC=ad,DC=hraedon,DC=com` |

**Group → role intent (drives bug 2b):**
- `cert-watch-admins` → **admin** (write)
- `cert-watch-users` → **read-only**

**Test identities** (DNs/UPNs are config; passwords are secret names):

| Role | UPN | DN | `sAMAccountName` (likely) | Member of | Password secret |
|---|---|---|---|---|---|
| Admin | `cw-admin@ad.hraedon.com` | `CN=cert-watch admin,OU=Service,OU=Accounts,DC=ad,DC=hraedon,DC=com` | `cw-admin` | `cert-watch-admins` | `CW_LDAP_TEST_ADMIN_PASSWORD` |
| Read-only | `cw-user@ad.hraedon.com` | `CN=cert-watch user,OU=Service,OU=Accounts,DC=ad,DC=hraedon,DC=com` | `cw-user` | `cert-watch-users` | `CW_LDAP_TEST_USER_PASSWORD` |

> **Filter note:** default `LDAP_USER_FILTER` is `(sAMAccountName={username})`. Confirm
> the test accounts' `sAMAccountName` (the `CN` contains a space, so it is *not*
> the login name). If login should accept UPN, set
> `LDAP_USER_FILTER=(userPrincipalName={username})` or
> `(|(sAMAccountName={username})(userPrincipalName={username}))`.

---

## Secrets handling

> **These are lab credentials** (operator confirmed — work/production credentials
> are never shared here). So the rules below are ordinary hygiene, not
> incident-grade handling. Assume anything the operator provides is lab-scoped.

1. Keep them out of the repo, the image, and CI logs anyway — a lab credential
   committed to git is still a bad habit to normalize.
2. Store in GitHub Actions **encrypted secrets** (or a vault): `CW_LDAP_BIND_PASSWORD`,
   `CW_LDAP_TEST_ADMIN_PASSWORD`, `CW_LDAP_TEST_USER_PASSWORD`, `CW_LDAP_CA_CERT`.
3. Rely on Actions masking; no `echo $SECRET`.
4. The service account should still be **least-privilege read-only** to the lab directory.
5. Synthetic-LDAP CI (Slice 1–2) uses **throwaway** in-config credentials; the
   lab directory (Slice 3) is only touched from a runner with network
   line-of-sight (see Risks → self-hosted runner).

---

## Slices

### Slice 1 — Synthetic LDAP E2E (no secrets; the default gate)
- Add a session fixture (e.g. `tests/e2e/ldap_fixtures.py`) that launches
  **glauth** (single cross-platform Go binary, fetched from its GitHub release;
  not vendored) with a declarative config mirroring the real OU/group shape:
  base `dc=ad,dc=hraedon,dc=com`, groups `cert-watch-admins` + `cert-watch-users`,
  users `cw-admin` (admins) and `cw-user` (users), plus a `cert-watch` bind acct.
- Boot cert-watch against it: `AUTH_PROVIDER=ldap`, `LDAP_SERVER=ldap://127.0.0.1:<port>`,
  matching base DN / bind DN, and `LDAP_GROUP_FILTER=memberOf={group}` (glauth
  does **not** implement AD's transitive OID — captured as a fidelity gap, see
  Slice 3).
- New `tests/e2e/test_ldap_login.py`:
  - admin logs in via the real form → lands on dashboard, write controls visible;
  - read-only user logs in → dashboard visible, write controls absent (asserts 2b once it lands; until then assert auth succeeds + correct group on session);
  - wrong password → rejected with the login error;
  - user outside both groups → access denied.
- Mark `e2e`. **AC:** all pass locally with `pytest -m e2e tests/e2e/test_ldap_login.py -n0`.

### Slice 2 — CI wiring for synthetic (extend `e2e.yml`)
- Reuse the existing `e2e` job; ensure the glauth binary is fetched/cached on
  the runner. Add a **windows-latest** matrix leg (your deploy target) so the
  glauth-on-Windows + LDAP path is exercised.
- **AC:** synthetic LDAP E2E green on ubuntu + windows in CI, on every PR, with no secrets.

### Slice 3 — Real-staging fidelity job (secrets-gated, periodic)
- Same Playwright tests, parametrized to point at the real directory via the
  topology table + secrets. Triggers: `workflow_dispatch` + nightly `schedule`
  (NOT per-PR).
- Validates what glauth can't: AD referrals, **transitive** group nesting (the
  `1.2.840.113556.1.4.1941` filter), LDAPS + `CW_LDAP_CA_CERT` pinning, multi-DC
  failover (also exercises bug 3's per-source test), UPN vs sAMAccountName.
- **Runner:** requires line-of-sight to `mvmdc0x` → **self-hosted runner inside
  the network** (GitHub-hosted runners can't reach `ad.hraedon.com`). Decision
  needed (see Risks).
- **AC:** admin + read-only test users authenticate against the real directory and
  land with correct authorization; failures surface the provider error verbatim.

### Slice 4 — Agentic browser layer
- Wire a **Playwright MCP server** (`@playwright/mcp`) into Claude Code so an
  agent drives the live UI from a task brief ("log in as cw-admin, open a cert,
  set owner, reload, confirm it persisted; then repeat as cw-user and confirm
  the owner controls are absent").
- Runs against the synthetic server (anytime) and the staging server (from the
  in-network runner / operator workstation). Retires the brittleness tracked in
  **BC-132**, and produces a natural-language audit trail of UI actions.
- **AC:** an agent completes the admin + read-only journeys against synthetic LDAP
  and reports pass/fail per step without hard-coded selectors.

### Slice 5 — (cross-link) Validate bug 2b against Slice 1
- Once group→role mapping (admins→admin, users→read-only) is implemented, the
  Slice 1 read-only assertions become the acceptance test for 2b. No separate
  harness needed.

---

## Testing

- Slices 1–3: pytest `-m e2e -n0` (single app instance, not parallel-safe — per
  the existing `e2e.yml` note).
- Keep the mocked unit suites (`test_auth.py`, `test_settings.py`) as the fast
  inner loop; E2E is the outer loop.
- Coverage ratchet (`--cov-fail-under=88`) applies to the unit suite only; E2E
  runs `--no-cov`.

## Risks / decisions

- **glauth dependency** — adds a test-time binary. Mitigation: fetch from a
  pinned release in the fixture/CI, cache it; no app dependency.
- **Synthetic ≠ AD fidelity** — glauth lacks the transitive `memberOf` OID and
  AD referral behavior. Mitigation: Slice 3 covers it; Slice 1 uses the simple
  `LDAP_GROUP_FILTER` knob. Document the delta so a synthetic pass is never
  mistaken for AD-validated.
- **Network reachability for Slice 3** — GitHub-hosted runners can't reach
  internal DCs. **Decision required:** self-hosted runner inside the network, or
  run Slice 3 only via the agentic layer from an in-network host. (Synthetic
  Slices 1–2 are unaffected.)
- **Secret hygiene** — lab credentials, but still kept out of the repo/logs and
  in the CI secret store (see Secrets).
- **Windows glauth path** — confirm the binary + LDAP socket behave under
  windows-latest before relying on Slice 2's Windows leg.
- **Entra** — its hosted login + MFA is the strongest case for the agentic layer
  (Slice 4). MVP scoped in the appendix below.

---

## Appendix A — Entra / OIDC MVP (lab tenant, no AD sync)

**Headline: no directory sync is required.** cert-watch authenticates Entra users
via OIDC authorization-code flow; it never reads the on-prem directory. **Cloud-only
users created directly in the lab tenant are sufficient — do not resync for this.**
(Resync only matters if you specifically want to validate *hybrid* on-prem-sourced
identities, which is not needed to validate cert-watch's OIDC integration.)

### Entra coordinates (lab — non-secret identifiers)
- Application (client) ID: `6da66046-d2b1-4678-bffb-196b3acec2dd` → `OAUTH_CLIENT_ID`
- Directory (tenant) ID: `863ba439-36cd-4208-99b3-4e566d61d871`
- `OAUTH_ISSUER_URL=https://login.microsoftonline.com/863ba439-36cd-4208-99b3-4e566d61d871/v2.0`
- Client secret → Vault `secret/cert-watch/entra/app` key `client_secret`
- Test-user passwords → Vault `secret/cert-watch/entra/cert-watch-admin|cert-watch-user` key `password`
- Group GUIDs for `CERT_WATCH_ALLOWED_GROUPS`: _TBD — read from Entra → Groups → Object ID_

### What cert-watch needs (provider: `oauth`)
- `AUTH_PROVIDER=oauth`
- `OAUTH_ISSUER_URL=https://login.microsoftonline.com/<tenant-id>/v2.0` (endpoints
  auto-discovered via OIDC `.well-known`)
- `OAUTH_CLIENT_ID=<app reg client id>`
- `OAUTH_CLIENT_SECRET` → secret `CW_OAUTH_CLIENT_SECRET`
- `OAUTH_SCOPE="openid profile email"`
- `CERT_WATCH_BASE_URL=<https origin>` — **required**; the redirect URI is
  `${BASE_URL}/auth/callback`. cert-watch refuses to derive it from the Host header
  (`routes/auth.py:_get_base_url`). For local E2E, `http://localhost:<port>` is
  accepted by Entra (localhost is the one http exception).

### Two MVP tiers

**MVP-0 — login only (works today, zero code change).**
1. Lab tenant (have it). **Keep MFA on** — automation completes the MFA prompt
   with a TOTP code brokered by Vault (see Appendix A.1). No Security-Defaults
   disable, no Conditional Access exclusions.
2. Create two **cloud-only** users: `cw-admin`, `cw-user`, and register a **TOTP
   authenticator** method for each (capture the seed → Vault, per A.1).
3. App registration:
   - Web platform redirect URI `${BASE_URL}/auth/callback`.
   - New client secret → `CW_OAUTH_CLIENT_SECRET`.
   - ID tokens enabled (auth-code flow).
   - Enterprise app → **Assignment required = Yes** so only assigned users sign in.
4. Set the env above; any assigned user can log in. **No role distinction yet.**

**MVP-1 — admin vs read-only (needs a small code change — this is bug 2b for Entra).**
- **Gap:** `src/cert_watch/auth/oauth_provider.py:411` returns
  `AuthResult(success=True, username=username)` and **does not populate
  `groups`/`roles`** from the verified claims. So `check_authz` sees no roles and
  there is no admin/read-only distinction today.
- **App-side (free tier, no P1/P2, no sync):** define **App Roles** `admin` and
  `readonly` in the app registration manifest; **assign the roles directly to the
  two users** (direct user→role assignment is free; assigning roles to *groups*
  is what needs P1/P2). Entra then emits a `roles` claim in the ID token.
- **Code change (decided: extract BOTH):** populate `AuthResult.roles` from
  `claims.get("roles", [])` (app-role values) **and** `AuthResult.groups` from
  `claims.get("groups", [])` on the success path (`oauth_provider.py:411`). Then
  gate with `CERT_WATCH_ALLOWED_ROLES` and/or `CERT_WATCH_ALLOWED_GROUPS`. Same
  `roles`/`groups`-population fix the LDAP side needs for 2b — do them together.
- **Groups caveat + the free/P1 line (verified against MS docs):**
  - **Free:** Token configuration → groups claim → **Security groups** ("All
    groups" path). Emits all the user's security-group **object-ID GUIDs**. No
    group→app assignment needed. This is the path to use.
  - **P1 (avoid on free tenant):** "Groups assigned to the application" claim
    option, and *assigning a group* to the enterprise app or to an app role.
    "A free tenant can't assign groups to an application." → assign the two
    **users** directly to the app roles instead (free).
  - Cloud-only groups emit **GUIDs, not names**, so `CERT_WATCH_ALLOWED_GROUPS`
    matches GUIDs — record the two group GUIDs in config (App roles stay the
    human-readable path).
  - **Overage:** a user in >200 groups gets a `_claim_names`/`_claim_sources`
    pointer instead of the list (Graph callback needed) — not a concern for the
    lab, but the code should tolerate the `groups` claim being absent.

### Entra E2E / agentic notes
- The Microsoft hosted login page **must be driven by a browser** and its markup
  changes without notice → this is the prime candidate for the **agentic layer
  (Slice 4)** rather than brittle scripted selectors.
- Keep the Entra E2E job `workflow_dispatch`/scheduled (secrets-gated), never
  per-PR. The synthetic LDAP gate stays the per-PR signal.
- Secrets: `CW_OAUTH_CLIENT_SECRET`, plus the two test-user passwords
  (`CW_ENTRA_TEST_ADMIN_PASSWORD`, `CW_ENTRA_TEST_USER_PASSWORD`) in the CI
  secret store. Lab credentials, same hygiene as the LDAP secrets above.

### Decisions for the operator
1. ✅ **Vault** TOTP secrets engine (seed sealed in Vault, codes audited). (A.1)
2. ✅ **App Roles + groups** — extract both `roles` and `groups` claims; groups
   match by GUID (cloud-only caveat above).
3. Open: bundle MVP-1 (the roles+groups claim change) with the LDAP-side 2b fix,
   or stand up MVP-0 (login-only) first? (Leaning: bundle — same code path.)

---

## Appendix A.1 — MFA-intact automation via Vault-brokered TOTP

Goal: never exclude a test account from MFA. The automation completes the second
factor like a user would, but the TOTP **seed never leaves the secret manager** —
the E2E job / agent only ever pulls an ephemeral 6-digit code.

### Why this is possible on Free tier (grounded in Microsoft docs)
- Entra ID Free + Security Defaults allows "mobile app as a second factor"; a
  **software-OATH TOTP** seed is generated and **shown at registration** (the
  "use a different authenticator app / can't scan the QR?" screen reveals the
  base32 key). We capture that seed once.
- The **admin-provisioned** OATH-token upload (Graph/CSV) is cleaner and fully
  scriptable but requires admin control over methods ≈ **P1** — list as an upgrade
  once licensed; not needed for MVP.
- Pick **TOTP / verification-code**, *not* Authenticator push with number
  matching — push needs a human to approve and can't be automated.

### One-time setup (per test user)
1. Register a TOTP method for `cw-admin` / `cw-user`; on the QR screen choose
   "enter manually" to reveal the base32 `secret`.
2. Load it into Vault's **TOTP secrets engine** as a *key* (Vault stores the seed
   and generates codes):
   ```
   vault secrets enable totp
   vault write totp/keys/entra-cw-admin \
     url="otpauth://totp/Entra:cw-admin@<tenant>?secret=<BASE32>&issuer=Entra&algorithm=SHA1&digits=6&period=30"
   ```
   (Repeat for `cw-user`. The on-prem LDAP test users don't need this — LDAP has
   no MFA in the directory bind path.)

### At login (E2E fixture / agent)
1. Pull the user password from Vault KV (or CI secret).
2. Enter username + password on the Entra page.
3. When prompted for the code:
   ```
   vault read -field=code totp/code/entra-cw-admin   # -> 123456
   ```
4. Type it, submit. Vault logs every code read (provenance) and handles the time
   window; ensure the **runner clock is NTP-synced** (TOTP is time-sensitive).

### Auth to Vault from CI / agent
- CI: Vault **AppRole** (role-id in config, secret-id from the CI secret store) or
  GitHub OIDC → Vault JWT auth (no long-lived token).
- Agent/in-network host: a short-TTL Vault token or AppRole; least-privilege
  policy granting only `read` on `totp/code/entra-*` and the relevant KV paths.

### Bitwarden alternative
`bw get totp <item-id>` returns the current code from a stored authenticator key;
works, but Vault's TOTP engine is the better fit here — the seed is sealed
server-side and every code issuance is audit-logged, which matches the provenance
goal. Bitwarden stores the seed in the vault item and computes client-side.

### Note: this also un-blocks "remember MFA"
Headless runs use a fresh browser each time, so Entra prompts for MFA every run —
which is exactly what we want to exercise. The Vault-TOTP path makes that a
non-event instead of a blocker.

---

## Appendix A.2 — Credential management in k8s (broader solution)

Two distinct consumers, each with a different right answer. The mistake is using
one mechanism for both.

### Consumer 1 — cert-watch at runtime (the app pod)
cert-watch already supports the `<NAME>_FILE` convention (`config.py:read_secret`):
any secret can be a file path instead of an env value. That makes the
lowest-friction k8s fit:

- **Vault Agent Injector (recommended).** Pod annotations render secrets to
  `/vault/secrets/*`; set `OAUTH_CLIENT_SECRET_FILE=/vault/secrets/oauth_client_secret`,
  `LDAP_BIND_PASSWORD_FILE=/vault/secrets/ldap_bind_password`, `LDAP_CA_CERT_FILE`,
  `SMTP_PASSWORD_FILE`, etc. **Zero app changes** — it rides the existing `_FILE`
  support. Auth via k8s method (pod ServiceAccount → Vault role → least-priv policy).
- **Alternative — Vault Secrets Operator (VSO)** or **External Secrets Operator
  (ESO):** sync Vault → native k8s `Secret`, then mount as env/files. Pick this if
  you prefer native Secrets / no sidecars; ESO if you want a vendor-neutral layer.

Recommendation: **Vault Agent Injector** for cert-watch (best `_FILE` fit); adopt
VSO/ESO only if a no-sidecar/native-Secret policy already exists.

### Consumer 2 — the agent / CI driving E2E
- **CI:** Vault **AppRole** or **GitHub OIDC → Vault JWT** (no long-lived token).
  Policy scoped to read only `secret/data/cert-watch/entra/*` and `totp/code/entra-*`.
- **Agentic layer — the "Vault MCP" idea (good, with one hard rule):**
  - **Do** expose the **TOTP codes** to the agent via an MCP: `totp/code/entra-*`
    returns an ephemeral 30-second code, so even passing through the agent's
    context is low-risk, and every issuance is Vault-audited (fits the provenance
    goal). A thin MCP scoped to *only* `totp/code/*` is trivial and safe; community
    Vault MCP servers also exist.
  - **Don't** let the agent read raw KV passwords. Those go straight into the
    **test process** (Playwright) from Vault via env/file — never into the agent's
    chat context. Separate the token/policy the MCP uses (codes only) from the one
    the runner uses (passwords).
  - Net rule: **agent sees ephemeral codes; the process sees passwords.** This is
    the same seed-never-leaves-Vault discipline applied to the human/agent boundary.

### Why this generalizes the pain point
Standardizing on **Vault + k8s auth**, with the Injector for workloads and scoped
AppRole/OIDC (+ a codes-only MCP) for agents/CI, gives one issuance+audit plane
for every secret cert-watch touches — runtime, CI, and agentic — instead of the
per-surface ad-hoc handling that's been the friction.
