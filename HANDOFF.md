# cert-watch — Session Handoff (2026-06-05, updated)

Resume doc for the agentic-LDAP-E2E work. Read this first.

---

## TL;DR — RESUME HERE

**Goal:** an agent does a full **LDAP E2E UI-aware runthrough** against the real lab
AD (cw-admin / cw-user log in through the browser; access gating works).

**STATUS: ✅ RUNTHROUGH IS GREEN.** Both cw-admin and cw-user log in through the
browser via real AD LDAPS and land on the dashboard; bad creds are rejected with
"invalid credentials". Verified via screenshots (`/tmp/shot_02_{admin,user}.png`,
`/tmp/shot_03_badcreds.png`). Server was running on **port 8771** at handoff time.

Getting here took **three** real cert-watch bug fixes (two from the prior session,
one found this session — see below), each now covered by **regression tests**.
Full suite: **1262 passed, coverage 89.87%**.

**The earlier blocker (secret-id expired) is resolved** — operator refreshed the
`cert-watch-setup` secret-id into `~/.cw-vault-setup.env`. If it expires again,
re-run (operator, admin token):
```bash
export VAULT_ADDR=https://vault.k8s.hraedon.com   # + admin VAULT_TOKEN
vault write auth/approle/role/cert-watch-setup secret_id_ttl=8h token_policies=cert-watch-setup
vault write -f -field=secret_id auth/approle/role/cert-watch-setup/secret-id
```
Paste into `~/.cw-vault-setup.env` as `VAULT_SECRET_ID=…` (role-id + addr unchanged).

**What's left:** commit the session's work (see inventory) and pick up the backlog
(RBAC / Plan 035 is the big one — today proves login + access gating, NOT role
differentiation; admin and user currently see the same UI incl. "Add host").

---

## Three bugs fixed (UNCOMMITTED — in working tree), all regression-tested

All three broke **private-CA LDAPS auth** and were invisible to the mocked unit
tests (the `MagicMock` Connection swallowed bad kwargs; comma-split never hit a
real DN). The live E2E caught all three.

1. `src/cert_watch/auth/ldap_provider.py` `_resolve_ca_cert()` — `Path(pem).is_file()`
   raises `OSError(ENAMETOOLONG)` on inline PEM **contents** (the normal case),
   surfacing as a generic "authentication failed". Fixed: guard PEM/long/multiline
   strings and wrap the stat in try/except.
2. Same file, `authenticate()` — passed `use_ssl=` to `ldap3.Connection(...)`,
   which has no such kwarg (it's a `Server` arg); current ldap3 rejects it. Fixed:
   removed from both the service-bind and user-bind `Connection()` calls.
3. **NEW this session** — `src/cert_watch/config.py` parsed `LDAP_REQUIRED_GROUPS`
   by splitting on `,`. Group DNs *contain* commas, so each DN was shredded into
   RDN fragments (`CN=…`, `OU=Groups`, `DC=…`) → the group filter matched nothing
   → every login failed "not in required group(s)". This path was broken for ANY
   real DN. Fixed: new `split_group_dns()` helper splits on **`;`/newline** (used
   by both the env-parse and the persisted/settings-UI parse); subnets stay on
   comma. Settings UI label updated to "semicolon-separated DNs".

**Regression tests added (this session):**
- `tests/test_auth.py` — stricter fake `ldap3.Connection` that rejects unknown
  kwargs (catches bug #2) + inline-PEM / ENAMETOOLONG paths (bug #1). 5 tests.
  Mutation-verified: reintroducing either bug makes them fail (bug #1 reproduces
  the literal `OSError: [Errno 36] File name too long`).
- `tests/test_settings.py` — `split_group_dns` + env/kv parse keep full DNs (bug
  #3). 5 tests.

**Breadcrumbs:** not filed — all three are fixed + regression-guarded, so the
history belongs in the commit message.

---

## Full uncommitted inventory (nothing committed this session)

Branch `main`, last commit `13e9248`. `git status` working tree:

**My changes (this session):**
- `src/cert_watch/auth/ldap_provider.py` — the two LDAP bug fixes above
- `src/cert_watch/auth/oauth_provider.py` — Entra `roles`+`groups` claim extraction (2b groundwork) + test in `tests/test_auth.py`
- `src/cert_watch/routes/settings.py` — bug fixes: don't blank secrets on save; per-server LDAP test; SMTP STARTTLS opportunistic
- `src/cert_watch/alerts.py` — `negotiate_starttls()` helper (port-25 fix) + tests in `tests/test_alerts.py`
- `src/cert_watch/templates/certificate_detail.html` — owner/notes toggle two-click fix
- `tests/test_settings.py`, `tests/test_no_inline_styles.py` — tests + ratchet 19→3
- `deploy/vault/` (NEW) — policies (`cert-watch-{setup,app,e2e-runner,totp-mcp}.hcl`) + `README.md` runbook
- `plans/034-agentic-e2e-auth-validation.md`, `plans/035-role-based-authorization.md` (NEW)
- `.gitignore` — secret-file backstops

**NOT mine — verify before committing:**
- `src/cert_watch/static/css/tokens.css`, `src/cert_watch/templates/settings.html` — Kimi's BC-127 settings redesign (kept; I fixed the ratchet)
- `scripts/install-windows.ps1` — modified, origin unknown, did not touch this session
- `hraedon_root.cer` — lab root CA (public cert; consider moving to `deploy/vault/` or gitignoring)
- `.coverage.*` untracked artifacts — ignore/clean

**Action:** commit the bug fixes + tests + plans + deploy/vault on a branch once the
runthrough is green. Run full suite first (`uv run pytest`).

---

## Exact resume procedure (after secret-id refresh)

### 1. Rebuild the CA bundle (EPHEMERAL — /tmp is wiped on reset)
The DC LDAPS cert chains `leaf → ad-MVMCA01 → Hraedon Root CA`. Root is at
`/projects/cert-watch/hraedon_root.cer`. Build a bundle (root + issuing from the
live handshake) so Python `ssl` (CERT_REQUIRED, no partial-chain) validates:
```bash
cd /tmp
openssl s_client -connect mvmdc01.ad.hraedon.com:636 -showcerts </dev/null 2>/dev/null \
  | awk '/BEGIN CERT/{f=1} f{print} /END CERT/{f=0}' > chain.pem
csplit -z -s -f xc_ -b '%02d.pem' chain.pem '/-----BEGIN CERTIFICATE-----/' '{*}'
cat /projects/cert-watch/hraedon_root.cer xc_01.pem > /tmp/cw_ldap_ca.pem   # root + issuing
```
(Root-only may also work since the DC presents the issuing CA; bundle is safest.)

### 2. Relaunch cert-watch (run_in_background=true; use a FRESH port; do NOT pkill+relaunch the same port — that races to exit 144)
```bash
cd /projects/cert-watch
source ~/.cw-vault-setup.env
SETUP_TOK=$(vault write -field=token auth/approle/login role_id="$VAULT_ROLE_ID" secret_id="$VAULT_SECRET_ID")
E2E_RID=$(VAULT_TOKEN="$SETUP_TOK" vault read -field=role_id auth/approle/role/cert-watch-e2e/role-id)
E2E_SID=$(VAULT_TOKEN="$SETUP_TOK" vault write -f -field=secret_id auth/approle/role/cert-watch-e2e/secret-id)
E2E_TOK=$(vault write -field=token auth/approle/login role_id="$E2E_RID" secret_id="$E2E_SID")
export AUTH_PROVIDER=ldap
export LDAP_SERVER=ldaps://mvmdc01.ad.hraedon.com,ldaps://mvmdc02.ad.hraedon.com,ldaps://mvmdc03.ad.hraedon.com
export LDAP_BASE_DN=DC=ad,DC=hraedon,DC=com
export LDAP_BIND_DN=$(VAULT_TOKEN="$E2E_TOK" vault kv get -field=bind_dn  kv/cert-watch/ldap/bind)
export LDAP_BIND_PASSWORD=$(VAULT_TOKEN="$E2E_TOK" vault kv get -field=password kv/cert-watch/ldap/bind)
export LDAP_USER_FILTER='(sAMAccountName={username})'
export LDAP_CA_CERT_FILE=/tmp/cw_ldap_ca.pem
export LDAP_REQUIRED_GROUPS='CN=cert-watch-admins,OU=Groups,DC=ad,DC=hraedon,DC=com;CN=cert-watch-users,OU=Groups,DC=ad,DC=hraedon,DC=com'  # NOTE: semicolon-separated (DNs contain commas — see bug #3)
export CERT_WATCH_DATA_DIR=/tmp/cw-ldap-data
export CERT_WATCH_COOKIE_SECURE=0
exec .venv/bin/python -m cert_watch --host 127.0.0.1 --port 8770 > /tmp/cw-ldap.log 2>&1
```
Health: `curl -s --retry 40 --retry-delay 1 --retry-connrefused http://127.0.0.1:8770/healthz`

### 3. Run the agentic runthrough
Script is ephemeral — recreate `/tmp/cw_runthrough.py` (content in "Runthrough
script" below), then:
```bash
source ~/.cw-vault-setup.env
SETUP_TOK=$(vault write -field=token auth/approle/login role_id="$VAULT_ROLE_ID" secret_id="$VAULT_SECRET_ID")
E2E_RID=$(VAULT_TOKEN="$SETUP_TOK" vault read -field=role_id auth/approle/role/cert-watch-e2e/role-id)
E2E_SID=$(VAULT_TOKEN="$SETUP_TOK" vault write -f -field=secret_id auth/approle/role/cert-watch-e2e/secret-id)
E2E_TOK=$(vault write -field=token auth/approle/login role_id="$E2E_RID" secret_id="$E2E_SID")
export CW_BASE=http://127.0.0.1:8770
export CW_ADMIN_PW=$(VAULT_TOKEN="$E2E_TOK" vault kv get -field=password kv/cert-watch/ldap/cw-admin)
export CW_USER_PW=$(VAULT_TOKEN="$E2E_TOK" vault kv get -field=password kv/cert-watch/ldap/cw-user)
.venv/bin/python /tmp/cw_runthrough.py
```
Expected now (both bugs fixed): cw-admin & cw-user land on the dashboard
(`on_dashboard=True`); bad creds rejected. Then read the screenshots
(`/tmp/shot_*.png`) to narrate the UI-aware part.

---

## Key coordinates (NON-SECRET; secrets live in Vault)

- **AD:** domain `ad.hraedon.com`; base DN `DC=ad,DC=hraedon,DC=com`; DCs `mvmdc01/02/03`
- **Transport:** **LDAPS 636 only** — 389 refused (`strongerAuthRequired`, signing enforced)
- **Bind acct:** `CN=cert-watch,OU=Service,OU=Accounts,DC=ad,DC=hraedon,DC=com`
- **Test users:** `cw-admin` (→`cert-watch-admins`), `cw-user` (→`cert-watch-users`); login by `sAMAccountName`
- **Group DNs:** `CN=cert-watch-admins,OU=Groups,…` / `CN=cert-watch-users,OU=Groups,…`
- **CA:** DC cert chains to `Hraedon Root CA` (NOT published in AD — the directory
  publishes a different root, "Merritt Homelab Root CA"; DC cert is stale-PKI).
  Root provided at `hraedon_root.cer`. *Lab follow-up: re-issue DC certs under the
  current root, then the AD-published bundle validates without the manual root.*
- **Entra (for later, MVP not yet run):** client `6da66046-d2b1-4678-bffb-196b3acec2dd`,
  tenant `863ba439-36cd-4208-99b3-4e566d61d871`, group GUIDs admins
  `38171415-ded8-4e14-9a44-439bc5223f50` / users `65a2fd9f-0138-4b57-9a7b-3fe4236c7c64`

## Vault (provisioned + verified this session)
- KV v2 at **`kv/`** (not `secret/`). Secrets: `kv/cert-watch/entra/{app,cert-watch-admin,cert-watch-user}`, `kv/cert-watch/ldap/{bind,cw-admin,cw-user}`
- Policies: `cert-watch-{setup,app,e2e-runner,totp-mcp}` — trust split verified (mcp=codes only; runner=passwords+codes; neither reads seeds)
- AppRoles: `cert-watch-e2e`, `cert-watch-totp-mcp` (+ `cert-watch-setup` for automation)
- k8s auth: role `cert-watch` (SA `cert-watch/cert-watch` → `cert-watch-app`) — end-to-end verified
- TOTP: `totp/keys/entra-cert-watch-{admin,user}` live (Entra MFA-intact automation)
- vault CLI at `~/.local/bin/vault` (v1.19.5). TLS validates cleanly (no `-k`).

## Environment notes (post-reset)
- `.venv` has ldap3 + playwright + authlib/joserfc (persists with repo). If missing:
  `uv pip install -e '.[dev,e2e,auth-ldap,auth-oauth]'` + `.venv/bin/playwright install chromium`.
- kubectl: context `default` (`api.k8s.hraedon.com`); `kubectl config use-context default` if unset.
- `/tmp/*` is gone after reset: CA bundle, `cw_runthrough.py`, screenshots — recreate from this doc.

---

## Backlog / next steps (priority order)
1. ✅ DONE — refreshed secret-id, ran the runthrough, confirmed green (3rd bug found+fixed en route).
2. ✅ DONE — regression tests for all three LDAP bugs (stricter fake ldap3 + group-DN split). Breadcrumbs intentionally skipped (fixed + tested).
3. **Commit the session's work on a branch** (3 bug fixes, the 10 new regression tests, plans, deploy/vault); run full suite (now 1262 passing). NOT yet committed.
4. **Implement Plan 035 (RBAC)** — needed for admin-vs-read-only *write* gating; today's runthrough only proves login + access gating, not role differentiation (admin & user see the same UI incl. "Add host").
5. **Scope the operator-requested feature** (NOT yet done): during the LDAP *test* operation, capture/accept the presented cert chain (TOFU auto-provision of the CA) — "even automatic provisioning is better than raw LDAP." This automates the openssl-s_client + AD-config-fetch dance I did manually.
6. Entra MVP runthrough (Plan 034 Appendix A) — uses the Vault TOTP broker (already live).
7. Deploy-time: migrate csrf/auth secrets into `kv/cert-watch/app` + rewire `deployment.yaml` to the Vault Agent Injector (`_FILE` env).
8. Housekeeping: shred `~/.cw-vault-setup.env` when done; decide on `hraedon_root.cer` placement.

## Runthrough script (recreate at /tmp/cw_runthrough.py)
```python
import os
from playwright.sync_api import sync_playwright
BASE = os.environ.get("CW_BASE", "http://127.0.0.1:8770")
ADMIN_PW = os.environ["CW_ADMIN_PW"]; USER_PW = os.environ["CW_USER_PW"]
def login(page, user, pw):
    page.goto(f"{BASE}/login", wait_until="domcontentloaded")
    page.fill("input[name=username]", user); page.fill("input[name=password]", pw)
    try: page.get_by_role("button", name="Sign in").click()
    except Exception: page.press("input[name=password]", "Enter")
    page.wait_for_timeout(1500); return page.url
with sync_playwright() as p:
    b = p.chromium.launch()
    ctx = b.new_context(); pg = ctx.new_page()
    pg.goto(f"{BASE}/login", wait_until="domcontentloaded"); pg.screenshot(path="/tmp/shot_01_login.png"); ctx.close()
    for tag, user, pw in [("admin","cw-admin",ADMIN_PW),("user","cw-user",USER_PW)]:
        ctx = b.new_context(); pg = ctx.new_page(); url = login(pg, user, pw)
        pg.screenshot(path=f"/tmp/shot_02_{tag}.png", full_page=True); body = pg.content()
        print(f"{tag.upper()} ({user}): url={url}")
        print(f"   on_dashboard={url.rstrip('/')==BASE}  shows_user={user in body}")
        ctx.close()
    ctx = b.new_context(); pg = ctx.new_page(); url = login(pg, "cw-admin", "deliberately-wrong-pw")
    pg.screenshot(path="/tmp/shot_03_badcreds.png")
    print(f"BADCREDS: url={url}  rejected={'login' in url}"); ctx.close(); b.close()
print("== runthrough complete ==")
```
