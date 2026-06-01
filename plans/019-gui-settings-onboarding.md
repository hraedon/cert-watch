# Plan 019: GUI Settings & Guided Onboarding

> **Status:** ready for implementation. Grounded in the code as of `780d4aa`.
> Extends Plan 014 (onboarding) with the missing middle: getting from
> "local admin created" to "LDAP/OAuth configured" without env vars.

## Why this matters

The setup wizard (Plan 014) handles the first 5 minutes well. But the next
30 minutes — configuring real auth, SMTP, and a first host — require editing
env vars, restarting the container, and hoping it works. The target audience
(regulated AD shops) needs guided configuration, not a README to read.

The `kv_store` table + in-memory provider rebuild pattern is already proven
by the setup wizard. This plan extends it to all configuration.

---

## The user journey (before → after)

**Before (today):**
1. `docker run` → setup wizard → local admin created → dashboard
2. Read README to find LDAP env vars
3. Edit docker-compose.yml, add 10+ env vars
4. Restart container
5. Pray it works (no validation, errors only in logs)
6. Repeat for SMTP, alerts, etc.

**After (this plan):**
1. `docker run` → setup wizard → local admin created → dashboard
2. Click "Settings" in header → Auth tab → select LDAP
3. Fill in server, base DN, bind DN, password → "Test Connection" → green checkmark
4. Click "Apply" → provider rebuilt in-memory, no restart
5. Settings tab for SMTP → test email → apply
6. Guided first-host add from dashboard empty state

---

## Slice 1 — Settings page shell + auth config (do first)

### New route: `routes/settings.py`

```
GET  /settings          → render settings.html (tabs: Auth, Alerts, SMTP, General)
POST /settings/auth     → save auth config to kv_set, rebuild provider
POST /settings/smtp     → save SMTP config to kv_set
POST /settings/alerts   → save alert config to kv_set
POST /settings/test-ldap → test LDAP bind, return JSON {ok: bool, error: str}
POST /settings/test-smtp → test SMTP send, return JSON {ok: bool, error: str}
```

All routes auth-gated (require admin role). CSRF-protected.

### kv_store keys for auth config

```
auth_provider          = "" | "ldap" | "oauth" | "entra"
ldap_server            = "ldap://dc1.example.com"
ldap_base_dn           = "DC=example,DC=com"
ldap_bind_dn           = "CN=svc,OU=..."
ldap_bind_password     = "..."  (sensitive)
ldap_user_filter       = "(sAMAccountName={username})"
ldap_start_tls         = "0" | "1"
ldap_ca_cert           = "-----BEGIN CERTIFICATE-----..."
ldap_required_groups   = "CN=Group1,..."
ldap_connect_timeout   = "5"
oauth_client_id        = "..."
oauth_client_secret    = "..."  (sensitive)
oauth_issuer_url       = "https://login.microsoftonline.com/..."
oauth_scope            = "openid profile email"
```

### Settings merge logic

Config resolution order (highest priority first):
1. Environment variables (explicit overrides, never written by GUI)
2. `kv_store` values (GUI-written)
3. Hardcoded defaults

In `Settings.from_env()`, after reading env vars, fall back to `kv_get()`
for any unset field. This is the same pattern as local admin in `app.py:106-116`.

### Auth provider rebuild on save

When `POST /settings/auth` saves, call `build_auth_provider()` with the
merged config and assign `request.app.state.auth_provider`. Same pattern
as `setup.py:100-123`. No restart needed.

If `build_auth_provider()` raises `ValueError` (e.g. LDAP missing required
fields), return the error to the form — don't apply.

### Template: `templates/settings.html`

Tabs with Alpine.js or plain JS toggle:
- **Auth tab**: provider dropdown (none/local-admin/LDAP/OAuth) →
  show/hide provider-specific fields. "Test Connection" button.
- **SMTP tab**: host, port, user, password, from addr. "Send Test" button.
- **Alerts tab**: recipients, webhook URL, thresholds.
- **General tab**: data dir (read-only), scheduler time, TLS verify toggle.

Existing CSS classes (`cw-panel`, `cw-form-panel`, `cw-btn`, `cw-input`)
from `tokens.css`. No new CSS needed.

### Tests

- GET /settings returns 200 with auth config form
- POST /settings/auth with valid LDAP config → saved to kv_set, provider rebuilt
- POST /settings/auth with invalid config → error returned, provider unchanged
- POST /settings/test-ldap with mock → returns {ok: true} or {ok: false, error: ...}
- Config merge: env var overrides kv_store value
- CSRF required on all POST endpoints
- Non-admin user gets 403

### AC

- AC-1: An operator can configure LDAP auth from the GUI without editing env vars.
- AC-2: "Test Connection" validates LDAP bind before applying.
- AC-3: Auth provider changes take effect without restart.
- AC-4: Env vars always override GUI settings (escape hatch).

---

## Slice 2 — Extended setup wizard (steps 2-3)

### Modify `routes/setup.py` and `templates/setup.html`

Step 1 (local admin) is done. Add:

**Step 2 — SMTP (optional):**
- Fields: host, port, user, password, from addr, recipients
- "Send Test Email" button → POST /settings/test-smtp
- "Skip" button → proceed to step 3
- Save to kv_set on submit

**Step 3 — First host:**
- Reuse the add-host form pattern from `templates/index.html`
- "Skip" button → finish setup
- On submit → add host via existing `SqliteHostRepository`, redirect to dashboard

### Setup flow change

After step 1 completes, don't redirect to `/`. Redirect to `/setup?step=2`.
After step 3 (or skip), set `kv_set("setup_complete", "1")` and redirect to `/`.

### Tests

- Setup wizard shows step 2 after step 1 completes
- Step 2 "Skip" proceeds to step 3
- Step 3 "Skip" completes setup, redirects to /
- Step 3 host submission adds host to DB
- setup_complete flag prevents re-triggering

### AC

- AC-5: After setup, the operator has a local admin AND optionally SMTP and a first host.
- AC-6: Each step can be skipped.

---

## Slice 3 — Dashboard guided empty state

### Modify `templates/index.html`

When no hosts exist, instead of just the "no certificates" message:

```
Welcome to cert-watch! Get started:

1. Add a host to scan        [Add Host →]
2. Upload a certificate       [Upload →]
3. Configure alerting         [Settings →]
```

Links to the existing add-host modal, upload form, and `/settings`.

### Tests

- Empty dashboard shows guided onboarding links
- Links point to correct destinations

### AC

- AC-7: Fresh install dashboard guides the user to their first action.

---

## Sequencing

1. **Slice 1** (settings page + auth config) — highest leverage, unblocks the journey
2. **Slice 2** (extended wizard) — improves first-run, depends on slice 1 for SMTP test
3. **Slice 3** (empty state) — quick win, independent

## Risk notes

- **Secrets in kv_store**: OAuth client secret and LDAP bind password stored in
  SQLite plaintext. Same risk as the local admin password hash (already stored).
  At-rest encryption is a separate concern (future: OS-level or SQLCipher).
- **Provider rebuild race**: A request in-flight during provider swap could see
  the old or new provider. This is acceptable — the window is milliseconds and
  the worst case is a redirect to login.
- **Env var / kv_store confusion**: An operator who sets both may be surprised
  that env vars win. The settings page should display a warning when an env var
  overrides a GUI value: "LDAP_SERVER is set via environment variable; GUI
  value will not take effect."

## Docs

- README: new "Configuration" section noting GUI settings are available
- Runbook: "Auth configuration" section updated with GUI instructions
- AGENTS.md: new env vars (`CERT_WATCH_*`), settings page note
