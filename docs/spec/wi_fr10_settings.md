# Interface Specification: FR-10 Settings GUI

## Dependencies

- `interface_ref`: `database_layer`
- `interface_ref`: `auth`

## AC-01: Settings Page

`GET /settings` must render a page with tabs:
- **Authentication** — provider selection, LDAP config, OAuth config
- **SMTP** — host, port, user, password, from address
- **Alerts** — webhook URL, recipients, digest mode, PagerDuty routing key

## AC-02: Auth Configuration Save

`POST /settings/auth` must:
- Accept `auth_provider`, `ldap_server`, `ldap_base_dn`, `ldap_bind_dn`, `ldap_bind_password`, `ldap_user_filter`, `ldap_start_tls`, `ldap_ca_cert`, `ldap_required_groups`, `ldap_connect_timeout`, `ldap_group_filter`, `oauth_client_id`, `oauth_client_secret`, `oauth_issuer_url`, `oauth_scope`, `oauth_authorization_endpoint`, `oauth_token_endpoint`, `oauth_userinfo_endpoint`, `base_url`.
- Encrypt sensitive fields (`ldap_bind_password`, `oauth_client_secret`) with `fernet_encrypt()` using the signing key-derived encryption key.
- Store all values in `kv_store`.
- Persist `auth_provider` to `kv_store` so it survives restart.
- Return a JSON response: `{ok: true, message: "Authentication settings saved"}`.

## AC-03: SMTP Configuration Save

`POST /settings/smtp` must:
- Accept `smtp_host`, `smtp_port`, `smtp_user`, `smtp_password`, `alert_from`.
- Encrypt `smtp_password`.
- Store in `kv_store`.
- Return JSON confirmation.

## AC-04: Alert Configuration Save

`POST /settings/alerts` must:
- Accept `webhook_url`, `webhook_template`, `webhook_kind`, `pagerduty_routing_key`, `alert_recipients`, `alert_digest_only`.
- Encrypt `pagerduty_routing_key`.
- Store in `kv_store`.
- Return JSON confirmation.

## AC-05: Test Connection Buttons

- **Test SMTP**: `POST /settings/test-smtp` sends a test email via `AlertConfig` and returns `{ok: true/false, error: "..."}`.
- **Test LDAP**: `POST /settings/test-ldap` attempts a service bind and user search, returns `{ok: true/false, error: "...", tofu: {...}}` (tofu block on cert verification failure for LDAPS).
- Blank numeric fields default to standard values (e.g., 587 for SMTP port, 5 for LDAP timeout) rather than 500-ing.

## AC-06: Environment Override

- Env vars always win over GUI values (`from_env_with_kv` already enforces env-wins via `_kv()`).
- The Settings page must show a warning when an env var is set, indicating that the GUI value is overridden.
- `CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH` and `CERT_WATCH_LOCAL_ADMIN_USER` env vars override kv_store values.

## AC-07: API Keys Management

`GET /settings/api-keys` page must:
- List existing API keys (name, scope, created at, last used).
- Show an empty state when no keys exist.
- Allow creating a new key with name + scope (read/write/admin).
- Show the raw token once (prefixed `cwk_`), then never again.
- Allow revoking keys (removes from `api_keys` table).

## AC-08: First-Run Setup Wizard

- `GET /setup` shows the setup wizard on first run (no auth, no `ALLOW_UNAUTH`).
- Wizard creates a local admin with username + password.
- After setup, redirect to `/login`.
- `setup_complete` flag stored in `kv_store`.
- `CERT_WATCH_ALLOW_UNAUTH=1` suppresses the wizard redirect.
- Auto-provisioned admin (BC-083) also sets `setup_complete`.

## AC-09: Webhook Alert Presets

- Settings → Alerts tab has a "Webhook preset" dropdown (Slack, Teams, PagerDuty, Alertmanager, Custom).
- Selecting a preset pre-fills `webhook_kind` and sets the template textarea to the target's expected JSON shape.
- No inline `onchange` handler — delegated listener (BC-075).
- Presets are stored in `alert_adapters.py` as adapter registry.

## AC-10: In-UI Password Rotation

- Logged-in local admin can change their password from Settings.
- Old password verified before allowing change.
- New password hashed with scrypt and stored in `kv_store`.
- Session version bumped to invalidate prior sessions.
