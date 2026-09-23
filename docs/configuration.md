# Configuration

cert-watch is configured with environment variables and, for many settings,
from **Settings** in the web interface. This page explains how the two
combine, then lists every setting.

## Where a setting's value comes from

For each setting, cert-watch takes the first of these that exists:

1. **The environment variable**, if it is set. For settings that can also be
   saved in Settings, a blank value counts as unset, so a placeholder such as
   `SMTP_PASSWORD: ""` in a Compose file doesn't hide what you saved there.
2. **The `_FILE` variant.** Every secret can instead be read from a file named
   by `<VARIABLE>_FILE`, e.g. `SMTP_PASSWORD_FILE=/run/secrets/smtp`. Use this
   with Docker, Kubernetes or systemd secrets. If a `_FILE` variable is set but
   the file is missing, unreadable or empty, cert-watch refuses to start and
   names the variable. It never runs with a silently empty secret. If both the
   variable and its `_FILE` form are set, the variable wins.
3. **The value saved in Settings**, for settings marked *In Settings* below.
   Saved secrets are encrypted with the auth secret.
4. **The default.**

So environment variables always win, which makes them the right place for
configuration you manage as code. The Settings page shows a setting as locked
when an environment variable is supplying it. Saving a setting in the
interface applies it immediately, with no restart.

Numeric settings have ranges. An out-of-range environment value stops
cert-watch at startup with a message naming the variable. An out-of-range
saved value falls back to the default and is logged. Boolean variables are `1`
for on; anything else is off.

## Process controls

These aren't settings in the table below because they control the process
rather than the application:

| Variable | Default | Description |
|---|---|---|
| `CERT_WATCH_PORT` | `8000` | Port to listen on. Also settable with `--port`. |
| `CERT_WATCH_RELOAD` | `0` | `1` reloads on code changes. Development only. |

## Reference

This section is generated from the code by `scripts/gen_config_reference.py`,
so it lists exactly what the running version reads. *In Settings* marks
settings that can also be saved from the web interface.

<!-- BEGIN GENERATED REFERENCE: scripts/gen_config_reference.py -->

### Server

| Variable | Default | In Settings | Description |
|---|---|:---:|---|
| `CERT_WATCH_DATA_DIR` | `/var/lib/cert-watch`; `%PROGRAMDATA%\cert-watch` on Windows |  | Directory holding the database, generated secrets and pre-upgrade backups. |
| `CERT_WATCH_HOST` | `0.0.0.0` |  | Address to listen on. Also settable with `--host`. Whether this address is routable decides the [first-start behaviour](install.md#first-start). |
| `CERT_WATCH_LOG_FORMAT` | `text` |  | `text`, or `json` for structured logs. |
| `CERT_WATCH_INSTANCE_ID` | host name |  | Identifier stamped on exported audit events. Defaults to the host name. |
| `CERT_WATCH_ALLOW_UNAUTH` | `0` |  | `1` runs with no sign-in at all, even on a routable address. For development and isolated test systems only. |

### Scanning

| Variable | Default | In Settings | Description |
|---|---|:---:|---|
| `CERT_WATCH_TLS_VERIFY` | `0` |  | `1` makes scans fail on certificates that don't validate. The default is to scan anyway and report validation separately, which is what you want for monitoring. |
| `CERT_WATCH_ALLOW_PRIVATE_IPS` | `1` |  | `1` allows scanning private (RFC 1918 / ULA) addresses. `0` refuses all of them. |
| `CERT_WATCH_ALLOWED_SUBNETS` | — | yes | Comma-separated CIDR ranges. When set, a private address is scannable only inside one of them. Public addresses stay scannable; loopback, link-local and cloud metadata addresses are always refused. Recommended for production. |
| `CERT_WATCH_DNS_SERVERS` | — |  | Comma-separated resolver addresses used for scan targets, for example internal domain controllers. Defaults to the system resolver. |
| `CERT_WATCH_SCAN_TIMEOUT` | `10.0` |  | Seconds to wait for a TLS connection. |
| `CERT_WATCH_SCAN_RETRIES` | `2` |  | Retries for a scan that fails to connect. Range 0–10. |
| `CERT_WATCH_SCAN_RETRY_BACKOFF` | `1.0` |  | Base delay in seconds between scan retries. |
| `CERT_WATCH_SCAN_MAX_OUTPUT_BYTES` | `1048576` |  | Maximum bytes read from `openssl s_client` when it is used for chain extraction or STARTTLS. Minimum 1024. |
| `CERT_WATCH_HSTS_TIMEOUT` | `5.0` |  | Seconds to wait for the HSTS header probe on port 443. |
| `CERT_WATCH_CHECK_REVOCATION` | `0` | yes | `1` checks that OCSP and CRL endpoints are reachable during posture grading. Findings are warnings, not grade penalties. |
| `CERT_WATCH_DRIFT_ALERTS` | `1` | yes | `0` disables drift alerts: issuer change, key-size drop, SHA-1 downgrade, TLS or posture downgrade. |

### Scheduling and retention

| Variable | Default | In Settings | Description |
|---|---|:---:|---|
| `CERT_WATCH_SCHED_HOUR` | `6` | yes | Hour (UTC) of the daily scan. Range 0–23. |
| `CERT_WATCH_SCHED_MIN` | `0` | yes | Minute of the daily scan. Range 0–59. |
| `CERT_WATCH_RENEWAL_WINDOW_DAYS` | `30` | yes | A certificate this close to expiry with no successor raises a *renewal stalled* alert. `0` disables it. Range 0–365. |
| `CERT_WATCH_HISTORY_RETENTION_DAYS` | `365` |  | Days of per-scan certificate history to keep. `0` keeps it forever. Range 0–3650. |
| `CERT_WATCH_ALERT_RETENTION_DAYS` | `90` | yes | Days of delivered alerts to keep; undelivered ones are kept four times as long. `0` keeps them forever. Range 0–3650. |
| `CERT_WATCH_AUDIT_RETENTION_DAYS` | `90` |  | Days of audit log to keep. `0` keeps it forever. Range 0–3650. |
| `CERT_WATCH_EVENT_RETENTION_DAYS` | `30` |  | Days of lifecycle events to keep. `0` keeps them forever. Range 0–3650. |

### Alert email

| Variable | Default | In Settings | Description |
|---|---|:---:|---|
| `SMTP_HOST` | — | yes | SMTP relay host. Email alerts are off until this is set. |
| `SMTP_PORT` | `587` | yes | SMTP relay port. Port 465 uses implicit TLS; other ports use STARTTLS when the relay offers it, and credentials are never sent without TLS. Range 1–65535. |
| `SMTP_USER` | — | yes | SMTP user name, if the relay needs authentication. |
| `SMTP_PASSWORD` (also `_FILE`) | — | yes | SMTP password. |
| `ALERT_FROM` | — | yes | Sender address for alert email. |
| `ALERT_RECIPIENTS` | — | yes | Comma-separated addresses that receive every alert, in addition to [routed recipients](alerting.md#who-gets-an-alert). |
| `ALERT_DIGEST_ONLY` | `0` | yes | `1` sends a daily digest instead of one email per threshold crossing. Final-countdown alerts still go out individually. |

### Alert webhook

| Variable | Default | In Settings | Description |
|---|---|:---:|---|
| `ALERT_WEBHOOK_URL` | — | yes | Destination for alert webhooks. For Teams and Discord, the incoming-webhook URL. Treat it as a secret: most such URLs are credentials. |
| `ALERT_WEBHOOK_KIND` | `generic` | yes | Payload format: `generic`, `slack`, `teams`, `discord`, `pagerduty` or `alertmanager`. |
| `ALERT_WEBHOOK_HEADERS` (also `_FILE`) | — | yes | JSON object of extra HTTP headers, for example an authorization header. |
| `ALERT_WEBHOOK_TEMPLATE` | — | yes | Payload template for the `generic` kind. Unset sends the default JSON body. |
| `ALERT_PAGERDUTY_ROUTING_KEY` (also `_FILE`) | — | yes | PagerDuty Events API v2 routing key, for the `pagerduty` kind. |

### Renewal webhook

| Variable | Default | In Settings | Description |
|---|---|:---:|---|
| `CERT_WATCH_RENEWAL_WEBHOOK_URL` | — |  | Destination for machine-readable *renewal needed* events, for your renewal automation to act on. Setting it enables the webhook. See [alerting.md](alerting.md#the-renewal-webhook). |
| `CERT_WATCH_RENEWAL_WEBHOOK_HEADERS` (also `_FILE`) | — |  | JSON object of extra HTTP headers for the renewal webhook. |

### Sign-in: LDAP / Active Directory

| Variable | Default | In Settings | Description |
|---|---|:---:|---|
| `AUTH_PROVIDER` | — | yes | `ldap` for LDAP / Active Directory; `oauth`, `oidc`, `entra` or `azure` for OAuth / OIDC. Unset means local accounts only. |
| `LDAP_SERVER` | — | yes | Comma-separated LDAP URLs, tried in order, e.g. `ldaps://dc1.example.com,ldaps://dc2.example.com`. |
| `LDAP_BASE_DN` | — | yes | Base DN for the user search. |
| `LDAP_BIND_DN` | — | yes | DN of the service account used for the search. |
| `LDAP_BIND_PASSWORD` (also `_FILE`) | — | yes | Password of the search service account. |
| `LDAP_USER_FILTER` | `(sAMAccountName={username})` | yes | Search filter; `{username}` is replaced with the escaped user name. |
| `LDAP_START_TLS` | `0` | yes | `1` upgrades `ldap://` connections with StartTLS. |
| `LDAP_CA_CERT` (also `_FILE`) | — | yes | CA certificate (PEM, or a path to one) for verifying the directory's TLS certificate. |
| `LDAP_REQUIRED_GROUPS` | — | yes | Comma-separated group DNs; users outside all of them can't sign in. Nested membership counts. |
| `LDAP_CONNECT_TIMEOUT` | `5` | yes | Seconds to wait for each directory server. Range 1–300. |
| `CERT_WATCH_LDAP_ALLOW_INSECURE` | `0` |  | `1` permits a simple bind over plain `ldap://` without StartTLS, sending directory passwords in cleartext. Off by default; a migration escape hatch only. |
| `LDAP_GROUP_FILTER` | — | yes | Filter for the group membership check, with `{group}` as the group DN. The default uses Active Directory's nested-membership rule; use `member={group}` for other directories. |

### Sign-in: OAuth / OIDC

| Variable | Default | In Settings | Description |
|---|---|:---:|---|
| `OAUTH_CLIENT_ID` | — | yes | Client ID of the application registered with your identity provider. |
| `OAUTH_CLIENT_SECRET` (also `_FILE`) | — | yes | Client secret for that application. |
| `OAUTH_ISSUER_URL` | — | yes | OIDC issuer URL, e.g. `https://login.microsoftonline.com/<tenant>/v2.0`. Endpoints are discovered from it. |
| `OAUTH_SCOPE` | `openid profile email` | yes | Scopes requested at sign-in. |
| `OAUTH_AUTHORIZATION_ENDPOINT` | — | yes | Overrides the discovered authorization endpoint. |
| `OAUTH_TOKEN_ENDPOINT` | — | yes | Overrides the discovered token endpoint. |
| `OAUTH_USERINFO_ENDPOINT` | — | yes | Overrides the discovered userinfo endpoint. |
| `CERT_WATCH_JWKS_CACHE_TTL` | `86400` |  | Seconds to cache the provider's signing keys. Range 60–604800. |

### Access control

| Variable | Default | In Settings | Description |
|---|---|:---:|---|
| `CERT_WATCH_ROLE_MAP` | — |  | JSON mapping of cert-watch roles to directory groups, IdP roles or user names. Merged with the mapping in Settings → Roles; this wins per role. See [access-control.md](access-control.md#1-role-mapping-recommended). |
| `CERT_WATCH_ADMINS` | — |  | Without a role mapping: the only directory users who are administrators. |
| `CERT_WATCH_WRITE_USERS` | — |  | Without a role mapping: the only directory users (with the administrators) who may change data. |
| `CERT_WATCH_ALLOWED_GROUPS` | — |  | Directory groups whose members may sign in; everyone else is refused. |
| `CERT_WATCH_ALLOWED_ROLES` | — |  | OIDC roles whose holders may sign in; everyone else is refused. |
| `CERT_WATCH_LOCAL_ADMIN_USER` | — | yes | User name of the break-glass administrator. |
| `CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH` (also `_FILE`) | — | yes | Password hash for the break-glass administrator, from `cert-watch hash-password`. |

### Sessions and secrets

| Variable | Default | In Settings | Description |
|---|---|:---:|---|
| `CERT_WATCH_AUTH_SECRET` (also `_FILE`) | — |  | Key that signs sessions and encrypts credentials saved in Settings. Generated and stored in the data directory as `.auth_secret` if unset. Rotating it requires `cert-watch re-encrypt`. |
| `CERT_WATCH_CSRF_SECRET` (also `_FILE`) | — |  | Key for CSRF tokens. Derived from the auth secret if unset. |
| `CERT_WATCH_SESSION_TTL` | `28800` |  | Session lifetime in seconds. Range 60–2592000. |
| `CERT_WATCH_COOKIE_SECURE` | `1` |  | `0` drops the `Secure` flag from cookies, for plain-HTTP local development only. |
| `CERT_WATCH_CSP_REPORT_URI` | — |  | URL that receives Content-Security-Policy violation reports. |

### Behind a proxy

| Variable | Default | In Settings | Description |
|---|---|:---:|---|
| `CERT_WATCH_TRUST_PROXY` | `0` |  | `1` takes the client address from `X-Forwarded-For` / `X-Real-IP`, for rate limiting and the audit log. |
| `CERT_WATCH_TRUSTED_PROXIES` | — |  | Comma-separated proxy addresses allowed to set forwarded headers. |
| `CERT_WATCH_BASE_URL` | — |  | Public URL of this instance, e.g. `https://certs.example.com`. Required for OAuth sign-in; also adds a link to the certificate in renewal-webhook payloads. |

### SIEM export

| Variable | Default | In Settings | Description |
|---|---|:---:|---|
| `CERT_WATCH_SYSLOG_HOST` | — |  | Syslog server; setting it enables syslog export of the audit log. |
| `CERT_WATCH_SYSLOG_PORT` | `514` |  | Syslog port. |
| `CERT_WATCH_SYSLOG_PROTO` | `udp` |  | `udp` or `tcp`. |
| `CERT_WATCH_HEC_URL` | — |  | Splunk HTTP Event Collector URL; setting it (with the token) enables HEC export. |
| `CERT_WATCH_HEC_TOKEN` (also `_FILE`) | — |  | Splunk HEC token. |
| `CERT_WATCH_HEC_INDEX` | — |  | Splunk index. |
| `CERT_WATCH_HEC_SOURCETYPE` | `cert_watch` |  | Splunk sourcetype. |
| `CERT_WATCH_EVENTLOG` | `0` |  | `1` writes the audit log to the Windows Event Log (Application log). Windows only; needs the `cert-watch[windows]` extra. |
| `CERT_WATCH_EVENTLOG_SOURCE` | `cert-watch` |  | Event source name for the Windows Event Log. |

### Metrics

| Variable | Default | In Settings | Description |
|---|---|:---:|---|
| `CERT_WATCH_METRICS_TOKEN` (also `_FILE`) | — |  | When set, `/metrics` requires `Authorization: Bearer <token>`. |

<!-- END GENERATED REFERENCE -->

## Settings that live only in the interface

A few configurations are too structured for environment variables and are
managed only under **Settings**: alert groups, the posture policy (rules and
severities), event-stream forwarding, roles, local users and API keys. They're
stored in the database and included in backups.
