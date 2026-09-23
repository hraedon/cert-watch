"""Operator-facing descriptions for every setting in :data:`FIELD_SPECS`.

``docs/configuration.md`` is generated from this table and the field specs by
``scripts/gen_config_reference.py``. ``tests/test_config_reference.py`` fails
when a setting has no entry here or when the published reference is stale, so
adding a setting means describing it.
"""

from __future__ import annotations

# Order of sections in the generated reference.
GROUPS: tuple[str, ...] = (
    "Server",
    "Scanning",
    "Scheduling and retention",
    "Alert email",
    "Alert webhook",
    "Renewal webhook",
    "Sign-in: LDAP / Active Directory",
    "Sign-in: OAuth / OIDC",
    "Access control",
    "Sessions and secrets",
    "Behind a proxy",
    "SIEM export",
    "Metrics",
)

# field name -> (group, description). Fields that are purely internal (derived
# or never operator-set) are listed in INTERNAL instead.
FIELD_DOCS: dict[str, tuple[str, str]] = {
    "data_dir": ("Server", "Directory holding the database, generated secrets and pre-upgrade backups."),
    "bind_host": ("Server", "Address to listen on. Also settable with `--host`. Whether this address is routable decides the [first-start behaviour](install.md#first-start)."),
    "log_format": ("Server", "`text`, or `json` for structured logs."),
    "instance_id": ("Server", "Identifier stamped on exported audit events. Defaults to the host name."),
    "allow_unauth": ("Server", "`1` runs with no sign-in at all, even on a routable address. For development and isolated test systems only."),

    "tls_verify": ("Scanning", "`1` makes scans fail on certificates that don't validate. The default is to scan anyway and report validation separately, which is what you want for monitoring."),
    "allow_private": ("Scanning", "`1` allows scanning private (RFC 1918 / ULA) addresses. `0` refuses all of them."),
    "allowed_subnets": ("Scanning", "Comma-separated CIDR ranges. When set, a private address is scannable only inside one of them. Public addresses stay scannable; loopback, link-local and cloud metadata addresses are always refused. Recommended for production."),
    "dns_servers": ("Scanning", "Comma-separated resolver addresses used for scan targets, for example internal domain controllers. Defaults to the system resolver."),
    "scan_timeout": ("Scanning", "Seconds to wait for a TLS connection."),
    "scan_retries": ("Scanning", "Retries for a scan that fails to connect."),
    "scan_retry_backoff": ("Scanning", "Base delay in seconds between scan retries."),
    "scan_max_output_bytes": ("Scanning", "Maximum bytes read from `openssl s_client` when it is used for chain extraction or STARTTLS."),
    "hsts_timeout": ("Scanning", "Seconds to wait for the HSTS header probe on port 443."),
    "check_revocation": ("Scanning", "`1` checks that OCSP and CRL endpoints are reachable during posture grading. Findings are warnings, not grade penalties."),
    "drift_alerts": ("Scanning", "`0` disables drift alerts: issuer change, key-size drop, SHA-1 downgrade, TLS or posture downgrade."),

    "sched_hour": ("Scheduling and retention", "Hour (UTC) of the daily scan."),
    "sched_min": ("Scheduling and retention", "Minute of the daily scan."),
    "renewal_window_days": ("Scheduling and retention", "A certificate this close to expiry with no successor raises a *renewal stalled* alert. `0` disables it."),
    "history_retention_days": ("Scheduling and retention", "Days of per-scan certificate history to keep. `0` keeps it forever."),
    "alert_retention_days": ("Scheduling and retention", "Days of delivered alerts to keep; undelivered ones are kept four times as long. `0` keeps them forever."),
    "audit_retention_days": ("Scheduling and retention", "Days of audit log to keep. `0` keeps it forever."),
    "event_retention_days": ("Scheduling and retention", "Days of lifecycle events to keep. `0` keeps them forever."),

    "smtp_host": ("Alert email", "SMTP relay host. Email alerts are off until this is set."),
    "smtp_port": ("Alert email", "SMTP relay port. Port 465 uses implicit TLS; other ports use STARTTLS when the relay offers it, and credentials are never sent without TLS."),
    "smtp_user": ("Alert email", "SMTP user name, if the relay needs authentication."),
    "smtp_password": ("Alert email", "SMTP password."),
    "alert_from": ("Alert email", "Sender address for alert email."),
    "alert_recipients": ("Alert email", "Comma-separated addresses that receive every alert, in addition to [routed recipients](alerting.md#who-gets-an-alert)."),
    "alert_digest_only": ("Alert email", "`1` sends a daily digest instead of one email per threshold crossing. Final-countdown alerts still go out individually."),

    "webhook_url": ("Alert webhook", "Destination for alert webhooks. For Teams and Discord, the incoming-webhook URL. Treat it as a secret: most such URLs are credentials."),
    "webhook_kind": ("Alert webhook", "Payload format: `generic`, `slack`, `teams`, `discord`, `pagerduty` or `alertmanager`."),
    "webhook_headers": ("Alert webhook", "JSON object of extra HTTP headers, for example an authorization header."),
    "webhook_template": ("Alert webhook", "Payload template for the `generic` kind. Unset sends the default JSON body."),
    "pagerduty_routing_key": ("Alert webhook", "PagerDuty Events API v2 routing key, for the `pagerduty` kind."),

    "renewal_webhook_url": ("Renewal webhook", "Destination for machine-readable *renewal needed* events, for your renewal automation to act on. Setting it enables the webhook. See [alerting.md](alerting.md#the-renewal-webhook)."),
    "renewal_webhook_headers": ("Renewal webhook", "JSON object of extra HTTP headers for the renewal webhook."),

    "auth_provider": ("Sign-in: LDAP / Active Directory", "`ldap` for LDAP / Active Directory; `oauth`, `oidc`, `entra` or `azure` for OAuth / OIDC. Unset means local accounts only."),
    "ldap_server": ("Sign-in: LDAP / Active Directory", "Comma-separated LDAP URLs, tried in order, e.g. `ldaps://dc1.example.com,ldaps://dc2.example.com`."),
    "ldap_base_dn": ("Sign-in: LDAP / Active Directory", "Base DN for the user search."),
    "ldap_bind_dn": ("Sign-in: LDAP / Active Directory", "DN of the service account used for the search."),
    "ldap_bind_password": ("Sign-in: LDAP / Active Directory", "Password of the search service account."),
    "ldap_user_filter": ("Sign-in: LDAP / Active Directory", "Search filter; `{username}` is replaced with the escaped user name."),
    "ldap_start_tls": ("Sign-in: LDAP / Active Directory", "`1` upgrades `ldap://` connections with StartTLS."),
    "ldap_ca_cert": ("Sign-in: LDAP / Active Directory", "CA certificate (PEM, or a path to one) for verifying the directory's TLS certificate."),
    "ldap_required_groups": ("Sign-in: LDAP / Active Directory", "Comma-separated group DNs; users outside all of them can't sign in. Nested membership counts."),
    "ldap_connect_timeout": ("Sign-in: LDAP / Active Directory", "Seconds to wait for each directory server."),
    "ldap_group_filter": ("Sign-in: LDAP / Active Directory", "Filter for the group membership check, with `{group}` as the group DN. The default uses Active Directory's nested-membership rule; use `member={group}` for other directories."),

    "oauth_client_id": ("Sign-in: OAuth / OIDC", "Client ID of the application registered with your identity provider."),
    "oauth_client_secret": ("Sign-in: OAuth / OIDC", "Client secret for that application."),
    "oauth_issuer_url": ("Sign-in: OAuth / OIDC", "OIDC issuer URL, e.g. `https://login.microsoftonline.com/<tenant>/v2.0`. Endpoints are discovered from it."),
    "oauth_scope": ("Sign-in: OAuth / OIDC", "Scopes requested at sign-in."),
    "oauth_authorization_endpoint": ("Sign-in: OAuth / OIDC", "Overrides the discovered authorization endpoint."),
    "oauth_token_endpoint": ("Sign-in: OAuth / OIDC", "Overrides the discovered token endpoint."),
    "oauth_userinfo_endpoint": ("Sign-in: OAuth / OIDC", "Overrides the discovered userinfo endpoint."),
    "jwks_cache_ttl": ("Sign-in: OAuth / OIDC", "Seconds to cache the provider's signing keys."),

    "role_map": ("Access control", "JSON mapping of cert-watch roles to directory groups, IdP roles or user names. Merged with the mapping in Settings → Roles; this wins per role. See [access-control.md](access-control.md#1-role-mapping-recommended)."),
    "admin_users": ("Access control", "Without a role mapping: the only directory users who are administrators."),
    "write_users": ("Access control", "Without a role mapping: the only directory users (with the administrators) who may change data."),
    "allowed_groups": ("Access control", "Directory groups whose members may sign in; everyone else is refused."),
    "allowed_roles": ("Access control", "OIDC roles whose holders may sign in; everyone else is refused."),
    "local_admin_user": ("Access control", "User name of the break-glass administrator."),
    "local_admin_password_hash": ("Access control", "Password hash for the break-glass administrator, from `cert-watch hash-password`."),

    "auth_secret": ("Sessions and secrets", "Key that signs sessions and encrypts credentials saved in Settings. Generated and stored in the data directory as `.auth_secret` if unset. Rotating it requires `cert-watch re-encrypt`."),
    "csrf_secret": ("Sessions and secrets", "Key for CSRF tokens. Derived from the auth secret if unset."),
    "session_ttl": ("Sessions and secrets", "Session lifetime in seconds."),
    "cookie_secure": ("Sessions and secrets", "`0` drops the `Secure` flag from cookies, for plain-HTTP local development only."),
    "csp_report_uri": ("Sessions and secrets", "URL that receives Content-Security-Policy violation reports."),

    "trust_proxy": ("Behind a proxy", "`1` takes the client address from `X-Forwarded-For` / `X-Real-IP`, for rate limiting and the audit log."),
    "trusted_proxies": ("Behind a proxy", "Comma-separated proxy addresses allowed to set forwarded headers."),
    "base_url": ("Behind a proxy", "Public URL of this instance, e.g. `https://certs.example.com`. Required for OAuth sign-in; also adds a link to the certificate in renewal-webhook payloads."),

    "syslog_host": ("SIEM export", "Syslog server; setting it enables syslog export of the audit log."),
    "syslog_port": ("SIEM export", "Syslog port."),
    "syslog_proto": ("SIEM export", "`udp` or `tcp`."),
    "hec_url": ("SIEM export", "Splunk HTTP Event Collector URL; setting it (with the token) enables HEC export."),
    "hec_token": ("SIEM export", "Splunk HEC token."),
    "hec_index": ("SIEM export", "Splunk index."),
    "hec_sourcetype": ("SIEM export", "Splunk sourcetype."),
    "eventlog_requested": ("SIEM export", "`1` writes the audit log to the Windows Event Log (Application log). Windows only; needs the `cert-watch[windows]` extra."),
    "eventlog_source": ("SIEM export", "Event source name for the Windows Event Log."),

    "metrics_token": ("Metrics", "When set, `/metrics` requires `Authorization: Bearer <token>`."),
}

# Settings that exist on the Settings object but are not operator inputs.
INTERNAL: dict[str, str] = {
    "db_path": "Derived from the data directory.",
    "event_stream_config": "Set under Settings → Events.",
    "event_stream_pagerduty_routing_key": "Set under Settings → Events.",
    "policy_config": "Set under Settings → Policy.",
}
