"""The Settings dataclass and its builder methods.

Decomposed from the monolithic config.py (BC-144a / config decomposition).
"""

from __future__ import annotations

import logging
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from cert_watch.alerts import AlertConfig, WebhookConfig
    from cert_watch.auth import AuthProvider
    from cert_watch.renewal_webhook import RenewalWebhookConfig
    from cert_watch.security import SecurityContext

logger = logging.getLogger("cert_watch.config")


@dataclass(frozen=True)
class Settings:
    db_path: Path
    data_dir: Path
    sched_hour: int = 6
    sched_min: int = 0
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: str | None = None
    alert_from: str | None = None
    alert_recipients: tuple[str, ...] = ()
    webhook_url: str | None = None
    webhook_headers: dict[str, str] | None = None
    webhook_template: str = ""
    webhook_kind: str = "generic"
    pagerduty_routing_key: str = ""
    alert_digest_only: bool = False
    tls_verify: bool = False
    allow_private: bool = True
    allowed_subnets: tuple[str, ...] = ()
    dns_servers: tuple[str, ...] = ()
    log_format: str = "text"
    audit_retention_days: int = 90
    history_retention_days: int = 365
    alert_retention_days: int = 90
    drift_alerts: bool = True
    event_retention_days: int = 30
    renewal_window_days: int = 30
    check_revocation: bool = False
    scan_timeout: float = 10.0
    scan_retries: int = 2
    scan_retry_backoff: float = 1.0
    scan_max_output_bytes: int = 1048576
    hsts_timeout: float = 5.0
    auth_provider: str = ""
    ldap_server: str = ""
    ldap_base_dn: str = ""
    ldap_bind_dn: str = ""
    ldap_bind_password: str = ""
    ldap_user_filter: str = "(sAMAccountName={username})"
    ldap_start_tls: bool = False
    ldap_ca_cert: str = ""
    ldap_required_groups: tuple[str, ...] = ()
    ldap_connect_timeout: int = 5
    ldap_group_filter: str = ""
    oauth_client_id: str = ""
    oauth_client_secret: str = ""
    oauth_issuer_url: str = ""
    oauth_scope: str = "openid profile email"
    oauth_authorization_endpoint: str = ""
    oauth_token_endpoint: str = ""
    oauth_userinfo_endpoint: str = ""
    allowed_groups: tuple[str, ...] = ()
    allowed_roles: tuple[str, ...] = ()
    admin_users: tuple[str, ...] = ()
    session_ttl: int = 28800
    write_users: tuple[str, ...] = ()
    role_map: dict[str, dict[str, Any]] = field(default_factory=dict)
    local_admin_user: str = ""
    local_admin_password_hash: str = ""
    base_url: str = ""
    allow_unauth: bool = False
    jwks_cache_ttl: int = 86400
    renewal_webhook_url: str = ""
    renewal_webhook_headers: dict[str, str] | None = None
    event_stream_config: dict[str, Any] | None = None
    event_stream_pagerduty_routing_key: str = ""
    policy_config: dict[str, Any] | None = None
    auth_secret: str = ""
    csrf_secret: str = ""
    cookie_secure: bool = True
    bind_host: str = "0.0.0.0"
    trust_proxy: bool = False
    trusted_proxies: tuple[str, ...] = ()
    metrics_token: str = ""
    csp_report_uri: str = ""
    instance_id: str = field(default_factory=socket.gethostname)
    syslog_host: str = ""
    syslog_port: int = 514
    syslog_proto: str = "udp"
    hec_url: str = ""
    hec_token: str = ""
    hec_index: str = ""
    hec_sourcetype: str = "cert_watch"
    eventlog_requested: bool = False
    eventlog_source: str = "cert-watch"

    @classmethod
    def from_env(cls) -> Settings:
        """Build Settings from environment variables only.

        This is the base loader used by ``from_env_with_kv()``.  In production
        the lifespan should use ``from_env_with_kv()`` so GUI-configured
        auth/smtp/alert settings survive restart (BC-159).
        """
        from cert_watch.config.loader import load_env_values

        return cls(**load_env_values())

    def build_alert_config(self) -> AlertConfig | None:
        """Return an AlertConfig if SMTP envs are sufficiently populated, else None."""
        from cert_watch.alerts import AlertConfig

        if not (self.smtp_host and self.alert_from and self.alert_recipients):
            return None
        return AlertConfig(
            smtp_host=self.smtp_host,
            smtp_port=self.smtp_port,
            smtp_user=self.smtp_user or "",
            smtp_password=self.smtp_password or "",
            from_addr=self.alert_from,
            recipients=list(self.alert_recipients),
            allow_private=self.allow_private,
            allowed_subnets=self.allowed_subnets,
        )

    def build_webhook_config(self) -> WebhookConfig | None:
        """Return a WebhookConfig if webhook URL is set, else None."""
        from cert_watch.alerts import WebhookConfig
        from cert_watch.http_client import validate_webhook_url

        if not self.webhook_url:
            return None
        err = validate_webhook_url(
            self.webhook_url,
            allow_private=self.allow_private,
            allowed_subnets=self.allowed_subnets,
        )
        if err:
            import logging
            logging.getLogger("cert_watch.config").warning(
                "ALERT_WEBHOOK_URL is invalid and will be skipped: %s", err,
            )
            return None
        return WebhookConfig(
            url=self.webhook_url,
            kind=self.webhook_kind,
            routing_key=self.pagerduty_routing_key,
            headers=self.webhook_headers or {},
            template=self.webhook_template,
            allow_private=self.allow_private,
            allowed_subnets=self.allowed_subnets,
        )

    def build_renewal_webhook_config(self) -> RenewalWebhookConfig | None:
        """Return a RenewalWebhookConfig if the renewal webhook URL is set, else None."""
        if not self.renewal_webhook_url:
            return None
        from cert_watch.http_client import validate_webhook_url

        err = validate_webhook_url(
            self.renewal_webhook_url,
            allow_private=self.allow_private,
            allowed_subnets=self.allowed_subnets,
        )
        if err:
            logger.warning(
                "CERT_WATCH_RENEWAL_WEBHOOK_URL is invalid and will be skipped: %s",
                err,
            )
            return None
        return RenewalWebhookConfig(
            url=self.renewal_webhook_url,
            headers=self.renewal_webhook_headers or {},
            allow_private=self.allow_private,
            allowed_subnets=self.allowed_subnets,
        )

    def build_auth_provider(self, *, security: SecurityContext | None = None) -> AuthProvider:
        """Return an AuthProvider from this fully resolved Settings snapshot."""
        from cert_watch.auth import build_auth_provider

        return build_auth_provider(
            provider=self.auth_provider,
            ldap_server=self.ldap_server,
            ldap_base_dn=self.ldap_base_dn,
            ldap_bind_dn=self.ldap_bind_dn,
            ldap_bind_password=self.ldap_bind_password,
            ldap_user_filter=self.ldap_user_filter,
            ldap_start_tls=self.ldap_start_tls,
            ldap_ca_cert=self.ldap_ca_cert,
            ldap_required_groups=list(self.ldap_required_groups),
            ldap_connect_timeout=self.ldap_connect_timeout,
            ldap_group_filter=self.ldap_group_filter,
            oauth_client_id=self.oauth_client_id,
            oauth_client_secret=self.oauth_client_secret,
            oauth_issuer_url=self.oauth_issuer_url,
            oauth_scope=self.oauth_scope,
            oauth_authorization_endpoint=self.oauth_authorization_endpoint,
            oauth_token_endpoint=self.oauth_token_endpoint,
            oauth_userinfo_endpoint=self.oauth_userinfo_endpoint,
            allow_private=self.allow_private,
            allowed_subnets=self.allowed_subnets,
            jwks_cache_ttl=self.jwks_cache_ttl,
            allowed_groups=list(self.allowed_groups),
            allowed_roles=list(self.allowed_roles),
            local_admin_user=self.local_admin_user,
            local_admin_password_hash=self.local_admin_password_hash,
            # #59: without the DB path the provider never consults the users
            # table, so accounts created in /settings/users could never log in.
            db_path=str(self.db_path),
            security=security,
        )

    @classmethod
    def from_env_with_kv(cls, db_path: Path, encryption_key: str | None = None) -> Settings:
        """Build Settings with kv_store fallback for auth/smtp/alert fields.

        Env vars take precedence; kv_store values fill in where env is unset.
        When *encryption_key* is set, sensitive kv_store values with the
        ``enc:v1:`` prefix are transparently decrypted (BC-082).
        """
        import dataclasses

        from cert_watch.auth.rbac import (
            RBAC_ENFORCED_KEY,
            normalize_ui_role_map,
            ui_role_map_by_name,
            ui_role_map_configured,
        )
        from cert_watch.config.kv_loader import _merge_kv_settings

        merged = _merge_kv_settings(cls.from_env(), db_path, encryption_key)
        # The role mapping saved from Settings → Roles (kv ``ldap_role_map``)
        # was stored but never read, so the UI's mapping had no effect. Merge it
        # per role, with CERT_WATCH_ROLE_MAP winning for any role it names.
        # Entries for roles that no longer exist are dropped (PR #78, B1).
        # Database errors propagate: a failed rebuild keeps the previous
        # Settings rather than one with an empty (= full access) role map.
        normalize_ui_role_map(db_path)
        role_map = {**ui_role_map_by_name(db_path), **merged.role_map}
        if not role_map and ui_role_map_configured(db_path):
            # Mapping was configured and then emptied: least privilege, not
            # the never-configured "full access" default (N-1).
            role_map = {RBAC_ENFORCED_KEY: {}}
        if role_map == merged.role_map:
            return merged
        return dataclasses.replace(merged, role_map=role_map)
