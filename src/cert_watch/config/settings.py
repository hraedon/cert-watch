"""The Settings dataclass and its builder methods.

Decomposed from the monolithic config.py (BC-144a / config decomposition).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cert_watch.alerts import AlertConfig, WebhookConfig
    from cert_watch.auth import AuthProvider
    from cert_watch.security import SecurityContext

from cert_watch.config.helpers import (
    _default_data_dir,
    _parse_float,
    _parse_int,
    _parse_role_map,
    read_secret,
    split_group_dns,
)


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
    role_map: dict = field(default_factory=dict)
    local_admin_user: str = ""
    local_admin_password_hash: str = ""
    base_url: str = ""
    allow_unauth: bool = False
    jwks_cache_ttl: int = 86400

    @classmethod
    def from_env(cls) -> Settings:
        """Build Settings from environment variables only.

        This is the base loader used by ``from_env_with_kv()``.  In production
        the lifespan should use ``from_env_with_kv()`` so GUI-configured
        auth/smtp/alert settings survive restart (BC-159).
        """
        import json
        import os

        env_data_dir = os.environ.get("CERT_WATCH_DATA_DIR")
        data_dir = Path(env_data_dir) if env_data_dir else _default_data_dir()
        recipients = tuple(
            r.strip()
            for r in os.environ.get("ALERT_RECIPIENTS", "").split(",")
            if r.strip()
        )
        webhook_url = os.environ.get("ALERT_WEBHOOK_URL") or None
        webhook_headers_str = os.environ.get("ALERT_WEBHOOK_HEADERS") or ""
        webhook_headers = None
        if webhook_headers_str:
            try:
                webhook_headers = json.loads(webhook_headers_str)
            except (json.JSONDecodeError, ValueError):
                webhook_headers = None

        sched_hour = _parse_int(
            os.environ.get("CERT_WATCH_SCHED_HOUR", "6"), 6,
            "CERT_WATCH_SCHED_HOUR",
            min_value=0, max_value=23,
        )
        sched_min = _parse_int(
            os.environ.get("CERT_WATCH_SCHED_MIN", "0"), 0,
            "CERT_WATCH_SCHED_MIN",
            min_value=0, max_value=59,
        )
        smtp_port = _parse_int(
            os.environ.get("SMTP_PORT", "587"), 587,
            "SMTP_PORT",
            min_value=1, max_value=65535,
        )
        ldap_connect_timeout = _parse_int(
            os.environ.get("LDAP_CONNECT_TIMEOUT", "5"), 5,
            "LDAP_CONNECT_TIMEOUT",
            min_value=1, max_value=300,
        )
        audit_retention_days = _parse_int(
            os.environ.get("CERT_WATCH_AUDIT_RETENTION_DAYS", "90"), 90,
            "CERT_WATCH_AUDIT_RETENTION_DAYS",
            min_value=0, max_value=3650,
        )
        renewal_window_days = _parse_int(
            os.environ.get("CERT_WATCH_RENEWAL_WINDOW_DAYS", "30"), 30,
            "CERT_WATCH_RENEWAL_WINDOW_DAYS",
            min_value=1, max_value=365,
        )
        history_retention_days = _parse_int(
            os.environ.get("CERT_WATCH_HISTORY_RETENTION_DAYS", "365"), 365,
            "CERT_WATCH_HISTORY_RETENTION_DAYS",
            min_value=0, max_value=3650,
        )
        alert_retention_days = _parse_int(
            os.environ.get("CERT_WATCH_ALERT_RETENTION_DAYS", "90"), 90,
            "CERT_WATCH_ALERT_RETENTION_DAYS",
            min_value=0, max_value=3650,
        )
        event_retention_days = _parse_int(
            os.environ.get("CERT_WATCH_EVENT_RETENTION_DAYS", "30"), 30,
            "CERT_WATCH_EVENT_RETENTION_DAYS",
            min_value=0, max_value=3650,
        )

        return cls(
            db_path=data_dir / "cert-watch.sqlite3",
            data_dir=data_dir,
            sched_hour=sched_hour,
            sched_min=sched_min,
            smtp_host=os.environ.get("SMTP_HOST") or None,
            smtp_port=smtp_port,
            smtp_user=os.environ.get("SMTP_USER") or None,
            smtp_password=read_secret("SMTP_PASSWORD"),
            alert_from=os.environ.get("ALERT_FROM") or None,
            alert_recipients=recipients,
            webhook_url=webhook_url,
            webhook_headers=webhook_headers,
            webhook_template=os.environ.get("ALERT_WEBHOOK_TEMPLATE", ""),
            webhook_kind=os.environ.get("ALERT_WEBHOOK_KIND", "generic"),
            pagerduty_routing_key=read_secret("ALERT_PAGERDUTY_ROUTING_KEY") or "",
            alert_digest_only=os.environ.get("ALERT_DIGEST_ONLY", "0") == "1",
            audit_retention_days=audit_retention_days,
            history_retention_days=history_retention_days,
            alert_retention_days=alert_retention_days,
            event_retention_days=event_retention_days,
            drift_alerts=os.environ.get("CERT_WATCH_DRIFT_ALERTS", "1") == "1",
            renewal_window_days=renewal_window_days,
            check_revocation=os.environ.get("CERT_WATCH_CHECK_REVOCATION", "0") == "1",
            tls_verify=os.environ.get("CERT_WATCH_TLS_VERIFY", "0") == "1",
            allow_private=os.environ.get("CERT_WATCH_ALLOW_PRIVATE_IPS", "1") == "1",
            allowed_subnets=tuple(
                s.strip()
                for s in os.environ.get("CERT_WATCH_ALLOWED_SUBNETS", "").split(",")
                if s.strip()
            ),
            log_format=os.environ.get("CERT_WATCH_LOG_FORMAT", "text"),
            dns_servers=tuple(
                s.strip()
                for s in os.environ.get("CERT_WATCH_DNS_SERVERS", "").split(",")
                if s.strip()
            ),
            auth_provider=os.environ.get("AUTH_PROVIDER", ""),
            ldap_server=os.environ.get("LDAP_SERVER", ""),
            ldap_base_dn=os.environ.get("LDAP_BASE_DN", ""),
            ldap_bind_dn=os.environ.get("LDAP_BIND_DN", ""),
            ldap_bind_password=read_secret("LDAP_BIND_PASSWORD") or "",
            ldap_user_filter=os.environ.get(
                "LDAP_USER_FILTER", "(sAMAccountName={username})"
            ),
            ldap_start_tls=os.environ.get("LDAP_START_TLS", "0") == "1",
            ldap_ca_cert=read_secret("LDAP_CA_CERT") or "",
            ldap_required_groups=split_group_dns(
                os.environ.get("LDAP_REQUIRED_GROUPS", "")
            ),
            ldap_connect_timeout=ldap_connect_timeout,
            ldap_group_filter=os.environ.get("LDAP_GROUP_FILTER", ""),
            oauth_client_id=os.environ.get("OAUTH_CLIENT_ID", ""),
            oauth_client_secret=read_secret("OAUTH_CLIENT_SECRET") or "",
            oauth_issuer_url=os.environ.get("OAUTH_ISSUER_URL", ""),
            oauth_scope=os.environ.get("OAUTH_SCOPE", "openid profile email"),
            oauth_authorization_endpoint=os.environ.get(
                "OAUTH_AUTHORIZATION_ENDPOINT", ""
            ),
            oauth_token_endpoint=os.environ.get("OAUTH_TOKEN_ENDPOINT", ""),
            oauth_userinfo_endpoint=os.environ.get("OAUTH_USERINFO_ENDPOINT", ""),
            allowed_groups=tuple(
                g.strip()
                for g in os.environ.get("CERT_WATCH_ALLOWED_GROUPS", "").split(",")
                if g.strip()
            ),
            allowed_roles=tuple(
                r.strip()
                for r in os.environ.get("CERT_WATCH_ALLOWED_ROLES", "").split(",")
                if r.strip()
            ),
            admin_users=tuple(
                u.strip()
                for u in os.environ.get("CERT_WATCH_ADMINS", "").split(",")
                if u.strip()
            ),
            scan_timeout=_parse_float(
                os.environ.get("CERT_WATCH_SCAN_TIMEOUT", "10.0"), 10.0,
                "CERT_WATCH_SCAN_TIMEOUT",
            ),
            scan_retries=_parse_int(
                os.environ.get("CERT_WATCH_SCAN_RETRIES", "2"), 2,
                "CERT_WATCH_SCAN_RETRIES",
                min_value=0, max_value=10,
            ),
            scan_retry_backoff=_parse_float(
                os.environ.get("CERT_WATCH_SCAN_RETRY_BACKOFF", "1.0"), 1.0,
                "CERT_WATCH_SCAN_RETRY_BACKOFF",
            ),
            scan_max_output_bytes=_parse_int(
                os.environ.get("CERT_WATCH_SCAN_MAX_OUTPUT_BYTES", "1048576"), 1048576,
                "CERT_WATCH_SCAN_MAX_OUTPUT_BYTES",
                min_value=1024,
            ),
            hsts_timeout=_parse_float(
                os.environ.get("CERT_WATCH_HSTS_TIMEOUT", "5.0"), 5.0,
                "CERT_WATCH_HSTS_TIMEOUT",
            ),
            session_ttl=_parse_int(
                os.environ.get("CERT_WATCH_SESSION_TTL", "28800"), 28800,
                "CERT_WATCH_SESSION_TTL",
                min_value=60, max_value=2592000,
            ),
            write_users=tuple(
                u.strip()
                for u in os.environ.get("CERT_WATCH_WRITE_USERS", "").split(",")
                if u.strip()
            ),
            role_map=_parse_role_map(
                os.environ.get("CERT_WATCH_ROLE_MAP", "")
            ),
            local_admin_user=os.environ.get("CERT_WATCH_LOCAL_ADMIN_USER", ""),
            local_admin_password_hash=read_secret(
                "CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH"
            ) or "",
            base_url=os.environ.get("CERT_WATCH_BASE_URL", "").rstrip("/"),
            allow_unauth=os.environ.get("CERT_WATCH_ALLOW_UNAUTH", "0") == "1",
            jwks_cache_ttl=_parse_int(
                os.environ.get("CERT_WATCH_JWKS_CACHE_TTL", "86400"), 86400,
                "CERT_WATCH_JWKS_CACHE_TTL",
                min_value=60, max_value=604800,
            ),
        )

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

    def build_auth_provider(self, *, security: SecurityContext | None = None) -> AuthProvider:
        """Return an AuthProvider based on auth config.

        Falls back to kv_store for local_admin_user/local_admin_password_hash when
        env vars are unset (Plan 014 Slice 2).
        """
        from cert_watch.auth import build_auth_provider
        from cert_watch.config.kv_loader import (
            LOCAL_ADMIN_PASSWORD_HASH,
            LOCAL_ADMIN_USER,
        )
        from cert_watch.database import kv_get

        local_admin_user = self.local_admin_user
        local_admin_password_hash = self.local_admin_password_hash
        if not local_admin_user:
            local_admin_user = kv_get(self.db_path, LOCAL_ADMIN_USER) or ""
        if not local_admin_password_hash:
            local_admin_password_hash = kv_get(
                self.db_path, LOCAL_ADMIN_PASSWORD_HASH
            ) or ""

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
            local_admin_user=local_admin_user,
            local_admin_password_hash=local_admin_password_hash,
            security=security,
        )

    @classmethod
    def from_env_with_kv(cls, db_path: Path, encryption_key: str | None = None) -> Settings:
        """Build Settings with kv_store fallback for auth/smtp/alert fields.

        Env vars take precedence; kv_store values fill in where env is unset.
        When *encryption_key* is set, sensitive kv_store values with the
        ``enc:v1:`` prefix are transparently decrypted (BC-082).
        """
        from cert_watch.config.kv_loader import _merge_kv_settings
        return _merge_kv_settings(cls.from_env(), db_path, encryption_key)
