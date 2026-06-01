import json
import logging
import os
import secrets
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

logger = logging.getLogger("cert_watch.config")


def resolve_or_persist_secret(env_name: str, data_dir: Path, filename: str) -> str:
    """Return env/_FILE secret if set (treating empty/whitespace as unset);
    else read data_dir/filename; else generate 32-byte hex, persist 0600, return it.

    This ensures signing keys survive restarts even when the operator hasn't
    set an explicit env var. The persisted file is the fallback for local dev
    and bare-metal installs without Docker secrets.
    """
    value = read_secret(env_name)
    if value and value.strip():
        return value
    secret_file = data_dir / filename
    try:
        if secret_file.exists():
            persisted = secret_file.read_text().strip()
            if persisted:
                logger.warning(
                    "Using persisted %s from %s (no %s env var set; "
                    "consider setting %s in production for explicit control)",
                    filename, secret_file, env_name, env_name,
                )
                return persisted
    except OSError:
        logger.debug("could not read %s, will regenerate", secret_file)
    generated = secrets.token_hex(32)
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        secret_file.write_text(generated + "\n")
        secret_file.chmod(0o600)
        logger.info("generated and persisted %s to %s", filename, secret_file)
    except OSError:
        logger.warning(
            "could not persist %s to %s; using ephemeral key (sessions will not survive restart)",
            filename, secret_file,
        )
    return generated


def read_secret(name: str) -> str | None:
    """Return the value of env var $name, or the file contents of $name_FILE.

    The ``_FILE`` convention is standard in Docker/Kubernetes secret mounts:
    the operator sets e.g. ``LDAP_BIND_PASSWORD_FILE=/run/secrets/ldap_pw``
    instead of putting the secret value directly in the environment.

    Returns ``None`` when neither is set.  When the ``_FILE`` variant is used,
    the file contents are stripped of trailing whitespace/newlines.
    """
    value = os.environ.get(name)
    if value is not None:
        return value
    file_path = os.environ.get(f"{name}_FILE")
    if file_path:
        try:
            return Path(file_path).read_text().strip()
        except OSError:
            logger.warning("read_secret: %s_FILE=%s could not be read", name, file_path)
            return None
    return None


def _default_data_dir_str(os_name: str, programdata: str | None) -> str:
    """Compute the default data-dir path string for *os_name*.

    Split out from :func:`_default_data_dir` so the platform branch is testable
    on any host (building a concrete ``WindowsPath`` is impossible on POSIX, so
    we join with ``PureWindowsPath`` and return a plain string).
    """
    if os_name == "nt":
        base = programdata or r"C:\ProgramData"
        return str(PureWindowsPath(base, "cert-watch"))
    return "/var/lib/cert-watch"


def _default_data_dir() -> Path:
    """Platform-appropriate default data directory.

    Always overridable via ``CERT_WATCH_DATA_DIR``. On Windows there is no
    ``/var`` hierarchy, so default to ``%PROGRAMDATA%\\cert-watch`` (normally
    ``C:\\ProgramData\\cert-watch``); on POSIX keep ``/var/lib/cert-watch``.
    """
    return Path(_default_data_dir_str(os.name, os.environ.get("PROGRAMDATA")))


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
    alert_digest_only: bool = False
    tls_verify: bool = False
    allow_private: bool = True
    dns_servers: tuple[str, ...] = ()
    log_format: str = "text"
    audit_retention_days: int = 90
    history_retention_days: int = 365
    drift_alerts: bool = True
    # Auth
    auth_provider: str = ""  # "", "none", "ldap", "oauth", "entra"
    ldap_server: str = ""
    ldap_base_dn: str = ""
    ldap_bind_dn: str = ""
    ldap_bind_password: str = ""
    ldap_user_filter: str = "(sAMAccountName={username})"
    ldap_start_tls: bool = False
    ldap_ca_cert: str = ""
    ldap_required_groups: tuple[str, ...] = ()
    ldap_connect_timeout: int = 5
    oauth_client_id: str = ""
    oauth_client_secret: str = ""
    oauth_issuer_url: str = ""
    oauth_scope: str = "openid profile email"
    oauth_authorization_endpoint: str = ""
    oauth_token_endpoint: str = ""
    oauth_userinfo_endpoint: str = ""
    # Authorization
    allowed_groups: tuple[str, ...] = ()
    allowed_roles: tuple[str, ...] = ()
    # Local break-glass admin
    local_admin_user: str = ""
    local_admin_password_hash: str = ""
    # Security
    base_url: str = ""  # Override for OAuth redirect URI detection
    allow_unauth: bool = False  # Suppress unauthenticated warning (CERT_WATCH_ALLOW_UNAUTH=1)

    @classmethod
    def from_env(cls) -> "Settings":
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
        sched_hour_str = os.environ.get("CERT_WATCH_SCHED_HOUR", "6")
        sched_min_str = os.environ.get("CERT_WATCH_SCHED_MIN", "0")
        smtp_port_str = os.environ.get("SMTP_PORT", "587")
        ldap_connect_timeout_str = os.environ.get("LDAP_CONNECT_TIMEOUT", "5")
        try:
            sched_hour = int(sched_hour_str)
        except ValueError:
            logger.warning("Invalid CERT_WATCH_SCHED_HOUR=%r, using default 6", sched_hour_str)
            sched_hour = 6
        try:
            sched_min = int(sched_min_str)
        except ValueError:
            logger.warning("Invalid CERT_WATCH_SCHED_MIN=%r, using default 0", sched_min_str)
            sched_min = 0
        try:
            smtp_port = int(smtp_port_str)
        except ValueError:
            logger.warning("Invalid SMTP_PORT=%r, using default 587", smtp_port_str)
            smtp_port = 587
        try:
            ldap_connect_timeout = int(ldap_connect_timeout_str)
        except ValueError:
            ldap_connect_timeout = 5
        audit_retention_str = os.environ.get("CERT_WATCH_AUDIT_RETENTION_DAYS", "90")
        try:
            audit_retention_days = int(audit_retention_str)
        except ValueError:
            logger.warning(
                "Invalid CERT_WATCH_AUDIT_RETENTION_DAYS=%r, using default 90",
                audit_retention_str,
            )
            audit_retention_days = 90
        history_retention_str = os.environ.get("CERT_WATCH_HISTORY_RETENTION_DAYS", "365")
        try:
            history_retention_days = int(history_retention_str)
        except ValueError:
            logger.warning(
                "Invalid CERT_WATCH_HISTORY_RETENTION_DAYS=%r, using default 365",
                history_retention_str,
            )
            history_retention_days = 365
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
            alert_digest_only=os.environ.get("ALERT_DIGEST_ONLY", "0") == "1",
            audit_retention_days=audit_retention_days,
            history_retention_days=history_retention_days,
            drift_alerts=os.environ.get("CERT_WATCH_DRIFT_ALERTS", "1") == "1",
            tls_verify=os.environ.get("CERT_WATCH_TLS_VERIFY", "0") == "1",
            allow_private=os.environ.get("CERT_WATCH_ALLOW_PRIVATE_IPS", "1") == "1",
            log_format=os.environ.get("CERT_WATCH_LOG_FORMAT", "text"),
            dns_servers=tuple(
                s.strip()
                for s in os.environ.get("CERT_WATCH_DNS_SERVERS", "").split(",")
                if s.strip()
            ),
            # Auth
            auth_provider=os.environ.get("AUTH_PROVIDER", ""),
            ldap_server=os.environ.get("LDAP_SERVER", ""),
            ldap_base_dn=os.environ.get("LDAP_BASE_DN", ""),
            ldap_bind_dn=os.environ.get("LDAP_BIND_DN", ""),
            ldap_bind_password=read_secret("LDAP_BIND_PASSWORD") or "",
            ldap_user_filter=os.environ.get("LDAP_USER_FILTER", "(sAMAccountName={username})"),
            ldap_start_tls=os.environ.get("LDAP_START_TLS", "0") == "1",
            ldap_ca_cert=read_secret("LDAP_CA_CERT") or "",
            ldap_required_groups=tuple(
                g.strip()
                for g in os.environ.get("LDAP_REQUIRED_GROUPS", "").split(",")
                if g.strip()
            ),
            ldap_connect_timeout=ldap_connect_timeout,
            oauth_client_id=os.environ.get("OAUTH_CLIENT_ID", ""),
            oauth_client_secret=read_secret("OAUTH_CLIENT_SECRET") or "",
            oauth_issuer_url=os.environ.get("OAUTH_ISSUER_URL", ""),
            oauth_scope=os.environ.get("OAUTH_SCOPE", "openid profile email"),
            oauth_authorization_endpoint=os.environ.get("OAUTH_AUTHORIZATION_ENDPOINT", ""),
            oauth_token_endpoint=os.environ.get("OAUTH_TOKEN_ENDPOINT", ""),
            oauth_userinfo_endpoint=os.environ.get("OAUTH_USERINFO_ENDPOINT", ""),
            # Authorization
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
            # Local break-glass admin
            local_admin_user=os.environ.get("CERT_WATCH_LOCAL_ADMIN_USER", ""),
            local_admin_password_hash=read_secret("CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH") or "",
            # Security
            base_url=os.environ.get("CERT_WATCH_BASE_URL", "").rstrip("/"),
            allow_unauth=os.environ.get("CERT_WATCH_ALLOW_UNAUTH", "0") == "1",
        )

    def build_alert_config(self):
        """Return an AlertConfig if SMTP envs are sufficiently populated, else None.

        Preserves the existing convention: when host/from/recipients are absent,
        return None so process_pending() no-ops.
        """
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
        )

    def build_webhook_config(self):
        """Return a WebhookConfig if webhook URL is set, else None."""
        from cert_watch.alerts import WebhookConfig

        if not self.webhook_url:
            return None
        return WebhookConfig(
            url=self.webhook_url,
            headers=self.webhook_headers or {},
            template=self.webhook_template,
        )

    def build_auth_provider(self):
        """Return an AuthProvider based on auth config. No-op when AUTH_PROVIDER is unset."""
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
            oauth_client_id=self.oauth_client_id,
            oauth_client_secret=self.oauth_client_secret,
            oauth_issuer_url=self.oauth_issuer_url,
            oauth_scope=self.oauth_scope,
            oauth_authorization_endpoint=self.oauth_authorization_endpoint,
            oauth_token_endpoint=self.oauth_token_endpoint,
            oauth_userinfo_endpoint=self.oauth_userinfo_endpoint,
            allowed_groups=list(self.allowed_groups),
            allowed_roles=list(self.allowed_roles),
            local_admin_user=self.local_admin_user,
            local_admin_password_hash=self.local_admin_password_hash,
        )



