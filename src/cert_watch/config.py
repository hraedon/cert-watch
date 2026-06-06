import json
import logging
import os
import secrets
from dataclasses import dataclass, field
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


def _parse_role_map(raw: str) -> dict:
    """Parse CERT_WATCH_ROLE_MAP JSON.  Returns {} on empty / invalid input."""
    if not raw:
        return {}
    try:
        import json
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def split_group_dns(raw: str) -> tuple[str, ...]:
    """Split a list of LDAP group DNs on semicolons or newlines.

    Group DNs contain commas (``CN=admins,OU=Groups,DC=example,DC=com``), so a
    comma-delimited list is ambiguous: it shreds each DN into its RDN fragments
    (``CN=admins``, ``OU=Groups``, ``DC=example``, …), and the resulting group
    filter matches nothing — every LDAP_REQUIRED_GROUPS login fails as "not in
    required group(s)". Semicolons/newlines do not appear in normal AD DNs, so
    they are the safe delimiter for a list of DNs.
    """
    parts = raw.replace("\n", ";").split(";")
    return tuple(p.strip() for p in parts if p.strip())


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


# Setting keys (kv_store column names) whose values are secrets: encrypted at
# rest when written via the GUI, decrypted on read, and masked in the UI. Single
# source of truth — `routes/settings.py` imports this so the encrypt/decrypt/mask
# sides cannot drift. (They previously diverged: `pagerduty_routing_key` was on
# the decrypt side here but missing from the settings-side set, so a future
# GUI-managed routing key would have been written in cleartext.)
SENSITIVE_SETTING_KEYS = frozenset({
    "ldap_bind_password",
    "ldap_ca_cert",
    "oauth_client_secret",
    "smtp_password",
    "pagerduty_routing_key",
})


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


def _parse_int(raw: str, default: int, name: str) -> int:
    """Parse an integer env var with fallback and warning on invalid input."""
    try:
        return int(raw)
    except ValueError:
        logger.warning("Invalid %s=%r, using default %s", name, raw, default)
        return default


def _parse_float(raw: str, default: float, name: str) -> float:
    """Parse a float env var with fallback and warning on invalid input."""
    try:
        return float(raw)
    except ValueError:
        logger.warning("Invalid %s=%r, using default %s", name, raw, default)
        return default


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
    webhook_kind: str = "generic"
    pagerduty_routing_key: str = ""
    alert_digest_only: bool = False
    tls_verify: bool = False
    allow_private: bool = True
    # CIDR allowlist scoping which PRIVATE ranges may be scanned. When set, a
    # private target IP is allowed only if it falls inside one of these CIDRs
    # (public hosts stay scannable; loopback/link-local stay blocked). Empty =
    # no allowlist, governed by allow_private. Makes internal scanning an
    # explicit, auditable capability rather than an ambient default.
    allowed_subnets: tuple[str, ...] = ()
    dns_servers: tuple[str, ...] = ()
    log_format: str = "text"
    audit_retention_days: int = 90
    history_retention_days: int = 365
    alert_retention_days: int = 90
    drift_alerts: bool = True
    renewal_window_days: int = 30  # 0 disables the renewal-stall alert (Plan 027)
    check_revocation: bool = False
    # Scan timeouts
    scan_timeout: float = 10.0
    scan_retries: int = 2
    scan_retry_backoff: float = 1.0
    hsts_timeout: float = 5.0
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
    ldap_group_filter: str = ""
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
    # Admin users (comma-separated usernames allowed to access /settings)
    admin_users: tuple[str, ...] = ()
    # Session lifetime in seconds (default 8 hours)
    session_ttl: int = 28800
    # Write users (comma-separated usernames allowed to write). When empty,
    # all authenticated users can write.
    write_users: tuple[str, ...] = ()
    # Role map (JSON) for Plan 035 (RBAC).  When empty, no role-gating
    # is active and all authenticated users get full access (backward compat).
    role_map: dict = field(default_factory=dict)
    # Local break-glass admin
    local_admin_user: str = ""
    local_admin_password_hash: str = ""
    # Security
    base_url: str = ""  # Override for OAuth redirect URI detection
    allow_unauth: bool = False  # Suppress unauthenticated warning (CERT_WATCH_ALLOW_UNAUTH=1)
    jwks_cache_ttl: int = 86400  # JWKS cache TTL in seconds (CERT_WATCH_JWKS_CACHE_TTL)

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
        renewal_window_str = os.environ.get("CERT_WATCH_RENEWAL_WINDOW_DAYS", "30")
        try:
            renewal_window_days = int(renewal_window_str)
        except ValueError:
            logger.warning(
                "Invalid CERT_WATCH_RENEWAL_WINDOW_DAYS=%r, using default 30",
                renewal_window_str,
            )
            renewal_window_days = 30
        history_retention_str = os.environ.get("CERT_WATCH_HISTORY_RETENTION_DAYS", "365")
        try:
            history_retention_days = int(history_retention_str)
        except ValueError:
            logger.warning(
                "Invalid CERT_WATCH_HISTORY_RETENTION_DAYS=%r, using default 365",
                history_retention_str,
            )
            history_retention_days = 365
        alert_retention_str = os.environ.get("CERT_WATCH_ALERT_RETENTION_DAYS", "90")
        try:
            alert_retention_days = int(alert_retention_str)
        except ValueError:
            logger.warning(
                "Invalid CERT_WATCH_ALERT_RETENTION_DAYS=%r, using default 90",
                alert_retention_str,
            )
            alert_retention_days = 90
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
            # Auth
            auth_provider=os.environ.get("AUTH_PROVIDER", ""),
            ldap_server=os.environ.get("LDAP_SERVER", ""),
            ldap_base_dn=os.environ.get("LDAP_BASE_DN", ""),
            ldap_bind_dn=os.environ.get("LDAP_BIND_DN", ""),
            ldap_bind_password=read_secret("LDAP_BIND_PASSWORD") or "",
            ldap_user_filter=os.environ.get("LDAP_USER_FILTER", "(sAMAccountName={username})"),
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
            # Admin users
            admin_users=tuple(
                u.strip()
                for u in os.environ.get("CERT_WATCH_ADMINS", "").split(",")
                if u.strip()
            ),
            # Scan timeouts
            scan_timeout=_parse_float(
                os.environ.get("CERT_WATCH_SCAN_TIMEOUT", "10.0"), 10.0,
                "CERT_WATCH_SCAN_TIMEOUT",
            ),
            scan_retries=_parse_int(
                os.environ.get("CERT_WATCH_SCAN_RETRIES", "2"), 2,
                "CERT_WATCH_SCAN_RETRIES",
            ),
            scan_retry_backoff=_parse_float(
                os.environ.get("CERT_WATCH_SCAN_RETRY_BACKOFF", "1.0"), 1.0,
                "CERT_WATCH_SCAN_RETRY_BACKOFF",
            ),
            hsts_timeout=_parse_float(
                os.environ.get("CERT_WATCH_HSTS_TIMEOUT", "5.0"), 5.0,
                "CERT_WATCH_HSTS_TIMEOUT",
            ),
            # Session TTL
            session_ttl=_parse_int(
                os.environ.get("CERT_WATCH_SESSION_TTL", "28800"), 28800,
                "CERT_WATCH_SESSION_TTL",
            ),
            # Write users
            write_users=tuple(
                u.strip()
                for u in os.environ.get("CERT_WATCH_WRITE_USERS", "").split(",")
                if u.strip()
            ),
            # RBAC role map (Plan 035)
            role_map=_parse_role_map(
                os.environ.get("CERT_WATCH_ROLE_MAP", "")
            ),
            # Local break-glass admin
            local_admin_user=os.environ.get("CERT_WATCH_LOCAL_ADMIN_USER", ""),
            local_admin_password_hash=read_secret("CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH") or "",
            # Security
            base_url=os.environ.get("CERT_WATCH_BASE_URL", "").rstrip("/"),
            allow_unauth=os.environ.get("CERT_WATCH_ALLOW_UNAUTH", "0") == "1",
            jwks_cache_ttl=int(os.environ.get("CERT_WATCH_JWKS_CACHE_TTL", "86400")),
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
            kind=self.webhook_kind,
            routing_key=self.pagerduty_routing_key,
            headers=self.webhook_headers or {},
            template=self.webhook_template,
            allow_private=self.allow_private,
            allowed_subnets=self.allowed_subnets,
        )

    def build_auth_provider(self):
        """Return an AuthProvider based on auth config. No-op when AUTH_PROVIDER is unset.

        Falls back to kv_store for local_admin_user/local_admin_password_hash when
        env vars are unset (Plan 014 Slice 2).
        """
        from cert_watch.auth import build_auth_provider
        from cert_watch.database import kv_get

        local_admin_user = self.local_admin_user
        local_admin_password_hash = self.local_admin_password_hash
        if not local_admin_user:
            local_admin_user = kv_get(self.db_path, "local_admin_user") or ""
        if not local_admin_password_hash:
            local_admin_password_hash = kv_get(self.db_path, "local_admin_password_hash") or ""

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
        )

    @classmethod
    def from_env_with_kv(cls, db_path: Path, encryption_key: str | None = None) -> "Settings":
        """Build Settings with kv_store fallback for auth/smtp/alert fields.

        Env vars take precedence; kv_store values fill in where env is unset.
        When *encryption_key* is set, sensitive kv_store values with the
        ``enc:v1:`` prefix are transparently decrypted (BC-082).
        """
        base = cls.from_env()
        if not db_path:
            return base
        try:
            from cert_watch.database import fernet_decrypt, kv_all
            kv = kv_all(db_path)
        except Exception:
            return base
        if not kv:
            return base

        def _decrypt(key: str, val: str) -> str:
            if encryption_key and key in SENSITIVE_SETTING_KEYS:
                result = fernet_decrypt(val, encryption_key)
                return result if result is not None else ""
            return val

        def _kv(env_val: str, kv_key: str, default: str = "") -> str:
            """Return env_val if set, else kv_store value, else default."""
            if env_val:
                return env_val
            raw = kv.get(kv_key, "")
            return _decrypt(kv_key, raw) if raw else default

        def _kv_bool(env_val: bool, kv_key: str, env_name: str) -> bool:
            """Env wins when the env var is explicitly set (even to 0); else
            kv_store; else the parsed env default.

            Checking ``env_name in os.environ`` is what makes explicit env
            precedence work for booleans whose default is False — without it a
            kv_store "1" silently overrode an operator's explicit ``=0`` (BC-076).
            """
            if env_name in os.environ:
                return env_val
            kv_val = kv.get(kv_key, "")
            if kv_val:
                return kv_val == "1" or kv_val.lower() == "true"
            return env_val

        def _kv_tuple(env_val: tuple[str, ...], kv_key: str) -> tuple[str, ...]:
            """Return env_val if set, else parse kv_store csv."""
            if env_val:
                return env_val
            raw = kv.get(kv_key, "")
            if raw:
                return tuple(g.strip() for g in raw.split(",") if g.strip())
            return env_val

        # Merge auth fields
        auth_provider = _kv(base.auth_provider, "auth_provider")
        ldap_server = _kv(base.ldap_server, "ldap_server")
        ldap_base_dn = _kv(base.ldap_base_dn, "ldap_base_dn")
        ldap_bind_dn = _kv(base.ldap_bind_dn, "ldap_bind_dn")
        ldap_bind_password = _kv(base.ldap_bind_password, "ldap_bind_password")
        ldap_user_filter = _kv(
            base.ldap_user_filter, "ldap_user_filter",
            "(sAMAccountName={username})",
        )
        ldap_start_tls = _kv_bool(base.ldap_start_tls, "ldap_start_tls", "LDAP_START_TLS")
        allowed_subnets = _kv_tuple(base.allowed_subnets, "allowed_subnets")
        ldap_ca_cert = _kv(base.ldap_ca_cert, "ldap_ca_cert")
        # NB: group DNs contain commas, so they use the semicolon/newline-safe
        # split (split_group_dns), not the comma-based _kv_tuple used for subnets.
        ldap_required_groups = base.ldap_required_groups or split_group_dns(
            kv.get("ldap_required_groups", "")
        )
        ldap_connect_timeout_str = kv.get("ldap_connect_timeout", "")
        if ldap_connect_timeout_str:
            try:
                ldap_connect_timeout = int(ldap_connect_timeout_str)
            except ValueError:
                ldap_connect_timeout = base.ldap_connect_timeout
        else:
            ldap_connect_timeout = base.ldap_connect_timeout
        ldap_group_filter = _kv(base.ldap_group_filter, "ldap_group_filter")
        oauth_client_id = _kv(base.oauth_client_id, "oauth_client_id")
        oauth_client_secret = _kv(base.oauth_client_secret, "oauth_client_secret")
        oauth_issuer_url = _kv(base.oauth_issuer_url, "oauth_issuer_url")
        oauth_scope = _kv(base.oauth_scope, "oauth_scope", "openid profile email")
        oauth_authorization_endpoint = _kv(
            base.oauth_authorization_endpoint,
            "oauth_authorization_endpoint",
        )
        oauth_token_endpoint = _kv(base.oauth_token_endpoint, "oauth_token_endpoint")
        oauth_userinfo_endpoint = _kv(base.oauth_userinfo_endpoint, "oauth_userinfo_endpoint")

        # Merge SMTP fields
        smtp_host = _kv(base.smtp_host or "", "smtp_host") or None
        smtp_port_str = kv.get("smtp_port", "")
        try:
            smtp_port = int(smtp_port_str) if smtp_port_str else base.smtp_port
        except ValueError:
            smtp_port = base.smtp_port
        smtp_user = _kv(base.smtp_user or "", "smtp_user") or None
        smtp_password = _kv(base.smtp_password or "", "smtp_password") or None
        alert_from = _kv(base.alert_from or "", "alert_from") or None
        alert_recipients_raw = kv.get("alert_recipients", "")
        if not base.alert_recipients and alert_recipients_raw:
            alert_recipients = tuple(
                r.strip()
                for r in alert_recipients_raw.split(",")
                if r.strip()
            )
        else:
            alert_recipients = base.alert_recipients

        # Merge alert fields
        webhook_url = _kv(base.webhook_url or "", "webhook_url") or None
        webhook_template = _kv(base.webhook_template, "webhook_template")
        webhook_kind = _kv(base.webhook_kind, "webhook_kind")
        pagerduty_routing_key = _kv(base.pagerduty_routing_key, "pagerduty_routing_key")
        alert_digest_only_str = kv.get("alert_digest_only", "")
        alert_digest_only = base.alert_digest_only
        if alert_digest_only_str and not base.alert_digest_only:
            alert_digest_only = alert_digest_only_str == "1"

        # Merge local admin from kv_store
        local_admin_user = base.local_admin_user
        local_admin_password_hash = base.local_admin_password_hash
        if not local_admin_user:
            local_admin_user = kv.get("local_admin_user", "")
        if not local_admin_password_hash:
            local_admin_password_hash = kv.get("local_admin_password_hash", "")

        return cls(
            db_path=base.db_path,
            data_dir=base.data_dir,
            sched_hour=base.sched_hour,
            sched_min=base.sched_min,
            smtp_host=smtp_host,
            smtp_port=smtp_port,
            smtp_user=smtp_user,
            smtp_password=smtp_password,
            alert_from=alert_from,
            alert_recipients=alert_recipients,
            webhook_url=webhook_url,
            webhook_headers=base.webhook_headers,
            webhook_template=webhook_template,
            webhook_kind=webhook_kind,
            pagerduty_routing_key=pagerduty_routing_key,
            alert_digest_only=alert_digest_only,
            tls_verify=base.tls_verify,
            allow_private=base.allow_private,
            allowed_subnets=allowed_subnets,
            dns_servers=base.dns_servers,
            log_format=base.log_format,
            audit_retention_days=base.audit_retention_days,
            history_retention_days=base.history_retention_days,
            alert_retention_days=base.alert_retention_days,
            drift_alerts=base.drift_alerts,
            renewal_window_days=base.renewal_window_days,
            check_revocation=base.check_revocation,
            # Auth
            auth_provider=auth_provider,
            ldap_server=ldap_server,
            ldap_base_dn=ldap_base_dn,
            ldap_bind_dn=ldap_bind_dn,
            ldap_bind_password=ldap_bind_password,
            ldap_user_filter=ldap_user_filter,
            ldap_start_tls=ldap_start_tls,
            ldap_ca_cert=ldap_ca_cert,
            ldap_required_groups=ldap_required_groups,
            ldap_connect_timeout=ldap_connect_timeout,
            ldap_group_filter=ldap_group_filter,
            oauth_client_id=oauth_client_id,
            oauth_client_secret=oauth_client_secret,
            oauth_issuer_url=oauth_issuer_url,
            oauth_scope=oauth_scope,
            oauth_authorization_endpoint=oauth_authorization_endpoint,
            oauth_token_endpoint=oauth_token_endpoint,
            oauth_userinfo_endpoint=oauth_userinfo_endpoint,
            # Authorization
            allowed_groups=base.allowed_groups,
            allowed_roles=base.allowed_roles,
            # Admin users
            admin_users=base.admin_users,
            # Session TTL
            session_ttl=base.session_ttl,
            # Write users
            write_users=base.write_users,
            # Local break-glass admin
            local_admin_user=local_admin_user,
            local_admin_password_hash=local_admin_password_hash,
            # Security
            base_url=base.base_url,
            allow_unauth=base.allow_unauth,
        )



