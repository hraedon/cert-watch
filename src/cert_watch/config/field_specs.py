"""Declarative metadata for every :class:`cert_watch.config.Settings` field."""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Any, Literal

ParserKind = Literal["str", "int", "bool", "float", "csv", "json", "path", "secret-file"]
NormalizeKind = Literal["none", "strip", "rstrip-slash", "lower", "group-dns", "string-dict"]


@dataclass(frozen=True)
class FieldSpec:
    """One setting's sources, conversion, validation, and disclosure policy."""

    env_names: tuple[str, ...]
    kv_key: str | None
    parser: ParserKind
    default: Any
    minimum: int | None = None
    maximum: int | None = None
    bounds: Literal["reject"] | None = None
    sensitive: bool = False
    optional: bool = False
    empty_uses_default: bool = False
    normalize: NormalizeKind = "none"
    derived_from: str | None = None


def _default_data_dir_str(os_name: str, programdata: str | None) -> str:
    """Compute the platform default without constructing WindowsPath on POSIX."""
    if os_name == "nt":
        return str(PureWindowsPath(programdata or r"C:\ProgramData", "cert-watch"))
    return "/var/lib/cert-watch"


def default_data_dir() -> Path:
    return Path(_default_data_dir_str(os.name, os.environ.get("PROGRAMDATA")))


# Tuple-valued env_names supports ordered legacy aliases. There are no retained
# aliases today; adding one is a table-only change and the first explicitly set
# name wins.
FIELD_SPECS: dict[str, FieldSpec] = {
    # These two legacy readers used ``value or default``. Keep their explicit
    # blank-string behavior in the parser while retaining the one source-order
    # rule (the env source is still selected before kv/default).
    "data_dir": FieldSpec(
        ("CERT_WATCH_DATA_DIR",), None, "path", default_data_dir, empty_uses_default=True
    ),
    "db_path": FieldSpec((), None, "path", "cert-watch.sqlite3", derived_from="data_dir"),
    "sched_hour": FieldSpec(("CERT_WATCH_SCHED_HOUR",), "sched_hour", "int", 6, 0, 23, "reject"),
    "sched_min": FieldSpec(("CERT_WATCH_SCHED_MIN",), "sched_min", "int", 0, 0, 59, "reject"),
    "smtp_host": FieldSpec(("SMTP_HOST",), "smtp_host", "str", None, optional=True),
    "smtp_port": FieldSpec(("SMTP_PORT",), "smtp_port", "int", 587, 1, 65535, "reject"),
    "smtp_user": FieldSpec(("SMTP_USER",), "smtp_user", "str", None, optional=True),
    "smtp_password": FieldSpec(
        ("SMTP_PASSWORD",), "smtp_password", "secret-file", None, sensitive=True, optional=True
    ),
    "alert_from": FieldSpec(("ALERT_FROM",), "alert_from", "str", None, optional=True),
    "alert_recipients": FieldSpec(("ALERT_RECIPIENTS",), "alert_recipients", "csv", ()),
    "webhook_url": FieldSpec(("ALERT_WEBHOOK_URL",), "webhook_url", "str", None, optional=True),
    "webhook_headers": FieldSpec(
        ("ALERT_WEBHOOK_HEADERS",), "webhook_headers", "json", None, sensitive=True, optional=True
    ),
    "webhook_template": FieldSpec(("ALERT_WEBHOOK_TEMPLATE",), "webhook_template", "str", ""),
    "webhook_kind": FieldSpec(("ALERT_WEBHOOK_KIND",), "webhook_kind", "str", "generic"),
    "pagerduty_routing_key": FieldSpec(
        ("ALERT_PAGERDUTY_ROUTING_KEY",), "pagerduty_routing_key", "secret-file", "", sensitive=True
    ),
    "alert_digest_only": FieldSpec(("ALERT_DIGEST_ONLY",), "alert_digest_only", "bool", False),
    "tls_verify": FieldSpec(("CERT_WATCH_TLS_VERIFY",), None, "bool", False),
    "allow_private": FieldSpec(("CERT_WATCH_ALLOW_PRIVATE_IPS",), None, "bool", True),
    "allowed_subnets": FieldSpec(("CERT_WATCH_ALLOWED_SUBNETS",), "allowed_subnets", "csv", ()),
    "dns_servers": FieldSpec(("CERT_WATCH_DNS_SERVERS",), None, "csv", ()),
    "log_format": FieldSpec(("CERT_WATCH_LOG_FORMAT",), None, "str", "text"),
    "audit_retention_days": FieldSpec(
        ("CERT_WATCH_AUDIT_RETENTION_DAYS",), None, "int", 90, 0, 3650, "reject"
    ),
    "history_retention_days": FieldSpec(
        ("CERT_WATCH_HISTORY_RETENTION_DAYS",), None, "int", 365, 0, 3650, "reject"
    ),
    "alert_retention_days": FieldSpec(
        ("CERT_WATCH_ALERT_RETENTION_DAYS",), "alert_retention_days", "int", 90, 0, 3650, "reject"
    ),
    "drift_alerts": FieldSpec(("CERT_WATCH_DRIFT_ALERTS",), "drift_alerts", "bool", True),
    "event_retention_days": FieldSpec(
        ("CERT_WATCH_EVENT_RETENTION_DAYS",), None, "int", 30, 0, 3650, "reject"
    ),
    "renewal_window_days": FieldSpec(
        ("CERT_WATCH_RENEWAL_WINDOW_DAYS",), "renewal_window_days", "int", 30, 0, 365, "reject"
    ),
    "check_revocation": FieldSpec(
        ("CERT_WATCH_CHECK_REVOCATION",), "check_revocation", "bool", False
    ),
    "scan_timeout": FieldSpec(("CERT_WATCH_SCAN_TIMEOUT",), None, "float", 10.0),
    "scan_retries": FieldSpec(("CERT_WATCH_SCAN_RETRIES",), None, "int", 2, 0, 10, "reject"),
    "scan_retry_backoff": FieldSpec(("CERT_WATCH_SCAN_RETRY_BACKOFF",), None, "float", 1.0),
    "scan_max_output_bytes": FieldSpec(
        ("CERT_WATCH_SCAN_MAX_OUTPUT_BYTES",), None, "int", 1048576, 1024, None, "reject"
    ),
    "hsts_timeout": FieldSpec(("CERT_WATCH_HSTS_TIMEOUT",), None, "float", 5.0),
    "auth_provider": FieldSpec(("AUTH_PROVIDER",), "auth_provider", "str", ""),
    "ldap_server": FieldSpec(("LDAP_SERVER",), "ldap_server", "str", ""),
    "ldap_base_dn": FieldSpec(("LDAP_BASE_DN",), "ldap_base_dn", "str", ""),
    "ldap_bind_dn": FieldSpec(("LDAP_BIND_DN",), "ldap_bind_dn", "str", ""),
    "ldap_bind_password": FieldSpec(
        ("LDAP_BIND_PASSWORD",), "ldap_bind_password", "secret-file", "", sensitive=True
    ),
    "ldap_user_filter": FieldSpec(
        ("LDAP_USER_FILTER",), "ldap_user_filter", "str", "(sAMAccountName={username})"
    ),
    "ldap_start_tls": FieldSpec(("LDAP_START_TLS",), "ldap_start_tls", "bool", False),
    "ldap_allow_insecure": FieldSpec(
        ("CERT_WATCH_LDAP_ALLOW_INSECURE",), None, "bool", False
    ),
    "ldap_ca_cert": FieldSpec(("LDAP_CA_CERT",), "ldap_ca_cert", "secret-file", "", sensitive=True),
    "ldap_required_groups": FieldSpec(
        ("LDAP_REQUIRED_GROUPS",), "ldap_required_groups", "csv", (), normalize="group-dns"
    ),
    "ldap_connect_timeout": FieldSpec(
        ("LDAP_CONNECT_TIMEOUT",), "ldap_connect_timeout", "int", 5, 1, 300, "reject"
    ),
    "ldap_group_filter": FieldSpec(("LDAP_GROUP_FILTER",), "ldap_group_filter", "str", ""),
    "oauth_client_id": FieldSpec(("OAUTH_CLIENT_ID",), "oauth_client_id", "str", ""),
    "oauth_client_secret": FieldSpec(
        ("OAUTH_CLIENT_SECRET",), "oauth_client_secret", "secret-file", "", sensitive=True
    ),
    "oauth_issuer_url": FieldSpec(("OAUTH_ISSUER_URL",), "oauth_issuer_url", "str", ""),
    "oauth_scope": FieldSpec(("OAUTH_SCOPE",), "oauth_scope", "str", "openid profile email"),
    "oauth_authorization_endpoint": FieldSpec(
        ("OAUTH_AUTHORIZATION_ENDPOINT",), "oauth_authorization_endpoint", "str", ""
    ),
    "oauth_token_endpoint": FieldSpec(("OAUTH_TOKEN_ENDPOINT",), "oauth_token_endpoint", "str", ""),
    "oauth_userinfo_endpoint": FieldSpec(
        ("OAUTH_USERINFO_ENDPOINT",), "oauth_userinfo_endpoint", "str", ""
    ),
    "allowed_groups": FieldSpec(("CERT_WATCH_ALLOWED_GROUPS",), None, "csv", ()),
    "allowed_roles": FieldSpec(("CERT_WATCH_ALLOWED_ROLES",), None, "csv", ()),
    "admin_users": FieldSpec(("CERT_WATCH_ADMINS",), None, "csv", ()),
    "session_ttl": FieldSpec(
        ("CERT_WATCH_SESSION_TTL",), None, "int", 28800, 60, 2592000, "reject"
    ),
    "write_users": FieldSpec(("CERT_WATCH_WRITE_USERS",), None, "csv", ()),
    "role_map": FieldSpec(("CERT_WATCH_ROLE_MAP",), None, "json", dict),
    "local_admin_user": FieldSpec(("CERT_WATCH_LOCAL_ADMIN_USER",), "local_admin_user", "str", ""),
    "local_admin_password_hash": FieldSpec(
        ("CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH",),
        "local_admin_password_hash",
        "secret-file",
        "",
        sensitive=True,
    ),
    "base_url": FieldSpec(("CERT_WATCH_BASE_URL",), None, "str", "", normalize="rstrip-slash"),
    "allow_unauth": FieldSpec(("CERT_WATCH_ALLOW_UNAUTH",), None, "bool", False),
    "jwks_cache_ttl": FieldSpec(
        ("CERT_WATCH_JWKS_CACHE_TTL",), None, "int", 86400, 60, 604800, "reject"
    ),
    "renewal_webhook_url": FieldSpec(
        ("CERT_WATCH_RENEWAL_WEBHOOK_URL",), None, "str", "", normalize="strip"
    ),
    "renewal_webhook_headers": FieldSpec(
        ("CERT_WATCH_RENEWAL_WEBHOOK_HEADERS",),
        None,
        "json",
        None,
        sensitive=True,
        optional=True,
        normalize="string-dict",
    ),
    "event_stream_config": FieldSpec(
        (), "event_stream_config", "json", None, optional=True
    ),
    "event_stream_pagerduty_routing_key": FieldSpec(
        (),
        "event_stream_pagerduty_routing_key",
        "secret-file",
        "",
        sensitive=True,
    ),
    "policy_config": FieldSpec((), "policy_set", "json", None, optional=True),
    # Runtime/security settings formerly read ad hoc outside config/.
    "auth_secret": FieldSpec(("CERT_WATCH_AUTH_SECRET",), None, "secret-file", "", sensitive=True),
    "csrf_secret": FieldSpec(("CERT_WATCH_CSRF_SECRET",), None, "str", "", sensitive=True),
    "cookie_secure": FieldSpec(("CERT_WATCH_COOKIE_SECURE",), None, "bool", True),
    "bind_host": FieldSpec(("CERT_WATCH_HOST",), None, "str", "0.0.0.0"),
    "trust_proxy": FieldSpec(("CERT_WATCH_TRUST_PROXY",), None, "bool", False),
    "trusted_proxies": FieldSpec(("CERT_WATCH_TRUSTED_PROXIES",), None, "csv", ()),
    "metrics_token": FieldSpec(("CERT_WATCH_METRICS_TOKEN",), None, "str", "", sensitive=True),
    "csp_report_uri": FieldSpec(("CERT_WATCH_CSP_REPORT_URI",), None, "str", ""),
    "instance_id": FieldSpec(
        ("CERT_WATCH_INSTANCE_ID",),
        None,
        "str",
        socket.gethostname,
        empty_uses_default=True,
    ),
    "syslog_host": FieldSpec(("CERT_WATCH_SYSLOG_HOST",), None, "str", "", normalize="strip"),
    "syslog_port": FieldSpec(("CERT_WATCH_SYSLOG_PORT",), None, "int", 514),
    "syslog_proto": FieldSpec(("CERT_WATCH_SYSLOG_PROTO",), None, "str", "udp", normalize="lower"),
    "hec_url": FieldSpec(("CERT_WATCH_HEC_URL",), None, "str", "", normalize="strip"),
    "hec_token": FieldSpec(("CERT_WATCH_HEC_TOKEN",), None, "secret-file", "", sensitive=True),
    "hec_index": FieldSpec(("CERT_WATCH_HEC_INDEX",), None, "str", "", normalize="strip"),
    "hec_sourcetype": FieldSpec(
        ("CERT_WATCH_HEC_SOURCETYPE",), None, "str", "cert_watch", normalize="strip"
    ),
    "eventlog_requested": FieldSpec(("CERT_WATCH_EVENTLOG",), None, "bool", False),
    "eventlog_source": FieldSpec(("CERT_WATCH_EVENTLOG_SOURCE",), None, "str", "cert-watch"),
}


SENSITIVE_SETTING_KEYS = frozenset(
    spec.kv_key for spec in FIELD_SPECS.values() if spec.sensitive and spec.kv_key
)
