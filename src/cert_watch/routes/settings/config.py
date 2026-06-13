"""Configuration key maps and kv_store/env merge helpers for settings routes."""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import Request

from cert_watch.config import SENSITIVE_SETTING_KEYS

# ---------- Per-section config keys and their env var names ----------

_AUTH_KEYS = {
    "auth_provider": "AUTH_PROVIDER",
    "ldap_server": "LDAP_SERVER",
    "ldap_base_dn": "LDAP_BASE_DN",
    "ldap_bind_dn": "LDAP_BIND_DN",
    "ldap_bind_password": "LDAP_BIND_PASSWORD",
    "ldap_user_filter": "LDAP_USER_FILTER",
    "ldap_start_tls": "LDAP_START_TLS",
    "ldap_ca_cert": "LDAP_CA_CERT",
    "ldap_required_groups": "LDAP_REQUIRED_GROUPS",
    "ldap_connect_timeout": "LDAP_CONNECT_TIMEOUT",
    "oauth_client_id": "OAUTH_CLIENT_ID",
    "oauth_client_secret": "OAUTH_CLIENT_SECRET",
    "oauth_issuer_url": "OAUTH_ISSUER_URL",
    "oauth_scope": "OAUTH_SCOPE",
    "oauth_authorization_endpoint": "OAUTH_AUTHORIZATION_ENDPOINT",
    "oauth_token_endpoint": "OAUTH_TOKEN_ENDPOINT",
    "oauth_userinfo_endpoint": "OAUTH_USERINFO_ENDPOINT",
}

_SMTP_KEYS = {
    "smtp_host": "SMTP_HOST",
    "smtp_port": "SMTP_PORT",
    "smtp_user": "SMTP_USER",
    "smtp_password": "SMTP_PASSWORD",
    "alert_from": "ALERT_FROM",
    "alert_recipients": "ALERT_RECIPIENTS",
}

_ALERT_KEYS = {
    "webhook_url": "ALERT_WEBHOOK_URL",
    "webhook_headers": "ALERT_WEBHOOK_HEADERS",
    "webhook_template": "ALERT_WEBHOOK_TEMPLATE",
    "webhook_kind": "ALERT_WEBHOOK_KIND",
    "alert_digest_only": "ALERT_DIGEST_ONLY",
}

# Single source of truth lives in config (SENSITIVE_SETTING_KEYS) so the
# encrypt-side (this module) and the decrypt-side (config.from_env_with_kv)
# cannot diverge. Don't re-inline this as a literal.
_SENSITIVE_KEYS = SENSITIVE_SETTING_KEYS


def _get_encryption_key(request: Request) -> str | None:
    """Return the Fernet encryption key derived from the signing key (BC-082)."""
    from cert_watch.database import derive_encryption_key

    security = getattr(request.app.state, "security", None)
    if security:
        return derive_encryption_key(security.signing_key)
    return None


def _env_overrides(keys: dict[str, str], db_path: Path) -> dict[str, bool]:
    """Return {kv_key: True} for keys where the env var is set (takes precedence)."""
    overrides: dict[str, bool] = {}
    for kv_key, env_name in keys.items():
        env_val = os.environ.get(env_name)
        if env_val is not None and env_val.strip():
            overrides[kv_key] = True
    return overrides


def _effective_config(
    keys: dict[str, str],
    db_path: Path,
    encryption_key: str | None = None,
) -> dict[str, str]:
    """Merge kv_store values with env var overrides (env wins).

    When *encryption_key* is set, sensitive values stored in encrypted form
    (``enc:v1:`` prefix) are transparently decrypted (BC-082).
    """
    from cert_watch.config import read_secret
    from cert_watch.database import fernet_decrypt, kv_all

    kv = kv_all(db_path)
    result: dict[str, str] = {}
    for kv_key, env_name in keys.items():
        env_val = os.environ.get(env_name)
        if env_val is not None and env_val.strip():
            result[kv_key] = env_val
        elif kv_key in kv and kv[kv_key]:
            val = kv[kv_key]
            if encryption_key and kv_key in _SENSITIVE_KEYS:
                val = fernet_decrypt(val, encryption_key) or ""
            result[kv_key] = val
        else:
            result[kv_key] = ""
    # Handle _FILE secrets
    for kv_key in _SENSITIVE_KEYS:
        if kv_key in keys:
            env_name = keys[kv_key]
            secret = read_secret(env_name)
            if secret:
                result[kv_key] = secret
    return result
