"""Configuration key maps and kv_store/env merge helpers for settings routes."""

from __future__ import annotations

from pathlib import Path

from fastapi import Request

from cert_watch.config import (
    FIELD_SPECS,
    SENSITIVE_SETTING_KEYS,
    setting_env_is_set,
    ui_field_map,
)

# ---------- Per-section config keys and their env var names ----------

_AUTH_KEYS = ui_field_map(
    (
        "auth_provider",
        "ldap_server",
        "ldap_base_dn",
        "ldap_bind_dn",
        "ldap_bind_password",
        "ldap_user_filter",
        "ldap_start_tls",
        "ldap_ca_cert",
        "ldap_required_groups",
        "ldap_connect_timeout",
        "oauth_client_id",
        "oauth_client_secret",
        "oauth_issuer_url",
        "oauth_scope",
        "oauth_authorization_endpoint",
        "oauth_token_endpoint",
        "oauth_userinfo_endpoint",
    )
)

_SMTP_KEYS = ui_field_map(
    (
        "smtp_host",
        "smtp_port",
        "smtp_user",
        "smtp_password",
        "alert_from",
        "alert_recipients",
    )
)

_ALERT_KEYS = ui_field_map(
    (
        "webhook_url",
        "webhook_headers",
        "webhook_template",
        "webhook_kind",
        "alert_digest_only",
        "drift_alerts",
        "renewal_window_days",
        "alert_retention_days",
        "sched_hour",
        "sched_min",
        "check_revocation",
    )
)

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
    del db_path  # retained for backward-compatible call sites
    by_kv = {spec.kv_key: name for name, spec in FIELD_SPECS.items() if spec.kv_key}
    return {kv_key: True for kv_key in keys if setting_env_is_set(by_kv[kv_key])}


def _effective_config(
    keys: dict[str, str],
    db_path: Path,
    encryption_key: str | None = None,
) -> dict[str, str]:
    """Merge kv_store values with env var overrides (env wins).

    When *encryption_key* is set, sensitive values stored in encrypted form
    (``enc:v1:`` prefix) are transparently decrypted (BC-082).
    """
    import json

    from cert_watch.config import current_settings
    from cert_watch.database import kv_all

    settings = current_settings(db_path, encryption_key=encryption_key)
    kv = kv_all(db_path)
    by_kv = {spec.kv_key: name for name, spec in FIELD_SPECS.items() if spec.kv_key}
    result: dict[str, str] = {}
    for kv_key in keys:
        field_name = by_kv[kv_key]
        if not setting_env_is_set(field_name) and not kv.get(kv_key):
            result[kv_key] = ""
            continue
        value = getattr(settings, field_name)
        spec = FIELD_SPECS[field_name]
        if value is None:
            rendered = ""
        elif isinstance(value, bool):
            rendered = "1" if value else "0"
        elif isinstance(value, tuple):
            separator = ";" if spec.normalize == "group-dns" else ","
            rendered = separator.join(value)
        elif isinstance(value, dict):
            rendered = json.dumps(value)
        else:
            rendered = str(value)
        result[kv_key] = rendered
    return result
