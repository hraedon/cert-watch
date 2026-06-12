"""Shared helpers for the settings route package."""

from __future__ import annotations

import contextlib
import ipaddress
import json
import logging
import os
import re
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from cert_watch import __commit__, __version__
from cert_watch.config import SENSITIVE_SETTING_KEYS, Settings
from cert_watch.database import ApiKeyEntry, kv_all, kv_set, kv_set_secret
from cert_watch.middleware import (
    get_auth_context,
    get_csrf_context,
    require_admin_form,
)
from cert_watch.routes._deps import _db_path, get_templates

logger = logging.getLogger("cert_watch.routes.settings")

templates = get_templates()

# Regex to strip IP addresses and ports from error messages to prevent info leakage.
_IP_ADDR_RE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b"
    r"|\[?(?:[0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F]{1,4}\]?(?::\d+)?"
)


# ---------- Auth config keys and their env var names ----------

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


def _sanitize_test_error(msg: str) -> str:
    """Strip IP addresses and internal details from error messages returned to the client."""
    return _IP_ADDR_RE.sub("<redacted>", msg)


def _get_encryption_key(request: Request) -> str | None:
    """Return the Fernet encryption key derived from the signing key (BC-082)."""
    from cert_watch.database import derive_encryption_key

    security = getattr(request.app.state, "security", None)
    if security:
        return derive_encryption_key(security.signing_key)
    return None


def _local_admin_configured(request: Request) -> bool:
    """Return True if a local admin account exists in kv_store."""
    from cert_watch.database import kv_get

    db = _db_path(request)
    return bool(kv_get(db, "local_admin_user"))


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
    from cert_watch.database import fernet_decrypt

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


def _settings_context(
    request: Request,
    *,
    tab: str = "auth",
    saved: str | None = None,
    error: str | None = None,
    password_changed: str | None = None,
    new_token: str | None = None,
    new_name: str | None = None,
) -> dict:
    """Build the full context dict for ``settings.html``.

    Used by ``settings_page()`` and ``_render_api_keys()`` so both render the
    same template with identical chrome (tabs, nav, auth config, etc.).
    """
    db = _db_path(request)
    enc_key = _get_encryption_key(request)
    auth_config = _effective_config(_AUTH_KEYS, db, enc_key)
    smtp_config = _effective_config(_SMTP_KEYS, db, enc_key)
    alert_config = _effective_config(_ALERT_KEYS, db, enc_key)
    env_overrides = {
        **_env_overrides(_AUTH_KEYS, db),
        **_env_overrides(_SMTP_KEYS, db),
        **_env_overrides(_ALERT_KEYS, db),
    }
    display_config = {}
    for k, v in {**auth_config, **smtp_config, **alert_config}.items():
        if k in _SENSITIVE_KEYS and v:
            display_config[k] = "••••••••"
        else:
            display_config[k] = v
    from cert_watch.database import kv_get

    local_admin = _local_admin_configured(request)
    env_hash_override = bool(os.environ.get("CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH", "").strip())
    autogenerated = local_admin and kv_get(db, "local_admin_autogenerated") == "1"

    ldap_role_map_raw = kv_get(db, "ldap_role_map") or "{}"
    try:
        ldap_role_map = json.loads(ldap_role_map_raw)
    except (json.JSONDecodeError, TypeError):
        ldap_role_map = {}

    from cert_watch.database import Role, User

    roles_data: list[Role] = []
    users_data: list[User] = []
    if tab in ("roles", "users"):
        from cert_watch.database import SqliteRoleRepository, SqliteUserRepository
        roles_data = SqliteRoleRepository(db).list_all()
        users_data = SqliteUserRepository(db).list_all()
    elif tab == "auth":
        from cert_watch.database import SqliteRoleRepository
        roles_data = SqliteRoleRepository(db).list_all()

    api_keys_data: list[ApiKeyEntry] = []
    if tab == "api-keys":
        from cert_watch.database import SqliteApiKeyRepository
        api_keys_data = SqliteApiKeyRepository(db).list_keys()

    policy_set = None
    if tab == "policy":
        from cert_watch.policy import load_policy_set
        policy_set = load_policy_set(str(db))

    auth_ctx = get_auth_context(request)
    csrf_ctx = get_csrf_context(request)
    return {
        "version": __version__, "commit": __commit__,
        "tab": tab,
        "saved": saved,
        "error": error,
        "password_changed": password_changed,
        "auth": display_config,
        "smtp": display_config,
        "alert": display_config,
        "env_overrides": env_overrides,
        "local_admin_configured": local_admin,
        "local_admin_autogenerated": autogenerated,
        "env_hash_override": env_hash_override,
        "ldap_role_map": ldap_role_map,
        "api_keys": api_keys_data,
        "policy_set": policy_set,
        "roles": roles_data,
        "users": users_data,
        "active_page": "settings",
        "new_token": new_token,
        "new_name": new_name,
        **auth_ctx,
        **csrf_ctx,
    }


def _render_api_keys(
    request: Request,
    *,
    new_token: str | None = None,
    new_name: str | None = None,
    error: str | None = None,
) -> HTMLResponse:
    """Render the API-keys management page inside the settings chrome.

    ``new_token`` is shown exactly once.  Uses ``settings.html`` (tab=api-keys)
    so the settings tabs remain visible — the old ``api_keys.html`` standalone
    template is no longer used here.
    """
    return templates.TemplateResponse(
        request=request,
        name="settings.html",
        context=_settings_context(
            request,
            tab="api-keys",
            new_token=new_token,
            new_name=new_name,
            error=error,
        ),
    )


def _rebuild_settings(request: Request, db_path: Path) -> None:
    """Rebuild Settings from env + kv_store and update app.state."""
    enc_key = _get_encryption_key(request)
    s = Settings.from_env_with_kv(db_path, encryption_key=enc_key)
    request.app.state.settings = s


async def _save_config_section(
    request: Request,
    keys: dict[str, str],
    tab_name: str,
    *,
    encrypt: bool = False,
    rebuild: bool = True,
) -> RedirectResponse:
    """Shared logic for saving a settings tab to kv_store.

    *encrypt*  – when True, sensitive keys (members of ``_SENSITIVE_KEYS``)
                   that are non-blank are stored encrypted (BC-082).
    *rebuild*  – when True, ``_rebuild_settings`` is called after saving.
    """
    admin_err = require_admin_form(request)
    if admin_err:
        return admin_err

    from cert_watch.middleware import check_csrf

    csrf_err = await check_csrf(request)
    if csrf_err:
        return RedirectResponse(
            url=f"/settings?tab={tab_name}&error={csrf_err}", status_code=303
        )

    db = _db_path(request)
    form = await request.form()
    enc_key = _get_encryption_key(request) if encrypt else None

    for kv_key in keys:
        raw = form.get(kv_key, "")
        val = raw.strip() if isinstance(raw, str) else ""
        if kv_key in _SENSITIVE_KEYS:
            if not val:
                continue
            if enc_key:
                kv_set_secret(db, kv_key, val, enc_key)
            else:
                kv_set(db, kv_key, val)
        else:
            kv_set(db, kv_key, val)

    if rebuild:
        _rebuild_settings(request, db)

    return RedirectResponse(url=f"/settings?tab={tab_name}&saved=1", status_code=303)


# ---------- TOFU CA capture for LDAPS test ----------


def _capture_ldaps_chain(
    url: str,
    timeout: int = 5,
    *,
    allow_private: bool = True,
    allowed_subnets: tuple[str, ...] = (),
) -> list[dict] | None:
    """Capture the certificate chain presented by an LDAPS server using a non-validating probe."""
    lowered = url.lower()
    if not lowered.startswith("ldaps://"):
        return None
    rest = url[8:]
    host = rest.split(":")[0].split("/")[0]
    port = 636
    if ":" in rest:
        with contextlib.suppress(ValueError):
            port = int(rest.split(":")[1].split("/")[0])
    from cert_watch.routes.settings import _probe_tls_chain
    return _probe_tls_chain(
        host, port, timeout,
        allow_private=allow_private, allowed_subnets=allowed_subnets,
    )


def _capture_starttls_chain(
    url: str,
    timeout: int = 5,
    *,
    allow_private: bool = True,
    allowed_subnets: tuple[str, ...] = (),
) -> list[dict] | None:
    """Capture the certificate chain presented by an LDAP server via StartTLS."""
    from cert_watch.scan import _is_blocked_ip

    lowered = url.lower()
    if not lowered.startswith("ldap://"):
        return None
    rest = url[7:]
    host = rest.split(":")[0].split("/")[0]
    port = 389
    if ":" in rest:
        with contextlib.suppress(ValueError):
            port = int(rest.split(":")[1].split("/")[0])

    # SSRF guard — resolve hostnames to catch DNS-based bypasses
    try:
        ip = ipaddress.ip_address(host)
        if _is_blocked_ip(ip, allow_private=allow_private, allowed_subnets=allowed_subnets):
            return None
    except ValueError:
        from cert_watch.scan_resolver import resolve_and_validate_host

        err, _ = resolve_and_validate_host(
            host, port, allow_private=allow_private, allowed_subnets=allowed_subnets,
        )
        if err:
            return None

    # Try ldap3 StartTLS first
    try:
        import ldap3
    except ImportError:
        return None

    der_chain: list[bytes] = []
    try:
        from cert_watch.scan_conn import _get_chain_der

        srv = ldap3.Server(url, get_info=ldap3.NONE, connect_timeout=timeout)
        conn = ldap3.Connection(srv, auto_bind=False, receive_timeout=timeout)
        conn.open()
        conn.start_tls()
        ssl_sock = conn.socket
        if ssl_sock is not None:
            der_chain = _get_chain_der(ssl_sock)
        conn.unbind()
    except Exception:
        pass

    # Fallback: raw TLS probe on the same port
    if not der_chain:
        from cert_watch.routes.settings import _probe_tls_chain
        return _probe_tls_chain(
            host, port, timeout,
            allow_private=allow_private,
            allowed_subnets=allowed_subnets,
        )

    return _der_chain_to_ca_dicts(der_chain)


def _probe_tls_chain(
    host: str,
    port: int,
    timeout: int = 5,
    *,
    allow_private: bool = True,
    allowed_subnets: tuple[str, ...] = (),
) -> list[dict] | None:
    """Non-validating TLS probe to capture the certificate chain from *host:port*."""
    import socket

    from cert_watch.scan import _is_blocked_ip, _scan_via_openssl

    # SSRF guard — resolve hostnames to catch DNS-based bypasses
    try:
        ip = ipaddress.ip_address(host)
        if _is_blocked_ip(ip, allow_private=allow_private, allowed_subnets=allowed_subnets):
            return None
    except ValueError:
        from cert_watch.scan_resolver import resolve_and_validate_host

        err, _ = resolve_and_validate_host(
            host, port, allow_private=allow_private, allowed_subnets=allowed_subnets,
        )
        if err:
            return None

    der_chain: list[bytes] = []
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with (
            socket.create_connection((host, port), timeout=timeout) as sock,
            ctx.wrap_socket(sock, server_hostname=host) as ssl_sock,
        ):
            from cert_watch.scan_conn import _get_chain_der

            der_chain = _get_chain_der(ssl_sock)
    except Exception:
        pass

    # If we only have the leaf (or nothing), try openssl for the full chain
    if len(der_chain) <= 1:
        try:
            openssl_chain, _ = _scan_via_openssl(
                host, port, timeout,
                allow_private=allow_private, allowed_subnets=allowed_subnets,
            )
            if openssl_chain:
                der_chain = openssl_chain
        except Exception:
            pass

    return _der_chain_to_ca_dicts(der_chain)


def _der_chain_to_ca_dicts(der_chain: list[bytes]) -> list[dict] | None:
    """Convert a list of DER-encoded certificates to CA dicts (leaf excluded)."""
    from cert_watch.certificate_model import Certificate, parse_certificate

    if not der_chain:
        return None

    certs: list[Certificate] = []
    for der in der_chain:
        parsed = parse_certificate(der)
        if isinstance(parsed, Certificate):
            certs.append(parsed)

    if not certs:
        return None

    # Drop the leaf (first cert); keep issuing CAs and root
    ca_certs = certs[1:]
    if not ca_certs:
        return None

    result: list[dict] = []
    for cert in ca_certs:
        pem = (
            x509.load_der_x509_certificate(cert.raw_der)
            .public_bytes(Encoding.PEM)
            .decode("utf-8")
        )
        result.append(
            {
                "subject": cert.subject,
                "issuer": cert.issuer,
                "not_after": cert.not_after.isoformat() if cert.not_after else "",
                "sha256": cert.fingerprint_sha256,
                "pem": pem,
            }
        )
    return result


def _is_cert_verify_error(exc: Exception) -> bool:
    """Return True when *exc* is a TLS certificate verification failure."""
    msg = str(exc).lower()
    return any(
        phrase in msg
        for phrase in (
            "certificate_verify_failed",
            "certificate verify failed",
            "unable to get local issuer certificate",
            "self signed certificate",
            "self-signed certificate",
            "unable to verify leaf signature",
            "certificate chain too long",
            "invalid ca certificate",
        )
    )
