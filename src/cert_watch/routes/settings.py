"""Settings page routes for GUI-based configuration."""

from __future__ import annotations

import contextlib
import ipaddress
import json
import logging
import os
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from cert_watch import __commit__, __version__
from cert_watch.config import SENSITIVE_SETTING_KEYS, Settings
from cert_watch.database import kv_all, kv_set, kv_set_secret
from cert_watch.middleware import get_auth_context, get_csrf_context
from cert_watch.routes._deps import _db_path, _get_settings, get_templates

logger = logging.getLogger("cert_watch.routes.settings")

router = APIRouter()

templates = get_templates()


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


def _require_admin(request: Request) -> RedirectResponse | JSONResponse | None:
    """Return redirect to /login if not authenticated, 403 if not admin, or None if OK."""
    from cert_watch.auth import LocalAdminProvider, NoAuthProvider, _CompositeProvider
    auth = getattr(request.app.state, "auth_provider", None)
    if auth is None or isinstance(auth, NoAuthProvider):
        return None  # No auth configured — allow access
    user = request.scope.get("auth_user")
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    # Local admin / break-glass always has admin access
    if isinstance(auth, LocalAdminProvider):
        return None
    if isinstance(auth, _CompositeProvider) and auth._local and user == auth._local.username:
        return None
    # Check CERT_WATCH_ADMINS list
    settings = getattr(request.app.state, "settings", None)
    if settings and settings.admin_users and user not in settings.admin_users:
        return JSONResponse(
            content={"error": "forbidden: admin access required"},
            status_code=403,
        )
    return None


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


def _env_overrides(keys: dict[str, str], db_path: Path) -> dict[str, bool]:
    """Return {kv_key: True} for keys where the env var is set (takes precedence)."""
    import os
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
    import os

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


# ---------- Settings page ----------


@router.get("/settings", response_class=HTMLResponse, response_model=None)
def settings_page(
    request: Request,
    tab: str = "auth",
    saved: str | None = None,
    error: str | None = None,
    password_changed: str | None = None,
) -> HTMLResponse | RedirectResponse:
    redirect_resp = _require_admin(request)
    if redirect_resp:
        assert isinstance(redirect_resp, RedirectResponse)
        return redirect_resp
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
    ctx = get_csrf_context(request)
    auth_ctx = get_auth_context(request)
    # Mask sensitive fields for display
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

    # Plan 040: LDAP role mapping from kv_store
    ldap_role_map_raw = kv_get(db, "ldap_role_map") or "{}"
    try:
        ldap_role_map = json.loads(ldap_role_map_raw)
    except (json.JSONDecodeError, TypeError):
        ldap_role_map = {}

    return templates.TemplateResponse(
        request=request,
        name="settings.html",
        context={
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
            "active_page": "settings",
            **auth_ctx,
            **ctx,
        },
    )


# ---------- API keys (Plan 039 / BC-104) ----------


def _render_api_keys(
    request: Request,
    *,
    new_token: str | None = None,
    new_name: str | None = None,
    error: str | None = None,
) -> HTMLResponse:
    """Render the API-keys management page. ``new_token`` is shown exactly once."""
    from cert_watch.database import SqliteApiKeyRepository

    repo = SqliteApiKeyRepository(_db_path(request))
    keys = repo.list_keys()
    return templates.TemplateResponse(
        request=request,
        name="api_keys.html",
        context={
            "version": __version__, "commit": __commit__,
            "active_page": "settings",
            "api_keys": keys,
            "new_token": new_token,
            "new_name": new_name,
            "error": error,
            **get_auth_context(request),
            **get_csrf_context(request),
        },
    )


@router.get("/settings/api-keys", response_class=HTMLResponse, response_model=None)
def api_keys_page(request: Request) -> HTMLResponse | RedirectResponse | JSONResponse:
    redirect_resp = _require_admin(request)
    if redirect_resp:
        return redirect_resp
    return _render_api_keys(request)


@router.post("/settings/api-keys", response_class=HTMLResponse, response_model=None)
async def api_keys_create(
    request: Request,
) -> HTMLResponse | RedirectResponse | JSONResponse:
    redirect_resp = _require_admin(request)
    if redirect_resp:
        return redirect_resp
    from cert_watch.audit import record_audit, resolve_actor, resolve_source_ip
    from cert_watch.database import SqliteApiKeyRepository
    from cert_watch.database.api_keys import VALID_SCOPES
    from cert_watch.middleware import check_csrf

    csrf_err = await check_csrf(request)
    if csrf_err:
        return _render_api_keys(request, error=csrf_err)

    form = await request.form()
    name = str(form.get("name") or "").strip()
    scope = str(form.get("scope") or "read")
    if not name:
        return _render_api_keys(request, error="A name is required.")
    if scope not in VALID_SCOPES:
        return _render_api_keys(request, error="Invalid scope.")

    repo = SqliteApiKeyRepository(_db_path(request))
    entry, raw_token = repo.create_key(name, scope)
    record_audit(
        _db_path(request),
        actor=resolve_actor(request),
        action="api_key.create",
        target_type="api_key",
        target_id=entry.id,
        detail={"name": name, "scope": scope},
        source_ip=resolve_source_ip(request),
    )
    return _render_api_keys(request, new_token=raw_token, new_name=name)


@router.post("/settings/api-keys/{key_id}/revoke", response_model=None)
async def api_keys_revoke(
    key_id: str, request: Request
) -> RedirectResponse | HTMLResponse | JSONResponse:
    redirect_resp = _require_admin(request)
    if redirect_resp:
        return redirect_resp
    from cert_watch.audit import record_audit, resolve_actor, resolve_source_ip
    from cert_watch.database import SqliteApiKeyRepository
    from cert_watch.middleware import check_csrf

    csrf_err = await check_csrf(request)
    if csrf_err:
        return _render_api_keys(request, error=csrf_err)
    SqliteApiKeyRepository(_db_path(request)).revoke_key(key_id)
    record_audit(
        _db_path(request),
        actor=resolve_actor(request),
        action="api_key.revoke",
        target_type="api_key",
        target_id=key_id,
        source_ip=resolve_source_ip(request),
    )
    return RedirectResponse(url="/settings/api-keys", status_code=303)


# ---------- Save auth config ----------


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
    redirect_resp = _require_admin(request)
    if redirect_resp:
        assert isinstance(redirect_resp, RedirectResponse)
        return redirect_resp

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


@router.post("/settings/auth")
async def save_auth_config(request: Request) -> RedirectResponse:
    resp = await _save_config_section(request, _AUTH_KEYS, "auth", encrypt=True, rebuild=True)
    if resp.status_code == 303 and ("saved=1" in str(resp.headers.get("location", ""))):
        # After saving, rebuild the auth provider so the new config is live immediately
        try:
            s = _get_settings(request)
            auth = s.build_auth_provider()
            request.app.state.auth_provider = auth
            request.app.state.needs_setup = False
            logger.info("settings: auth provider updated to '%s'", s.auth_provider)
        except (ValueError, Exception) as exc:
            logger.warning("settings: auth provider rebuild failed: %s", exc)
            return RedirectResponse(
                url=f"/settings?tab=auth&error={str(exc)[:120].replace(chr(10), ' ')}",
                status_code=303,
            )
    return resp


# ---------- Save SMTP config ----------


@router.post("/settings/smtp")
async def save_smtp_config(request: Request) -> RedirectResponse:
    resp = await _save_config_section(request, _SMTP_KEYS, "smtp", encrypt=True, rebuild=True)
    return resp


@router.post("/settings/alerts")
async def save_alert_config(request: Request) -> RedirectResponse:
    resp = await _save_config_section(request, _ALERT_KEYS, "alerts", encrypt=False, rebuild=True)
    return resp


# ---------- Change local admin password (BC-102) ----------


@router.post("/settings/change-password")
async def change_local_admin_password(request: Request) -> RedirectResponse:
    redirect_resp = _require_admin(request)
    if redirect_resp:
        assert isinstance(redirect_resp, RedirectResponse)
        return redirect_resp
    from cert_watch.middleware import check_csrf
    csrf_err = await check_csrf(request)
    if csrf_err:
        return RedirectResponse(url=f"/settings?tab=auth&error={csrf_err}", status_code=303)

    import os

    from cert_watch.auth import _scrypt_hash, verify_scrypt_hash
    from cert_watch.database import kv_get, kv_set
    from cert_watch.database.queries import bump_session_version

    db = _db_path(request)
    s = _get_settings(request)
    form = await request.form()

    _cur = form.get("current_password") or ""
    _new = form.get("new_password") or ""
    _conf = form.get("confirm_password") or ""
    current_password = _cur.strip() if isinstance(_cur, str) else ""
    new_password = _new.strip() if isinstance(_new, str) else ""
    confirm_password = _conf.strip() if isinstance(_conf, str) else ""

    if not current_password or not new_password:
        return RedirectResponse(
            url="/settings?tab=auth&error=current+and+new+password+are+required", status_code=303
        )
    if len(new_password) < 8:
        return RedirectResponse(
            url="/settings?tab=auth&error=new+password+must+be+at+least+8+characters",
            status_code=303,
        )
    if new_password != confirm_password:
        return RedirectResponse(
            url="/settings?tab=auth&error=new+passwords+do+not+match", status_code=303
        )

    # Check if env var overrides the hash (env always wins)
    env_hash = os.environ.get("CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH", "").strip()
    if env_hash:
        return RedirectResponse(
            url="/settings?tab=auth&error=cannot+rotate+via+UI:+CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH+is+set+(env+always+wins)",
            status_code=303,
        )

    stored_hash = kv_get(db, "local_admin_password_hash") or ""
    if not stored_hash:
        return RedirectResponse(
            url="/settings?tab=auth&error=no+local+admin+password+hash+found", status_code=303
        )

    if not verify_scrypt_hash(current_password, stored_hash):
        return RedirectResponse(
            url="/settings?tab=auth&error=current+password+is+incorrect", status_code=303
        )

    # Persist new hash + clear autogenerated flag
    kv_set(db, "local_admin_password_hash", _scrypt_hash(new_password))
    kv_set(db, "local_admin_autogenerated", "0")

    # Invalidate all existing sessions for this user
    username = kv_get(db, "local_admin_user") or "admin"
    bump_session_version(db, username)

    # Delete the one-time password file if it still exists
    try:
        pw_file = s.data_dir / "initial-admin-password"
        if pw_file.exists():
            pw_file.unlink()
            logger.info("Deleted initial-admin-password file after rotation")
    except OSError:
        logger.debug("Could not delete initial-admin-password file", exc_info=True)

    # Rebuild auth provider with new hash
    _rebuild_settings(request, db)
    auth = _get_settings(request).build_auth_provider()
    request.app.state.auth_provider = auth

    logger.info("Local admin password rotated via UI")
    return RedirectResponse(url="/settings?tab=auth&password_changed=1", status_code=303)


def _rebuild_settings(request: Request, db_path: Path) -> None:
    """Rebuild Settings from env + kv_store and update app.state."""
    enc_key = _get_encryption_key(request)
    s = Settings.from_env_with_kv(db_path, encryption_key=enc_key)
    request.app.state.settings = s


# ---------- TOFU CA capture for LDAPS test ----------


def _capture_ldaps_chain(
    url: str,
    timeout: int = 5,
    *,
    allow_private: bool = True,
    allowed_subnets: tuple[str, ...] = (),
) -> list[dict] | None:
    """Capture the certificate chain presented by an LDAPS server using a non-validating probe.

    Returns a list of dicts (one per CA cert, leaf excluded) with:
    - subject, issuer, not_after, sha256, pem

    Returns None when the URL is not LDAPS, the host is blocked by the SSRF
    guard, or no chain can be read.
    """
    import socket

    from cert_watch.certificate_model import Certificate, parse_certificate
    from cert_watch.scan import _is_blocked_ip, _scan_via_openssl

    lowered = url.lower()
    if not lowered.startswith("ldaps://"):
        return None
    rest = url[8:]
    host = rest.split(":")[0].split("/")[0]
    port = 636
    if ":" in rest:
        with contextlib.suppress(ValueError):
            port = int(rest.split(":")[1].split("/")[0])
    return _probe_tls_chain(host, port, timeout, allow_private=allow_private, allowed_subnets=allowed_subnets)


def _capture_starttls_chain(
    url: str,
    timeout: int = 5,
    *,
    allow_private: bool = True,
    allowed_subnets: tuple[str, ...] = (),
) -> list[dict] | None:
    """Capture the certificate chain presented by an LDAP server via StartTLS.

    Uses ldap3 to negotiate StartTLS, then reads the peer certificate from the
    wrapped SSL socket.  Falls back to a raw TLS probe on the same host/port
    when ldap3 is unavailable or StartTLS negotiation fails.

    Returns a list of dicts (one per CA cert, leaf excluded) with:
    - subject, issuer, not_after, sha256, pem

    Returns None when the URL is not ldap://, the host is blocked by the SSRF
    guard, or no chain can be read.
    """
    from cert_watch.certificate_model import Certificate, parse_certificate
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

    # SSRF guard
    try:
        ip = ipaddress.ip_address(host)
        if _is_blocked_ip(ip, allow_private=allow_private, allowed_subnets=allowed_subnets):
            return None
    except ValueError:
        pass

    # Try ldap3 StartTLS first
    try:
        import ldap3
    except ImportError:
        return None

    der_chain: list[bytes] = []
    try:
        srv = ldap3.Server(url, get_info=ldap3.NONE, connect_timeout=timeout)
        conn = ldap3.Connection(srv, auto_bind=False, receive_timeout=timeout)
        conn.open()
        conn.start_tls()
        ssl_sock = conn.socket
        if ssl_sock is not None:
            # Try native chain API (CPython 3.13+)
            for method in ("get_unverified_chain", "get_verified_chain"):
                getter = getattr(ssl_sock, method, None)
                if getter:
                    try:
                        items = getter()
                        der_chain = []
                        for c in items:
                            try:
                                der = c.public_bytes(Encoding.DER)
                            except AttributeError:
                                der = bytes(c)
                            der_chain.append(der)
                        break
                    except Exception:
                        continue
            else:
                leaf = ssl_sock.getpeercert(binary_form=True)
                if leaf:
                    der_chain.append(leaf)
        conn.unbind()
    except Exception:
        pass

    # Fallback: raw TLS probe on the same port (some servers present the same
    # cert on StartTLS and LDAPS, but not all — this is best-effort).
    if not der_chain:
        return _probe_tls_chain(host, port, timeout, allow_private=allow_private, allowed_subnets=allowed_subnets)

    return _der_chain_to_ca_dicts(der_chain)


def _probe_tls_chain(
    host: str,
    port: int,
    timeout: int = 5,
    *,
    allow_private: bool = True,
    allowed_subnets: tuple[str, ...] = (),
) -> list[dict] | None:
    """Non-validating TLS probe to capture the certificate chain from *host:port*.

    Returns a list of dicts (one per CA cert, leaf excluded) or None.
    """
    import socket

    from cert_watch.certificate_model import Certificate, parse_certificate
    from cert_watch.scan import _is_blocked_ip, _scan_via_openssl

    # SSRF guard
    try:
        ip = ipaddress.ip_address(host)
        if _is_blocked_ip(ip, allow_private=allow_private, allowed_subnets=allowed_subnets):
            return None
    except ValueError:
        pass

    der_chain: list[bytes] = []
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with (
            socket.create_connection((host, port), timeout=timeout) as sock,
            ctx.wrap_socket(sock, server_hostname=host) as ssl_sock,
        ):
            # Try native chain API (CPython 3.13+)
            for method in ("get_unverified_chain", "get_verified_chain"):
                getter = getattr(ssl_sock, method, None)
                if getter:
                    try:
                        items = getter()
                        der_chain = []
                        for c in items:
                            try:
                                der = c.public_bytes(Encoding.DER)
                            except AttributeError:
                                der = bytes(c)
                            der_chain.append(der)
                        break
                    except Exception:
                        continue
            else:
                leaf = ssl_sock.getpeercert(binary_form=True)
                if leaf:
                    der_chain.append(leaf)
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


# ---------- Test LDAP connection ----------


@router.post("/settings/test-ldap")
async def test_ldap_connection(request: Request) -> JSONResponse:
    _redirect = _require_admin(request)
    if _redirect:
        return JSONResponse({"ok": False, "error": "not authenticated"}, status_code=401)
    from cert_watch.middleware import check_csrf
    csrf_err = await check_csrf(request)
    if csrf_err:
        return JSONResponse({"ok": False, "error": csrf_err}, status_code=400)

    form = await request.form()
    _server = form.get("ldap_server", "")
    _base = form.get("ldap_base_dn", "")
    _bind = form.get("ldap_bind_dn", "")
    _pw = form.get("ldap_bind_password", "")
    _ca = form.get("ldap_ca_cert", "")
    _timeout = form.get("ldap_connect_timeout", "5")
    server = _server.strip() if isinstance(_server, str) else ""
    base_dn = _base.strip() if isinstance(_base, str) else ""
    bind_dn = _bind.strip() if isinstance(_bind, str) else ""
    bind_password = _pw.strip() if isinstance(_pw, str) else ""
    start_tls = form.get("ldap_start_tls", "0") == "1"
    ca_cert = _ca.strip() if isinstance(_ca, str) else ""
    # Guard the parse: a blank field (the input has no fallback value) or a
    # non-numeric value must surface as a clean JSON error, never an uncaught
    # ValueError -> 500 "Internal Server Error" that the frontend then fails to
    # parse as JSON. Mirrors the guarded parse in config.from_kv.
    _timeout_str = _timeout.strip() if isinstance(_timeout, str) else ""
    try:
        connect_timeout = int(_timeout_str) if _timeout_str else 5
    except ValueError:
        return JSONResponse(
            {"ok": False, "error": "Connect timeout must be a whole number of seconds"}
        )

    if not server or not base_dn:
        return JSONResponse({"ok": False, "error": "LDAP server and base DN are required"})

    # SSRF guard: block connections to loopback/link-local/metadata addresses.
    from cert_watch.scan import _is_blocked_ip

    for s in [s.strip() for s in server.split(",") if s.strip()]:
        host_part = s.split("://", 1)[-1].split(":")[0].split("/")[0]
        try:
            import ipaddress as _ip
            ip = _ip.ip_address(host_part)
            if _is_blocked_ip(ip):
                return JSONResponse(
                    {"ok": False, "error": f"LDAP server IP blocked: {ip}"},
                )
        except ValueError:
            pass  # hostname — DNS-resolved at connect time

    try:
        import os
        import tempfile

        import ldap3

        server_urls = [s.strip() for s in server.split(",") if s.strip()]

        # Pin the supplied CA (if any) to a single temp file shared by every probe.
        tmp_path: str | None = None
        if ca_cert:
            tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False)  # noqa: SIM115
            tmp.write(ca_cert)
            tmp.close()
            tmp_path = tmp.name

        def _build_tls(use_tls: bool) -> ldap3.Tls | None:
            if not use_tls:
                return None
            kwargs: dict = {"validate": ssl.CERT_REQUIRED}
            if tmp_path:
                kwargs["ca_certs_file"] = tmp_path
            return ldap3.Tls(**kwargs)

        # Probe each server URL on its own — a ServerPool with FIRST short-circuits
        # on the first reachable host, so a bad URL later in the list was never
        # contacted and the test passed despite it. Bind to each one individually
        # so every source is actually verified.
        any_tls = False
        try:
            for url in server_urls:
                srv_is_ldaps = url.lower().startswith("ldaps://")
                use_tls = srv_is_ldaps or start_tls
                tls = _build_tls(use_tls)
                try:
                    srv = ldap3.Server(url, tls=tls, connect_timeout=connect_timeout)
                    conn = ldap3.Connection(
                        srv,
                        user=bind_dn or None,
                        password=bind_password or None,
                        auto_bind=(
                            ldap3.AUTO_BIND_TLS_BEFORE_BIND
                            if (start_tls and not srv_is_ldaps)
                            else True
                        ),
                        read_only=True,
                    )
                except Exception as exc:  # noqa: BLE001 — report which URL failed
                    if use_tls and _is_cert_verify_error(exc):
                        settings = getattr(request.app.state, "settings", None)
                        _allow_private = settings.allow_private if settings else True
                        _allowed_subnets = settings.allowed_subnets if settings else ()
                        tofu_chain = _capture_ldaps_chain(
                            url,
                            timeout=connect_timeout,
                            allow_private=_allow_private,
                            allowed_subnets=_allowed_subnets,
                        )
                        if not tofu_chain and start_tls and not srv_is_ldaps:
                            tofu_chain = _capture_starttls_chain(
                                url,
                                timeout=connect_timeout,
                                allow_private=_allow_private,
                                allowed_subnets=_allowed_subnets,
                            )
                        if tofu_chain:
                            return JSONResponse({
                                "ok": False,
                                "error": f"{url}: {exc}",
                                "tofu": {
                                    "chain": [
                                        {
                                            "subject": c["subject"],
                                            "issuer": c["issuer"],
                                            "not_after": c["not_after"],
                                            "sha256": c["sha256"],
                                        }
                                        for c in tofu_chain
                                    ],
                                    "pem": "".join(c["pem"] for c in tofu_chain),
                                },
                            })
                    return JSONResponse({"ok": False, "error": f"{url}: {exc}"})
                tls_active = srv_is_ldaps or bool(getattr(conn, "tls_started", False))
                conn.unbind()
                if use_tls and not tls_active:
                    return JSONResponse({
                        "ok": False,
                        "error": f"{url}: TLS was requested but not established",
                    })
                if use_tls:
                    any_tls = True
        finally:
            if tmp_path:
                with contextlib.suppress(OSError):
                    os.unlink(tmp_path)

        n = len(server_urls)
        msg = f"All {n} server{'' if n == 1 else 's'} reachable; bind succeeded"
        if any_tls:
            msg += "; TLS validated against " + (
                "the pinned CA certificate"
                if ca_cert
                else "the system trust store (no CA certificate pinned)"
            )
        elif start_tls:
            msg += " (StartTLS requested but no server negotiated TLS)"
        return JSONResponse({"ok": True, "message": msg})
    except ImportError:
        return JSONResponse({
            "ok": False,
            "error": "ldap3 not installed (pip install cert-watch[auth-ldap])",
        })
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)})


# ---------- Pin LDAP CA (TOFU trust) ----------


@router.post("/settings/pin-ldap-ca")
async def pin_ldap_ca(request: Request) -> JSONResponse:
    _redirect = _require_admin(request)
    if _redirect:
        return JSONResponse({"ok": False, "error": "not authenticated"}, status_code=401)
    from cert_watch.middleware import check_csrf
    csrf_err = await check_csrf(request)
    if csrf_err:
        return JSONResponse({"ok": False, "error": csrf_err}, status_code=400)

    form = await request.form()
    _pem = form.get("ldap_ca_cert", "")
    pem = _pem.strip() if isinstance(_pem, str) else ""
    if not pem:
        return JSONResponse({"ok": False, "error": "No CA certificate provided"})

    db = _db_path(request)
    enc_key = _get_encryption_key(request)

    if enc_key:
        kv_set_secret(db, "ldap_ca_cert", pem, enc_key)
    else:
        kv_set(db, "ldap_ca_cert", pem)

    from cert_watch.audit import record_audit, resolve_actor, resolve_source_ip
    from cert_watch.certificate_model import extract_chain_from_pem

    chain = extract_chain_from_pem(pem)
    fps = [c.fingerprint_sha256 for c in chain]
    subjects = [c.subject for c in chain]
    record_audit(
        db,
        actor=resolve_actor(request),
        action="ca_pinned",
        target_type="ldap_ca",
        target_id=fps[0] if fps else "unknown",
        detail={
            "subjects": subjects,
            "sha256s": fps,
            "count": len(chain),
            "source": "tofu",
        },
        source_ip=resolve_source_ip(request),
    )

    return JSONResponse({"ok": True, "message": "CA certificate pinned successfully"})


# ---------- Test SMTP connection ----------


@router.post("/settings/test-smtp")
async def test_smtp_connection(request: Request) -> JSONResponse:
    _redirect = _require_admin(request)
    if _redirect:
        return JSONResponse({"ok": False, "error": "not authenticated"}, status_code=401)
    from cert_watch.middleware import check_csrf
    csrf_err = await check_csrf(request)
    if csrf_err:
        return JSONResponse({"ok": False, "error": csrf_err}, status_code=400)

    form = await request.form()
    _host = form.get("smtp_host", "")
    _port = form.get("smtp_port", "587")
    _user = form.get("smtp_user", "")
    _pw = form.get("smtp_password", "")
    _from = form.get("alert_from", "")
    _recip = form.get("alert_recipients", "")
    host = _host.strip() if isinstance(_host, str) else ""
    # Guard the parse (see test_ldap_connection): a blank or non-numeric port
    # must return a JSON error, not raise -> 500.
    _port_str = _port.strip() if isinstance(_port, str) else ""
    try:
        port = int(_port_str) if _port_str else 587
    except ValueError:
        return JSONResponse({"ok": False, "error": "SMTP port must be a whole number"})
    user = _user.strip() if isinstance(_user, str) else ""
    password = _pw.strip() if isinstance(_pw, str) else ""
    from_addr = _from.strip() if isinstance(_from, str) else ""
    recipients = _recip.strip() if isinstance(_recip, str) else ""

    if not host:
        return JSONResponse({"ok": False, "error": "SMTP host is required"})

    # SSRF guard: block connections to loopback/link-local/metadata addresses.
    from cert_watch.scan import _is_blocked_ip

    try:
        import ipaddress as _ip
        ip = _ip.ip_address(host)
        if _is_blocked_ip(ip):
            return JSONResponse(
                {"ok": False, "error": f"SMTP host IP blocked: {ip}"},
            )
    except ValueError:
        pass  # hostname — DNS-resolved at connect time

    if not from_addr or not recipients:
        return JSONResponse({
            "ok": False,
            "error": "From address and recipients are required for test",
        })

    import smtplib
    from email.message import EmailMessage

    msg = EmailMessage()
    msg["Subject"] = "[cert-watch] SMTP test"
    msg["From"] = from_addr
    msg["To"] = recipients
    msg.set_content(
        "This is a test email from cert-watch. "
        "SMTP configuration is working correctly."
    )

    try:
        if port == 465:
            s: smtplib.SMTP_SSL | smtplib.SMTP = smtplib.SMTP_SSL(host, port, timeout=10)
        else:
            s = smtplib.SMTP(host, port, timeout=10)
        from cert_watch.alerts import negotiate_starttls
        with s:
            if not negotiate_starttls(s, port, bool(user)):
                return JSONResponse({
                    "ok": False,
                    "error": "STARTTLS not supported by server; refusing to send "
                    "credentials in cleartext. Use port 465, clear the username/"
                    "password, or use a server that supports STARTTLS.",
                })
            if user:
                s.login(user, password)
            s.send_message(msg)
        return JSONResponse({"ok": True, "message": f"Test email sent to {recipients}"})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)})


# ---------- Role management (Plan 040) ----------


@router.get("/settings/roles", response_class=HTMLResponse, response_model=None)
def roles_page(request: Request) -> HTMLResponse | RedirectResponse | JSONResponse:
    redirect_resp = _require_admin(request)
    if redirect_resp:
        return redirect_resp
    from cert_watch.database import SqliteRoleRepository

    db = _db_path(request)
    roles = SqliteRoleRepository(db).list_all()
    return templates.TemplateResponse(
        request=request,
        name="settings.html",
        context={
            "version": __version__, "commit": __commit__,
            "tab": "roles",
            "roles": roles,
            "auth": {}, "smtp": {}, "alert": {},
            "env_overrides": {},
            "active_page": "settings",
            **_get_auth_ctx(request),
            **get_csrf_context(request),
        },
    )


@router.post("/settings/roles")
async def create_role(request: Request) -> RedirectResponse:
    redirect_resp = _require_admin(request)
    if redirect_resp:
        return redirect_resp
    from cert_watch.middleware import check_csrf
    csrf_err = await check_csrf(request)
    if csrf_err:
        return RedirectResponse(url=f"/settings?tab=roles&error={csrf_err}", status_code=303)

    from cert_watch.database import Role, SqliteRoleRepository

    form = await request.form()
    name = str(form.get("name") or "").strip()
    email = str(form.get("email") or "").strip()
    description = str(form.get("description") or "").strip()
    if not name:
        return RedirectResponse(url="/settings?tab=roles&error=role+name+required", status_code=303)

    role = Role(name=name, email=email, description=description)
    SqliteRoleRepository(_db_path(request)).add(role)
    return RedirectResponse(url="/settings?tab=roles&saved=1", status_code=303)


@router.post("/settings/roles/{role_id}/delete")
async def delete_role(role_id: str, request: Request) -> RedirectResponse:
    redirect_resp = _require_admin(request)
    if redirect_resp:
        return redirect_resp
    from cert_watch.middleware import check_csrf
    csrf_err = await check_csrf(request)
    if csrf_err:
        return RedirectResponse(url=f"/settings?tab=roles&error={csrf_err}", status_code=303)

    from cert_watch.database import SqliteRoleRepository

    SqliteRoleRepository(_db_path(request)).delete(role_id)
    return RedirectResponse(url="/settings?tab=roles&saved=1", status_code=303)


# ---------- User management (Plan 040) ----------


@router.get("/settings/users", response_class=HTMLResponse, response_model=None)
def users_page(request: Request) -> HTMLResponse | RedirectResponse | JSONResponse:
    redirect_resp = _require_admin(request)
    if redirect_resp:
        return redirect_resp
    from cert_watch.database import SqliteRoleRepository, SqliteUserRepository

    db = _db_path(request)
    users = SqliteUserRepository(db).list_all()
    roles = SqliteRoleRepository(db).list_all()
    return templates.TemplateResponse(
        request=request,
        name="settings.html",
        context={
            "version": __version__, "commit": __commit__,
            "tab": "users",
            "users": users,
            "roles": roles,
            "auth": {}, "smtp": {}, "alert": {},
            "env_overrides": {},
            "active_page": "settings",
            **_get_auth_ctx(request),
            **get_csrf_context(request),
        },
    )


@router.post("/settings/users")
async def create_user(request: Request) -> RedirectResponse:
    redirect_resp = _require_admin(request)
    if redirect_resp:
        return redirect_resp
    from cert_watch.middleware import check_csrf
    csrf_err = await check_csrf(request)
    if csrf_err:
        return RedirectResponse(url=f"/settings?tab=users&error={csrf_err}", status_code=303)

    from cert_watch.auth import _scrypt_hash
    from cert_watch.database import SqliteUserRepository, User

    form = await request.form()
    username = str(form.get("username") or "").strip()
    email = str(form.get("email") or "").strip()
    password = str(form.get("password") or "").strip()
    role_id = str(form.get("role_id") or "").strip()
    if not username or not password:
        return RedirectResponse(
            url="/settings?tab=users&error=username+and+password+required", status_code=303
        )
    if len(password) < 8:
        return RedirectResponse(
            url="/settings?tab=users&error=password+must+be+at+least+8+characters", status_code=303
        )

    user = User(
        username=username,
        email=email,
        password_hash=_scrypt_hash(password),
        role_id=role_id,
    )
    SqliteUserRepository(_db_path(request)).add(user)
    return RedirectResponse(url="/settings?tab=users&saved=1", status_code=303)


@router.post("/settings/users/{user_id}/delete")
async def delete_user(user_id: str, request: Request) -> RedirectResponse:
    redirect_resp = _require_admin(request)
    if redirect_resp:
        return redirect_resp
    from cert_watch.middleware import check_csrf
    csrf_err = await check_csrf(request)
    if csrf_err:
        return RedirectResponse(url=f"/settings?tab=users&error={csrf_err}", status_code=303)

    from cert_watch.database import SqliteUserRepository

    SqliteUserRepository(_db_path(request)).delete(user_id)
    return RedirectResponse(url="/settings?tab=users&saved=1", status_code=303)


# ---------- LDAP role mapping (Plan 040) ----------


@router.post("/settings/ldap-role-map")
async def save_ldap_role_map(request: Request) -> RedirectResponse:
    redirect_resp = _require_admin(request)
    if redirect_resp:
        return redirect_resp
    from cert_watch.middleware import check_csrf
    csrf_err = await check_csrf(request)
    if csrf_err:
        return RedirectResponse(url=f"/settings?tab=auth&error={csrf_err}", status_code=303)

    form = await request.form()
    from cert_watch.database import SqliteRoleRepository, kv_set

    role_repo = SqliteRoleRepository(_db_path(request))
    map_data = {}
    for key in form:
        if key.startswith("role_map_"):
            role_id = key[len("role_map_"):]
            groups = str(form.get(key) or "").strip()
            if groups:
                role = role_repo.get(role_id)
                if role:
                    map_data[role.name] = {
                        "groups": [g.strip() for g in groups.split(",") if g.strip()]
                    }
    kv_set(_db_path(request), "ldap_role_map", json.dumps(map_data))
    return RedirectResponse(url="/settings?tab=auth&saved=1", status_code=303)


def _get_auth_ctx(request: Request) -> dict:
    from cert_watch.middleware import get_auth_context
    return get_auth_context(request)
