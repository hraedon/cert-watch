"""Settings page routes for GUI-based configuration."""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from cert_watch import __commit__, __version__
from cert_watch.config import Settings
from cert_watch.database import kv_all, kv_set
from cert_watch.middleware import get_auth_context, get_csrf_context

logger = logging.getLogger("cert_watch.routes.settings")

router = APIRouter()

BASE_DIR = Path(__file__).parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def _get_settings(request: Request) -> Settings:
    return request.app.state.settings


def _db_path(request: Request) -> Path:
    return _get_settings(request).db_path


def _require_admin(request: Request) -> RedirectResponse | None:
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
    "alert_digest_only": "ALERT_DIGEST_ONLY",
}

_SENSITIVE_KEYS = frozenset({
    "ldap_bind_password", "ldap_ca_cert",
    "oauth_client_secret",
    "smtp_password",
})


def _env_overrides(keys: dict[str, str], db_path: Path) -> dict[str, bool]:
    """Return {kv_key: True} for keys where the env var is set (takes precedence)."""
    import os
    overrides: dict[str, bool] = {}
    for kv_key, env_name in keys.items():
        env_val = os.environ.get(env_name)
        if env_val is not None and env_val.strip():
            overrides[kv_key] = True
    return overrides


def _effective_config(keys: dict[str, str], db_path: Path) -> dict[str, str]:
    """Merge kv_store values with env var overrides (env wins)."""
    import os

    from cert_watch.config import read_secret

    kv = kv_all(db_path)
    result: dict[str, str] = {}
    for kv_key, env_name in keys.items():
        env_val = os.environ.get(env_name)
        if env_val is not None and env_val.strip():
            result[kv_key] = env_val
        elif kv_key in kv and kv[kv_key]:
            result[kv_key] = kv[kv_key]
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


@router.get("/settings", response_class=HTMLResponse)
def settings_page(
    request: Request,
    tab: str = "auth",
    saved: str | None = None,
    error: str | None = None,
) -> HTMLResponse:
    redirect = _require_admin(request)
    if redirect:
        return redirect
    db = _db_path(request)
    auth_config = _effective_config(_AUTH_KEYS, db)
    smtp_config = _effective_config(_SMTP_KEYS, db)
    alert_config = _effective_config(_ALERT_KEYS, db)
    env_overrides = _env_overrides(_AUTH_KEYS, db)
    ctx = get_csrf_context(request)
    auth_ctx = get_auth_context(request)
    # Mask sensitive fields for display
    display_config = {}
    for k, v in {**auth_config, **smtp_config, **alert_config}.items():
        if k in _SENSITIVE_KEYS and v:
            display_config[k] = "••••••••"
        else:
            display_config[k] = v
    return templates.TemplateResponse(
        request=request,
        name="settings.html",
        context={
            "version": __version__, "commit": __commit__,
            "tab": tab,
            "saved": saved,
            "error": error,
            "auth": display_config,
            "smtp": display_config,
            "alert": display_config,
            "env_overrides": env_overrides,
            **auth_ctx,
            **ctx,
        },
    )


# ---------- Save auth config ----------


@router.post("/settings/auth")
async def save_auth_config(request: Request) -> RedirectResponse:
    redirect = _require_admin(request)
    if redirect:
        return redirect
    from cert_watch.middleware import check_csrf
    csrf_err = await check_csrf(request)
    if csrf_err:
        return RedirectResponse(url=f"/settings?tab=auth&error={csrf_err}", status_code=303)

    db = _db_path(request)
    form = await request.form()

    # Save each field to kv_store
    for kv_key in _AUTH_KEYS:
        val = form.get(kv_key, "").strip()
        kv_set(db, kv_key, val)

    # Rebuild auth provider with merged config
    try:
        _rebuild_settings(request, db)
        s = _get_settings(request)
        auth = s.build_auth_provider()
        request.app.state.auth_provider = auth
        request.app.state.needs_setup = False
        logger.info("settings: auth provider updated to '%s'", s.auth_provider)
    except (ValueError, Exception) as exc:
        logger.warning("settings: auth provider rebuild failed: %s", exc)
        return RedirectResponse(
            url=f"/settings?tab=auth&error={str(exc)[:120].replace(chr(10), ' ')}", status_code=303
        )

    return RedirectResponse(url="/settings?tab=auth&saved=1", status_code=303)


# ---------- Save SMTP config ----------


@router.post("/settings/smtp")
async def save_smtp_config(request: Request) -> RedirectResponse:
    redirect = _require_admin(request)
    if redirect:
        return redirect
    from cert_watch.middleware import check_csrf
    csrf_err = await check_csrf(request)
    if csrf_err:
        return RedirectResponse(url=f"/settings?tab=smtp&error={csrf_err}", status_code=303)

    db = _db_path(request)
    form = await request.form()

    for kv_key in _SMTP_KEYS:
        val = form.get(kv_key, "").strip()
        kv_set(db, kv_key, val)

    # Rebuild settings with new SMTP values
    _rebuild_settings(request, db)
    return RedirectResponse(url="/settings?tab=smtp&saved=1", status_code=303)


# ---------- Save alert config ----------


@router.post("/settings/alerts")
async def save_alert_config(request: Request) -> RedirectResponse:
    redirect = _require_admin(request)
    if redirect:
        return redirect
    from cert_watch.middleware import check_csrf
    csrf_err = await check_csrf(request)
    if csrf_err:
        return RedirectResponse(url=f"/settings?tab=alerts&error={csrf_err}", status_code=303)

    db = _db_path(request)
    form = await request.form()

    for kv_key in _ALERT_KEYS:
        val = form.get(kv_key, "").strip()
        kv_set(db, kv_key, val)

    _rebuild_settings(request, db)
    return RedirectResponse(url="/settings?tab=alerts&saved=1", status_code=303)


def _rebuild_settings(request: Request, db_path: Path) -> None:
    """Rebuild Settings from env + kv_store and update app.state."""
    s = Settings.from_env_with_kv(db_path)
    request.app.state.settings = s


# ---------- Test LDAP connection ----------


@router.post("/settings/test-ldap")
async def test_ldap_connection(request: Request) -> JSONResponse:
    redirect = _require_admin(request)
    if redirect:
        return JSONResponse({"ok": False, "error": "not authenticated"}, status_code=401)
    from cert_watch.middleware import check_csrf
    csrf_err = await check_csrf(request)
    if csrf_err:
        return JSONResponse({"ok": False, "error": csrf_err}, status_code=400)

    form = await request.form()
    server = form.get("ldap_server", "").strip()
    base_dn = form.get("ldap_base_dn", "").strip()
    bind_dn = form.get("ldap_bind_dn", "").strip()
    bind_password = form.get("ldap_bind_password", "").strip()
    start_tls = form.get("ldap_start_tls", "0") == "1"
    ca_cert = form.get("ldap_ca_cert", "").strip()
    connect_timeout = int(form.get("ldap_connect_timeout", "5") or "5")

    if not server or not base_dn:
        return JSONResponse({"ok": False, "error": "LDAP server and base DN are required"})

    try:
        import ssl

        import ldap3

        server_urls = [s.strip() for s in server.split(",") if s.strip()]
        is_ldaps = any(s.lower().startswith("ldaps://") for s in server_urls)

        tls_kwargs: dict = {}
        tmp_path: str | None = None
        if is_ldaps or start_tls:
            tls_kwargs["validate"] = ssl.CERT_REQUIRED
            if ca_cert:
                import contextlib
                import os
                import tempfile
                tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False)  # noqa: SIM115
                tmp.write(ca_cert)
                tmp.close()
                tmp_path = tmp.name
                tls_kwargs["ca_certs_file"] = tmp_path

        try:
            tls = ldap3.Tls(**tls_kwargs) if tls_kwargs else None
            servers = [
                ldap3.Server(url, tls=tls, connect_timeout=connect_timeout)
                for url in server_urls
            ]
            pool = ldap3.ServerPool(servers, ldap3.FIRST)

            conn = ldap3.Connection(
                pool,
                user=bind_dn or None,
                password=bind_password or None,
                auto_bind=True if not start_tls else ldap3.AUTO_BIND_TLS_BEFORE_BIND,
                read_only=True,
            )
            conn.unbind()
        finally:
            if tmp_path:
                with contextlib.suppress(OSError):
                    os.unlink(tmp_path)
        return JSONResponse({"ok": True, "message": f"Connected to {server}"})
    except ImportError:
        return JSONResponse({
            "ok": False,
            "error": "ldap3 not installed (pip install cert-watch[auth-ldap])",
        })
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)})


# ---------- Test SMTP connection ----------


@router.post("/settings/test-smtp")
async def test_smtp_connection(request: Request) -> JSONResponse:
    redirect = _require_admin(request)
    if redirect:
        return JSONResponse({"ok": False, "error": "not authenticated"}, status_code=401)
    from cert_watch.middleware import check_csrf
    csrf_err = await check_csrf(request)
    if csrf_err:
        return JSONResponse({"ok": False, "error": csrf_err}, status_code=400)

    form = await request.form()
    host = form.get("smtp_host", "").strip()
    port = int(form.get("smtp_port", "587") or "587")
    user = form.get("smtp_user", "").strip()
    password = form.get("smtp_password", "").strip()
    from_addr = form.get("alert_from", "").strip()
    recipients = form.get("alert_recipients", "").strip()

    if not host:
        return JSONResponse({"ok": False, "error": "SMTP host is required"})
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
            s = smtplib.SMTP_SSL(host, port, timeout=10)
        else:
            s = smtplib.SMTP(host, port, timeout=10)
        with s:
            if port != 465:
                try:
                    s.starttls()
                except smtplib.SMTPNotSupportedError:
                    return JSONResponse({"ok": False, "error": "STARTTLS not supported by server"})
            if user:
                s.login(user, password)
            s.send_message(msg)
        return JSONResponse({"ok": True, "message": f"Test email sent to {recipients}"})
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)})
