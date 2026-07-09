"""SMTP configuration and test routes."""

from __future__ import annotations

import asyncio
import smtplib
from email.message import EmailMessage

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse

from cert_watch.alerts import negotiate_starttls
from cert_watch.middleware import require_admin_write
from cert_watch.routes.settings.config import _SMTP_KEYS
from cert_watch.routes.settings.core import _sanitize_test_error, _save_config_section

router = APIRouter()


def _send_smtp_test(
    host: str,
    port: int,
    user: str,
    password: str,
    msg: EmailMessage,
) -> str | None:
    """Send the probe message synchronously, returning a policy error if any."""
    if port == 465:
        smtp: smtplib.SMTP_SSL | smtplib.SMTP = smtplib.SMTP_SSL(host, port, timeout=10)
    else:
        smtp = smtplib.SMTP(host, port, timeout=10)
    with smtp:
        if not negotiate_starttls(smtp, port, bool(user)):
            return (
                "STARTTLS not supported by server; refusing to send "
                "credentials in cleartext. Use port 465, clear the username/"
                "password, or use a server that supports STARTTLS."
            )
        if user:
            smtp.login(user, password)
        smtp.send_message(msg)
    return None


@router.post("/settings/smtp")
async def save_smtp_config(request: Request) -> RedirectResponse:
    return await _save_config_section(request, _SMTP_KEYS, "smtp", encrypt=True, rebuild=True)


@router.post("/settings/test-smtp")
async def test_smtp_connection(
    request: Request,
    _auth: str = Depends(require_admin_write),
) -> JSONResponse:
    import logging

    from cert_watch.http_client import validate_smtp_host
    from cert_watch.routes._deps import _get_settings

    logger = logging.getLogger("cert_watch.routes.settings")

    form = await request.form()
    _host = form.get("smtp_host", "")
    _port = form.get("smtp_port", "587")
    _user = form.get("smtp_user", "")
    _pw = form.get("smtp_password", "")
    _from = form.get("alert_from", "")
    _recip = form.get("alert_recipients", "")
    host = _host.strip() if isinstance(_host, str) else ""
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
    # Uses the actual CERT_WATCH_ALLOW_PRIVATE_IPS / ALLOWED_SUBNETS settings so
    # the test path matches the real alert-delivery path (BC-116 SMTP parity).
    settings = _get_settings(request)
    ssrf_err = await asyncio.to_thread(
        validate_smtp_host,
        host,
        allow_private=settings.allow_private,
        allowed_subnets=settings.allowed_subnets,
    )
    if ssrf_err:
        return JSONResponse({"ok": False, "error": f"SMTP host blocked: {ssrf_err}"})

    if not from_addr or not recipients:
        return JSONResponse({
            "ok": False,
            "error": "From address and recipients are required for test",
        })

    msg = EmailMessage()
    msg["Subject"] = "[cert-watch] SMTP test"
    msg["From"] = from_addr
    msg["To"] = recipients
    msg.set_content(
        "This is a test email from cert-watch. "
        "SMTP configuration is working correctly."
    )

    try:
        policy_error = await asyncio.to_thread(
            _send_smtp_test, host, port, user, password, msg
        )
        if policy_error:
            return JSONResponse({"ok": False, "error": policy_error})
        return JSONResponse({"ok": True, "message": f"Test email sent to {recipients}"})
    except Exception as exc:
        logger.warning("SMTP test failed: %s", exc)
        return JSONResponse({"ok": False, "error": _sanitize_test_error(str(exc))})
