"""SMTP transport: connection, STARTTLS policy, sanitising and alert send."""

from __future__ import annotations

import contextlib
import logging
import smtplib
import ssl
from email.message import EmailMessage

from cert_watch.alerting.evidence import observe_exception, observe_failure, observe_smtp
from cert_watch.alerting.model import AlertConfig
from cert_watch.alerting.transports.base import _redact_secret
from cert_watch.database import Alert
from cert_watch.email_validation import is_safe_email_address
from cert_watch.http_client import resolve_smtp_host, validate_smtp_host

logger = logging.getLogger("cert_watch.alerts")

_validate_email = is_safe_email_address


def _sanitize_smtp_error(msg: str, config: AlertConfig | None) -> str:
    """Strip SMTP credentials from error messages to avoid logging secrets.

    Passwords are always redacted regardless of length (B4). Usernames keep
    the ``>= 4`` gate because short usernames like ``ops`` frequently appear
    as substrings of diagnostic text and are not secret per SMTP logging
    conventions.
    """
    if config and config.smtp_password:
        msg = _redact_secret(msg, config.smtp_password)
    if config and config.smtp_user and len(config.smtp_user) >= 4:
        msg = msg.replace(config.smtp_user, "***")
    return msg


def _check_smtp_ssrf(config: AlertConfig) -> str | None:
    """SSRF pre-check for the SMTP host (BC-116 SMTP parity).

    Returns an error string (which may include the resolved IP, for
    admin/diagnostic logging) when the host is blocked, or None when allowed.
    Never raises -- a blocked host is a delivery failure, not a crash (AC-06).

    Contract: the returned string is NOT safe for user-visible output. It can
    contain the resolved IP. Callers must discard it and use a fixed, IP-free
    message for anything persisted or shown to the user (e.g.
    ``alert.error_message``); the hostname (admin-configured, not secret) may be
    logged separately. Do not forward this return value into error_message.
    """
    return validate_smtp_host(
        config.smtp_host,
        allow_private=config.allow_private,
        allowed_subnets=config.allowed_subnets,
    )


def negotiate_starttls(s: smtplib.SMTP, port: int, has_credentials: bool) -> bool:
    """Opportunistically negotiate STARTTLS on a non-465 connection.

    Returns True when it is safe to proceed: either TLS was established, the
    connection is already wrapped (port 465), or STARTTLS is unavailable but
    there are no credentials to protect. Returns False only when STARTTLS is
    unavailable AND credentials are configured — the caller must then abort
    rather than transmit the password in cleartext.

    The no-credentials case is what makes plain port-25 relays work: such
    servers commonly don't offer STARTTLS and need no auth, yet the previous
    code refused them unconditionally with "STARTTLS not supported by server".
    """
    if port == 465:
        return True  # already TLS-wrapped via SMTP_SSL
    try:
        # smtplib's implicit default context does not verify certificates.
        # Always supply the platform trust-store context so STARTTLS checks
        # both the chain and the original relay hostname retained in _host.
        s.starttls(context=ssl.create_default_context())
        return True
    except smtplib.SMTPNotSupportedError:
        return not has_credentials


def connect_smtp_transport(
    host: str,
    pinned_ip: str,
    port: int,
    *,
    timeout: int,
) -> smtplib.SMTP | smtplib.SMTP_SSL:
    """Connect to a validated IP while retaining *host* for TLS identity."""
    if port == 465:
        # SMTP_SSL's implicit context is intentionally unverified in the
        # standard library. Use the default verifying context explicitly.
        context = ssl.create_default_context()
        smtp_ssl = smtplib.SMTP_SSL(timeout=timeout, context=context)
        smtp_ssl._host = host  # type: ignore[attr-defined]
        code, message = smtp_ssl.connect(pinned_ip, port)
        if code != 220:
            smtp_ssl.close()
            raise smtplib.SMTPConnectError(code, message)
        return smtp_ssl

    smtp = smtplib.SMTP(pinned_ip, port, timeout=timeout)
    smtp._host = host  # type: ignore[attr-defined]
    return smtp


def _smtp_recipients(alert: Alert, config: AlertConfig) -> list[str]:
    all_recipients = [r for r in config.recipients if _validate_email(r)]
    for r in alert.extra_recipients:
        if r not in all_recipients and _validate_email(r):
            all_recipients.append(r)
        elif r not in config.recipients and not _validate_email(r):
            logger.warning("skipping invalid email recipient: %r", r)
    return all_recipients


def send_alert(alert: Alert, config: AlertConfig | None) -> bool:
    """Send via SMTP. See AC-03/AC-06."""
    if config is None:
        return False
    msg = EmailMessage()
    msg["Subject"] = f"[cert-watch] {alert.alert_type}: {alert.message[:60]}"
    msg["From"] = config.from_addr
    all_recipients = _smtp_recipients(alert, config)
    if not all_recipients:
        logger.warning("no valid recipients for alert %s", alert.id)
        observe_failure("no_recipients")
        return False
    msg["To"] = ", ".join(all_recipients)
    msg.set_content(alert.message)
    conn = _open_smtp_connection(config, alert=alert)
    if conn is None:
        return False
    try:
        refused = conn.send_message(msg)
        observe_smtp(all_recipients, refused if isinstance(refused, dict) else {})
        return True
    except Exception as exc:  # noqa: BLE001 — AC-06: never raise; SMTP is an external service with unpredictable failure modes
        alert.error_message = _sanitize_smtp_error(str(exc), config)
        if isinstance(exc, smtplib.SMTPRecipientsRefused):
            observe_smtp(all_recipients, exc.recipients)
        observe_exception(exc)
        return False
    finally:
        with contextlib.suppress(Exception):
            conn.quit()


def _open_smtp_connection(
    config: AlertConfig, *, alert: Alert | None = None
) -> smtplib.SMTP | smtplib.SMTP_SSL | None:
    # Resolve and validate exactly once, then connect to that same address.
    # Resolving once for validation and again for transport leaves a DNS-
    # rebinding gap even when both individual operations look correct.
    ssrf_err, pinned_ip = resolve_smtp_host(
        config.smtp_host,
        config.smtp_port,
        allow_private=config.allow_private,
        allowed_subnets=config.allowed_subnets,
    )
    if ssrf_err is not None:
        observe_failure("blocked")
        logger.warning("smtp host %s blocked by SSRF policy", config.smtp_host)
        if alert is not None:
            alert.error_message = "smtp host blocked by SSRF policy"
        return None
    if pinned_ip is None:
        observe_failure("dns")
        logger.warning("smtp host %s could not be resolved", config.smtp_host)
        if alert is not None:
            alert.error_message = "SMTP host could not be resolved"
        return None
    # Connect to the pinned IP but retain the original hostname for TLS SNI and
    # certificate verification.
    s: smtplib.SMTP_SSL | smtplib.SMTP | None = None
    try:
        s = connect_smtp_transport(
            config.smtp_host,
            pinned_ip,
            config.smtp_port,
            timeout=15,
        )
        if not negotiate_starttls(s, config.smtp_port, bool(config.smtp_user)):
            observe_failure("tls")
            logger.warning(
                "SMTP send aborted: STARTTLS not supported by %s:%s",
                config.smtp_host, config.smtp_port,
            )
            if alert is not None:
                alert.error_message = (
                    "STARTTLS not supported by SMTP server; "
                    "refusing to send credentials in cleartext"
                )
            with contextlib.suppress(Exception):
                s.quit()
            return None
        if config.smtp_user:
            s.login(config.smtp_user, config.smtp_password)
        return s
    except Exception as exc:  # noqa: BLE001 — SMTP is an external service with unpredictable failure modes
        sanitized = _sanitize_smtp_error(str(exc), config)
        observe_exception(exc)
        logger.warning("SMTP connect failed: %s", sanitized)
        if alert is not None:
            alert.error_message = sanitized
        if s is not None:
            with contextlib.suppress(Exception):
                s.quit()
        return None
