"""SMTP transport: connection, STARTTLS policy, sanitising and alert send."""

from __future__ import annotations

import contextlib
import logging
import smtplib
import ssl
from collections.abc import Callable
from email.message import EmailMessage
from email.utils import getaddresses
from typing import Any

from cert_watch.alerting.model import AlertConfig, OutboundMessage, SendResult
from cert_watch.alerting.transports.base import _redact_secret
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
    message for anything persisted or shown to the user; the hostname
    (admin-configured, not secret) may be logged separately. Do not forward
    this return value into ``SendResult.operator_message``.
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


def _smtp_recipients(msg: OutboundMessage, config: AlertConfig) -> list[str]:
    all_recipients = [r for r in config.recipients if _validate_email(r)]
    for r in msg.queued_recipients:
        if r not in all_recipients and _validate_email(r):
            all_recipients.append(r)
        elif r not in config.recipients and not _validate_email(r):
            logger.warning("skipping invalid email recipient: %r", r)
    return all_recipients


def _exception_result(
    exc: Exception,
    config: AlertConfig,
    *,
    accepted: tuple[str, ...] = (),
    refused: tuple[str, ...] = (),
) -> SendResult:
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        reason = "authentication"
    elif isinstance(exc, ssl.SSLError):
        reason = "tls"
    elif isinstance(exc, smtplib.SMTPRecipientsRefused):
        reason = "recipients_refused"
    elif isinstance(exc, smtplib.SMTPResponseException):
        reason = "smtp_rejected"
    elif isinstance(exc, TimeoutError):
        reason = "timeout"
    else:
        reason = "transport"
    return SendResult(
        outcome="failed",
        reason=reason,
        reached_transport=True,
        accepted=accepted,
        refused=refused,
        operator_message=_sanitize_smtp_error(str(exc), config),
    )


class SmtpTransport:
    channel = "smtp"
    destination_id = "smtp"

    def __init__(self, config: AlertConfig) -> None:
        self.config = config

    def send(self, msg: OutboundMessage) -> SendResult:
        return send_alert(msg, self.config)


def send_alert(msg: OutboundMessage | Any, config: AlertConfig | None) -> SendResult:
    """Send via SMTP and return a complete, sanitized result."""
    if not isinstance(msg, OutboundMessage):
        # Compatibility for deprecated direct callers while plan 058's shims
        # remain. SmtpTransport itself accepts OutboundMessage only.
        msg = OutboundMessage.from_alert(msg)
    if config is None:
        return SendResult(
            "failed", "unknown", reached_transport=False,
            operator_message="SMTP is not configured",
        )
    email = EmailMessage()
    email["Subject"] = msg.subject
    email["From"] = config.from_addr
    all_recipients = list(msg.recipients) or _smtp_recipients(msg, config)
    if not all_recipients:
        logger.warning("no valid recipients for outbound message")
        return SendResult("failed", "no_recipients", reached_transport=False)
    email["To"] = ", ".join(all_recipients)
    email.set_content(msg.body)
    envelope = tuple(address for _, address in getaddresses(all_recipients))
    open_failure: list[SendResult] = []
    conn = _open_smtp_connection(config, on_failure=open_failure.append)
    if conn is None:
        if open_failure:
            return open_failure[0]
        return SendResult("failed", "unknown", reached_transport=False)
    try:
        raw_refused = conn.send_message(email)
        refused_map = raw_refused if isinstance(raw_refused, dict) else {}
        accepted_addresses = tuple(address for address in envelope if address not in refused_map)
        refused_addresses = tuple(address for address in envelope if address in refused_map)
        if refused_addresses:
            return SendResult(
                "partial",
                "recipients_refused",
                accepted=accepted_addresses,
                refused=refused_addresses,
            )
        return SendResult("accepted", accepted=envelope)
    except Exception as exc:  # noqa: BLE001 — AC-06: never raise; SMTP is an external service with unpredictable failure modes
        refused: tuple[str, ...] = ()
        accepted: tuple[str, ...] = ()
        if isinstance(exc, smtplib.SMTPRecipientsRefused):
            refused = tuple(address for address in envelope if address in exc.recipients)
            accepted = tuple(address for address in envelope if address not in exc.recipients)
        return _exception_result(exc, config, accepted=accepted, refused=refused)
    finally:
        with contextlib.suppress(Exception):
            conn.quit()


def _open_smtp_connection(
    config: AlertConfig,
    *,
    on_failure: Callable[[SendResult], None] | None = None,
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
        logger.warning("smtp host %s blocked by SSRF policy", config.smtp_host)
        if on_failure is not None:
            on_failure(SendResult(
                "blocked", "blocked", reached_transport=False,
                operator_message="smtp host blocked by SSRF policy",
            ))
        return None
    if pinned_ip is None:
        logger.warning("smtp host %s could not be resolved", config.smtp_host)
        if on_failure is not None:
            on_failure(SendResult(
                "failed", "dns", reached_transport=False,
                operator_message="SMTP host could not be resolved",
            ))
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
            logger.warning(
                "SMTP send aborted: STARTTLS not supported by %s:%s",
                config.smtp_host, config.smtp_port,
            )
            if on_failure is not None:
                on_failure(SendResult(
                    "failed", "tls",
                    operator_message=(
                        "STARTTLS not supported by SMTP server; "
                        "refusing to send credentials in cleartext"
                    ),
                ))
            with contextlib.suppress(Exception):
                s.quit()
            return None
        if config.smtp_user:
            s.login(config.smtp_user, config.smtp_password)
        return s
    except Exception as exc:  # noqa: BLE001 — SMTP is an external service with unpredictable failure modes
        sanitized = _sanitize_smtp_error(str(exc), config)
        logger.warning("SMTP connect failed: %s", sanitized)
        if on_failure is not None:
            on_failure(_exception_result(exc, config))
        if s is not None:
            with contextlib.suppress(Exception):
                s.quit()
        return None
