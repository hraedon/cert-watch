"""Email and webhook alerts. See spec wi_fr04_alerts.md."""

from __future__ import annotations

import contextlib
import json
import logging
import math
import smtplib
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.message import EmailMessage
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cert_watch.certificate_model import Certificate
from cert_watch.database import Alert as Alert
from cert_watch.database import AlertRepository
from cert_watch.http_client import SSRFBlockedError, ssrf_safe_urlopen, validate_smtp_host
from cert_watch.retry import backoff_range as backoff_range

if TYPE_CHECKING:
    from cert_watch.policy import PolicyViolation

logger = logging.getLogger("cert_watch.alerts")

LEAF_THRESHOLDS = (14, 7, 3, 1)


def _validate_email(addr: str) -> bool:
    """Reject email addresses that could inject extra SMTP recipients.

    Parses the address and rejects:
    - empty/only-display-name results,
    - any comma or semicolon (prevents header-injection of multiple
      To:/Cc: recipients via a stored owner_email),
    - newlines, carriage returns, tabs, or other control characters
      (prevents SMTP header injection),
    - malformed addresses without an '@'.
    """
    if not addr:
        return False
    if any(c in addr for c in (",", ";", "\r", "\n", "\t")):
        return False
    if any(ord(c) < 32 for c in addr):
        return False
    from email.utils import parseaddr

    _real_name, email = parseaddr(addr)
    return bool(email and "@" in email)


CHAIN_THRESHOLDS = (30, 14, 7)
# In digest mode, per-certificate alerts at or below this many days to expiry
# still fire individually (the final-countdown "3/2/1" alerts); the routine
# heads-up thresholds are left to the weekly digest. See evaluate_thresholds.
URGENT_THRESHOLD_DAYS = 3
SHORT_CERT_LIFETIME_DAYS = 90
SHORT_LIFETIME_LEAF_PCT = (50, 25, 10)
SHORT_LIFETIME_CHAIN_PCT = (50, 25, 10)


def effective_thresholds(
    cert: Certificate,
    *,
    custom_thresholds: tuple[int, ...] | None = None,
) -> tuple[int, ...]:
    if custom_thresholds is not None:
        return custom_thresholds
    validity_days = (cert.not_after - cert.not_before).days
    if validity_days <= SHORT_CERT_LIFETIME_DAYS:
        pcts = SHORT_LIFETIME_LEAF_PCT if cert.is_leaf else SHORT_LIFETIME_CHAIN_PCT
        return tuple(math.ceil(validity_days * p / 100) for p in pcts)
    return LEAF_THRESHOLDS if cert.is_leaf else CHAIN_THRESHOLDS


@dataclass
class AlertConfig:
    """SMTP configuration. See AC-01."""

    smtp_host: str
    smtp_user: str
    smtp_password: str
    from_addr: str
    recipients: list[str] = field(default_factory=list)
    smtp_port: int = 587
    # SSRF policy for the SMTP host (BC-116 SMTP parity). Defaults mirror
    # Settings.allow_private / CERT_WATCH_ALLOW_PRIVATE_IPS=1 so the common
    # case of an internal relay is unaffected; populated from Settings by
    # Settings.build_alert_config.
    allow_private: bool = True
    allowed_subnets: tuple[str, ...] = ()


@dataclass
class WebhookConfig:
    """Webhook/Slack alert configuration."""

    url: str
    kind: str = "generic"
    routing_key: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    timeout: int = 15
    template: str = ""
    allow_private: bool = False
    allowed_subnets: tuple[str, ...] = ()


def evaluate_thresholds(
    cert: Certificate,
    alert_repo: AlertRepository,
    *,
    cert_id: str | None = None,
    custom_thresholds: tuple[int, ...] | None = None,
    owner_info: dict[str, Any] | None = None,
    extra_recipients: list[str] | None = None,
    hostname: str = "",
    urgent_only: bool = False,
) -> list[Alert]:
    """Create a pending alert for the most urgent newly-tripped threshold.

    Each threshold fires **exactly once** per certificate: once a threshold has
    been alerted, it is never re-alerted. Only the single most urgent (smallest)
    threshold that the cert has crossed but hasn't yet been alerted for produces
    an alert. This prevents users from receiving a separate email for every
    threshold stage when a cert is already past several of them.

    The spec talks about cert_id as the link to existing alerts; we accept it as
    a kwarg so callers that persisted the cert can pass the row id. If omitted we
    use fingerprint_sha256 as a stable handle.

    If custom_thresholds is provided, those are used instead of the defaults.

    If extra_recipients is provided, those addresses are used as the alert's
    extra_recipients (merged from alert-group routing). Otherwise, the
    owner_info["owner_email"] is used (backward-compatible behavior).
    """
    days = cert.days_until_expiry()
    thresholds = effective_thresholds(cert, custom_thresholds=custom_thresholds)
    # Digest mode: only the final-countdown thresholds fire as individual alerts;
    # the rest are summarized by the weekly digest.
    if urgent_only:
        thresholds = tuple(t for t in thresholds if t <= URGENT_THRESHOLD_DAYS)
    cid = cert_id or cert.fingerprint_sha256

    # Suppress alerts when renewal is complete.
    if owner_info and owner_info.get("renewal_status") == "renewed":
        return []

    # Collect existing alerts scoped to the current alert_type so that
    # renewal_stalled / policy_violation rows don't interfere with expiry
    # thresholds. M4: Include failed alerts in the dedup set so a delivery
    # failure doesn't produce a duplicate row on the next cycle; instead the
    # failed alert is reset to pending for retry (see below).
    current_type = "expired" if days < 0 else "expiry_warning"
    cert_alerts = alert_repo.list_for_cert(cid)
    existing_for_type: set[int] = {
        a.threshold_days
        for a in cert_alerts
        if a.threshold_days is not None
        and a.alert_type == current_type
    }
    failed_for_type: dict[int, Alert] = {
        a.threshold_days: a
        for a in cert_alerts
        if a.threshold_days is not None
        and a.alert_type == current_type
        and a.status == "failed"
    }

    # Find the most urgent (smallest) threshold the cert has now crossed.
    # Floor semantics: days_until_expiry() returns floor(delta), so a cert
    # with 1d23h remaining shows days=1 and crosses the t=1 threshold.
    crossed = [t for t in thresholds if days <= t]
    if not crossed:
        return []

    most_urgent = min(crossed)

    # Each (alert_type, threshold) fires exactly once.
    if most_urgent in existing_for_type:
        # M4: If the existing alert failed delivery, reset it to pending so
        # process_pending retries it instead of creating a duplicate row.
        failed_alert = failed_for_type.get(most_urgent)
        if failed_alert:
            alert_repo.reset_to_pending(failed_alert.id)
            failed_alert.status = "pending"
            return [failed_alert]
        return []

    # Don't go backwards: if a more urgent threshold was already alerted
    # for this type, the situation has escalated past this one.
    if any(e < most_urgent for e in existing_for_type):
        return []

    alert = Alert(
        cert_id=cid,
        alert_type="expired" if days < 0 else "expiry_warning",
        status="pending",
        message=_format_message(cert, days, most_urgent, owner_info=owner_info),
        threshold_days=most_urgent,
        extra_recipients=(
            list(extra_recipients)
            if extra_recipients
            else (
                [owner_info["owner_email"]]
                if owner_info and owner_info.get("owner_email")
                else []
            )
        ),
        hostname=hostname,
        subject=cert.subject,
    )
    alert_id = alert_repo.create(alert)
    alert.id = alert_id
    return [alert]


def _load_host_owner_maps(
    db_path: str | Path,
) -> tuple[dict[tuple[str, int], int | None], dict[tuple[str, int], dict[str, Any]]]:
    """Load per-host threshold and owner/contact maps in a single query.

    Shared by ``evaluate_all_certs`` and ``evaluate_renewal_window`` so the
    ``hosts`` table is read once per evaluation path with consistent shaping.
    """
    from cert_watch.database import _connect

    host_thresholds: dict[tuple[str, int], int | None] = {}
    host_owners: dict[tuple[str, int], dict[str, Any]] = {}
    with _connect(db_path) as conn:
        for row in conn.execute("SELECT * FROM hosts").fetchall():
            key = (row["hostname"], row["port"])
            d = dict(row)
            host_thresholds[key] = d.get("threshold_days")
            host_owners[key] = {
                "owner_name": d.get("owner_name", ""),
                "owner_email": d.get("owner_email", ""),
                "owner_slack": d.get("owner_slack", ""),
                "renewal_status": d.get("renewal_status", "pending"),
            }
    return host_thresholds, host_owners


def evaluate_all_certs(
    db_path: str | Path, alert_repo: AlertRepository, *, urgent_only: bool = False
) -> list[Alert]:
    """Evaluate thresholds for all leaf certificates in the database.

    When ``urgent_only`` is set (digest mode), only the final-countdown
    thresholds (<= ``URGENT_THRESHOLD_DAYS``) produce individual alerts; the
    routine heads-up thresholds are covered by the weekly digest instead.

    Looks up per-host custom thresholds and owner/contact info from the hosts
    table and passes them through to evaluate_thresholds. Also resolves
    alert-group recipients based on effective tags and manual assignment.
    """
    from cert_watch.database import _connect, _parse_iso

    host_thresholds, host_owners = _load_host_owner_maps(db_path)

    with _connect(db_path) as conn:
        leaves = conn.execute(
            "SELECT id, subject, issuer, not_before, not_after, "
            "san_dns_names, fingerprint_sha256, hostname, port "
            "FROM certificates WHERE is_leaf = 1"
        ).fetchall()

    # Batch-resolve group recipients and threshold overrides in a single pass
    all_group_recipients, group_threshold_map = _resolve_group_config(db_path)

    # Role-based alert routing: users in a role get alerts for certs owned by
    # the role's team email (host.owner_email matches role.email).
    role_user_emails = _load_role_user_emails(db_path)

    all_alerts: list[Alert] = []
    for leaf_row in leaves:
        cert = Certificate(
            subject=leaf_row["subject"],
            issuer=leaf_row["issuer"],
            not_before=_parse_iso(leaf_row["not_before"]),
            not_after=_parse_iso(leaf_row["not_after"]),
            san_dns_names=(
                json.loads(leaf_row["san_dns_names"])
                if leaf_row["san_dns_names"]
                else []
            ),
            fingerprint_sha256=leaf_row["fingerprint_sha256"],
            raw_der=b"",
            is_leaf=True,
        )
        custom = None
        hostname = leaf_row["hostname"]
        port = leaf_row["port"]
        owner_info: dict[str, Any] | None = None
        if hostname and port:
            host_td = host_thresholds.get((hostname, port))
            if host_td is not None:
                custom = (host_td, max(host_td // 2, 1), max(host_td // 4, 1), 1)
            owner_info = host_owners.get((hostname, port))

        # Per-group threshold override: if any matching group has threshold_days
        # set, use the most urgent (smallest) group threshold.
        cert_id = leaf_row["id"]
        group_td = group_threshold_map.get(cert_id)
        if group_td is not None:
            custom = (group_td, max(group_td // 2, 1), max(group_td // 4, 1), 1)

        # Resolve alert-group recipients for this cert (batch result), then merge
        # with owner + role members through the shared resolver (single source of
        # truth shared with orphan detection — see resolve_cert_recipients).
        group_recipients = all_group_recipients.get(cert_id, [])
        merged_extra = resolve_cert_recipients(
            group_recipients, owner_info, role_user_emails
        )

        alerts = evaluate_thresholds(
            cert, alert_repo, cert_id=leaf_row["id"], custom_thresholds=custom,
            owner_info=owner_info, extra_recipients=merged_extra or None,
            hostname=leaf_row["hostname"] or "", urgent_only=urgent_only,
        )
        all_alerts.extend(alerts)
    return all_alerts


def _load_role_user_emails(db_path: str | Path) -> dict[str, list[str]]:
    """Map a role's team email (casefolded) → emails of users in that role.

    Used to fan alert routing out to the human members of a team whose address
    matches a host's ``owner_email``. Returns an empty map if the users/roles
    tables are unavailable (local-auth disabled), so routing degrades quietly.
    """
    role_user_emails: dict[str, list[str]] = {}
    try:
        from cert_watch.database.users_roles import (
            SqliteRoleRepository,
            SqliteUserRepository,
        )

        all_users = SqliteUserRepository(db_path).list_all()
        for role in SqliteRoleRepository(db_path).list_all():
            if not role.email:
                continue
            members = [u.email for u in all_users if u.role_id == role.id and u.email]
            if members:
                role_user_emails[role.email.casefold()] = members
    except (ImportError, sqlite3.Error):
        logger.warning("Role-based alert routing unavailable", exc_info=True)
        return {}
    return role_user_emails


def resolve_cert_recipients(
    group_recipients: list[str],
    owner_info: dict[str, Any] | None,
    role_user_emails: dict[str, list[str]],
) -> list[str]:
    """Merge a cert's alert-group recipients, host owner, and role members into a
    single order-preserving, deduplicated recipient list.

    This is the **one source of truth** for *who* an expiry alert for a cert
    reaches (beyond the global ``AlertConfig.recipients`` applied at send time).
    ``evaluate_all_certs`` uses it to populate ``extra_recipients``; orphan
    detection uses it to decide whether a cert routes to anyone specific. Keep
    dedup exact-string to match the downstream dedup in ``send_alert``.
    """
    merged: list[str] = list(group_recipients)
    owner_email = owner_info.get("owner_email") if owner_info else None
    if owner_email:
        if owner_email not in merged:
            merged.append(owner_email)
        for member in role_user_emails.get(owner_email.casefold(), []):
            if member not in merged:
                merged.append(member)
    return merged


def find_orphan_certs(db_path: str | Path) -> list[dict[str, Any]]:
    """Return leaf certs that resolve to **zero** specific recipients.

    An orphan matches no alert group and has no host ``owner_email`` (so no role
    members either). Such a cert is not dropped — at send time it still falls
    back to the global ``AlertConfig.recipients`` — but nothing routes it to a
    *named* owner or team, so it is the cert most likely to be silently
    forgotten. Surfaced in the admin renewal digest (Plan 050, decision pinned
    2026-06-20).

    Returns a list of ``{"cert_id", "hostname", "port", "subject"}`` dicts,
    ordered by hostname then subject, using the same routing resolver as the
    delivery path so the report can't drift from reality.
    """
    from cert_watch.database import _connect

    all_group_recipients, _ = _resolve_group_config(db_path)
    role_user_emails = _load_role_user_emails(db_path)
    _host_thresholds, host_owners = _load_host_owner_maps(db_path)

    with _connect(db_path) as conn:
        leaves = conn.execute(
            "SELECT id, subject, hostname, port FROM certificates WHERE is_leaf = 1"
        ).fetchall()

    orphans: list[dict[str, Any]] = []
    for row in leaves:
        owner_info = host_owners.get((row["hostname"], row["port"]))
        recipients = resolve_cert_recipients(
            all_group_recipients.get(row["id"], []), owner_info, role_user_emails
        )
        if not recipients:
            orphans.append({
                "cert_id": row["id"],
                "hostname": row["hostname"] or "",
                "port": row["port"],
                "subject": row["subject"] or "",
            })
    orphans.sort(key=lambda o: (o["hostname"], o["subject"]))
    return orphans


def evaluate_renewal_window(
    db_path: str | Path,
    alert_repo: AlertRepository,
    window_days: int = 30,
) -> list[Alert]:
    """Create ``renewal_stalled`` alerts for leaf certs inside their renewal
    window with no successor certificate (Plan 027).

    A signal distinct from ``expiry_warning``: the cert *should* have been
    rotated by automation by now, but no replacement has appeared — flagging a
    broken Certbot / cert-manager / ACME job well before the generic expiry
    alarm. A successor is any cert whose ``replaces_cert_id`` points at this one.
    Idempotent: at most one pending ``renewal_stalled`` alert per cert.
    """
    if window_days <= 0:
        return []
    from cert_watch.database import _connect, _parse_iso

    now = datetime.now(UTC)
    with _connect(db_path) as conn:
        superseded = {
            r["replaces_cert_id"]
            for r in conn.execute(
                "SELECT DISTINCT replaces_cert_id FROM certificates "
                "WHERE replaces_cert_id IS NOT NULL"
            ).fetchall()
        }
        leaves = conn.execute(
            "SELECT id, subject, hostname, port, not_after "
            "FROM certificates WHERE is_leaf = 1"
        ).fetchall()

    _host_thresholds, host_owners = _load_host_owner_maps(db_path)
    created: list[Alert] = []
    for leaf in leaves:
        cid = leaf["id"]
        if cid in superseded:
            continue  # a successor cert already exists → renewal worked
        try:
            days = (_parse_iso(leaf["not_after"]) - now).days
        except (ValueError, TypeError):  # date parse
            continue
        if days < 0 or days > window_days:
            continue  # expired (expiry_warning owns it) or outside the window
        existing = alert_repo.list_for_cert(cid)
        if any(
            a.alert_type == "renewal_stalled" and a.status == "pending"
            for a in existing
        ):
            continue  # already flagged this window
        owner = host_owners.get((leaf["hostname"], leaf["port"]), {})
        if owner.get("renewal_status") in ("renewed", "in_progress"):
            continue  # operator has flagged renewal as handled
        alert = Alert(
            cert_id=cid,
            alert_type="renewal_stalled",
            status="pending",
            message=_format_renewal_message(leaf, days, window_days, owner),
            threshold_days=window_days,
            extra_recipients=(
                [owner["owner_email"]] if owner.get("owner_email") else []
            ),
            hostname=leaf["hostname"] or "",
            subject=leaf["subject"] or "",
        )
        alert.id = alert_repo.create(alert)
        created.append(alert)
    return created


def _format_renewal_message(
    leaf: sqlite3.Row, days: int, window_days: int, owner: dict[str, Any]
) -> str:
    name = leaf["subject"] or leaf["hostname"] or leaf["id"]
    target = leaf["hostname"] or "this certificate"
    msg = (
        f"Certificate '{name}' is inside its renewal window "
        f"({days} days remaining; window: {window_days}d) but no successor "
        f"certificate has appeared. Check the renewal automation "
        f"(Certbot / cert-manager / ACME client) for {target}."
    )
    if owner.get("owner_name"):
        msg += f" Owner: {owner['owner_name']}."
    return msg


def _format_message(
    cert: Certificate, days: int, threshold: int, *, owner_info: dict[str, Any] | None = None
) -> str:
    """See AC-05."""
    action = (
        "Renew this certificate immediately."
        if days <= 7
        else "Plan a renewal soon."
    )
    msg = (
        f"Certificate '{cert.display_name}' "
        f"(subject: {cert.subject}) "
        f"expires on {cert.not_after.isoformat()} "
        f"({days} days remaining; threshold: <={threshold}d). "
        f"Recommended action: {action}"
    )
    if owner_info:
        parts = []
        if owner_info.get("owner_name"):
            parts.append(f"Owner: {owner_info['owner_name']}")
        if owner_info.get("owner_email"):
            parts.append(f"Contact: {owner_info['owner_email']}")
        if owner_info.get("owner_slack"):
            parts.append(f"Slack: {owner_info['owner_slack']}")
        if parts:
            msg += " " + "; ".join(parts)
    if owner_info and owner_info.get("renewal_status") == "in_progress":
        msg += " (renewal in progress)"
    return msg


def _sanitize_smtp_error(msg: str, config: AlertConfig | None) -> str:
    """Strip SMTP credentials from error messages to avoid logging secrets.

    Only replaces passwords >= 4 chars to avoid false positives (e.g. 'p' in 'nope').
    """
    if config and config.smtp_password and len(config.smtp_password) >= 4:
        msg = msg.replace(config.smtp_password, "***")
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
        s.starttls()
        return True
    except smtplib.SMTPNotSupportedError:
        return not has_credentials


def _sanitize_webhook_error(msg: str, config: WebhookConfig | None) -> str:
    """Strip webhook URL, header values, and routing key from error messages."""
    if config and config.url:
        msg = msg.replace(config.url, "***")
    if config and config.routing_key and len(config.routing_key) >= 4:
        msg = msg.replace(config.routing_key, "***")
    if config and config.headers:
        for val in config.headers.values():
            if len(val) >= 4:
                msg = msg.replace(val, "***")
    return msg


def send_alert(alert: Alert, config: AlertConfig | None) -> bool:
    """Send via SMTP. See AC-03/AC-06."""
    if config is None:
        return False
    msg = EmailMessage()
    msg["Subject"] = f"[cert-watch] {alert.alert_type}: {alert.message[:60]}"
    msg["From"] = config.from_addr
    all_recipients = [r for r in config.recipients if _validate_email(r)]
    for r in alert.extra_recipients:
        if r not in all_recipients and _validate_email(r):
            all_recipients.append(r)
        elif r not in config.recipients and not _validate_email(r):
            logger.warning("skipping invalid email recipient: %r", r)
    if not all_recipients:
        logger.warning("no valid recipients for alert %s", alert.id)
        return False
    msg["To"] = ", ".join(all_recipients)
    msg.set_content(alert.message)
    conn = _open_smtp_connection(config, alert=alert)
    if conn is None:
        return False
    try:
        conn.send_message(msg)
        return True
    except Exception as exc:  # noqa: BLE001 — AC-06: never raise; SMTP is an external service with unpredictable failure modes
        alert.error_message = _sanitize_smtp_error(str(exc), config)
        return False
    finally:
        with contextlib.suppress(Exception):
            conn.quit()


def send_webhook(alert: Alert, config: WebhookConfig | None) -> bool:
    """Send alert via the configured channel adapter. Returns True on success.

    Dispatches to the adapter matching ``config.kind`` and sends the resulting
    request through ``ssrf_safe_urlopen``. PagerDuty returns HTTP 202 on success;
    all other providers return 2xx.
    """
    from cert_watch.alert_adapters import get_adapter

    if config is None:
        return False
    try:
        adapter = get_adapter(config.kind)
        req = adapter.build(alert, config)
        resp = ssrf_safe_urlopen(
            req.url,
            data=req.body,
            timeout=config.timeout,
            method=req.method,
            headers=req.headers,
            allow_private=config.allow_private,
            allowed_subnets=config.allowed_subnets,
        )
        with resp:
            if config.kind == "pagerduty":
                return resp.status == 202
            return 200 <= resp.status < 300
    except SSRFBlockedError as exc:
        alert.error_message = f"webhook URL blocked by SSRF policy: {exc}"
        return False
    except Exception as exc:  # noqa: BLE001 — webhook is an external service with unpredictable failure modes
        alert.error_message = _sanitize_webhook_error(str(exc), config)
        return False


def _adapter_has_build_resolve(kind: str) -> bool:
    """True when the adapter for *kind* exposes a ``build_resolve`` method."""
    from cert_watch.alert_adapters import get_adapter

    try:
        adapter = get_adapter(kind)
    except ValueError:
        return False
    return hasattr(adapter, "build_resolve")


def send_webhook_resolve(
    cert_id: str,
    alert_type: str,
    threshold_days: int | None,
    config: WebhookConfig,
    *,
    summary: str = "",
    hostname: str = "",
    subject: str = "",
    alert_created_at: datetime | None = None,
) -> bool:
    """Send a resolve event through the appropriate adapter.

    Dispatches ``build_resolve`` on the adapter matching ``config.kind``.
    Returns False if the adapter has no ``build_resolve`` method.
    """
    from cert_watch.alert_adapters import get_adapter

    try:
        adapter = get_adapter(config.kind)
    except ValueError:
        return False

    build_resolve = getattr(adapter, "build_resolve", None)
    if build_resolve is None:
        return False

    try:
        req = build_resolve(
            cert_id, alert_type, threshold_days, config,
            summary=summary, hostname=hostname, subject=subject,
            alert_created_at=alert_created_at,
        )
        resp = ssrf_safe_urlopen(
            req.url,
            data=req.body,
            timeout=config.timeout,
            method=req.method,
            headers=req.headers,
            allow_private=config.allow_private,
            allowed_subnets=config.allowed_subnets,
        )
        with resp:
            if config.kind == "pagerduty":
                return resp.status == 202
            return 200 <= resp.status < 300
    except SSRFBlockedError as exc:
        logger.warning(
            "%s resolve blocked by SSRF policy: %s",
            config.kind,
            _sanitize_webhook_error(str(exc), config),
        )
        return False
    except Exception as exc:  # noqa: BLE001 — webhook resolve is an external service with unpredictable failure modes
        logger.warning(
            "%s resolve failed for cert %s: %s",
            config.kind,
            cert_id,
            _sanitize_webhook_error(str(exc), config),
        )
        return False


def resolve_webhook_for_renewed_cert(
    db_path: str | Path,
    old_cert_id: str,
    webhook_config: WebhookConfig | None = None,
    *,
    pending_alerts: list[Alert] | None = None,
) -> int:
    """Resolve all open incidents/alerts for a cert that has been renewed.

    Works for any webhook kind whose adapter exposes ``build_resolve``.
    Looks up pending alerts for the old cert and sends a resolve event for
    each unique (alert_type, threshold_days) combination. Returns the
    number of resolve events sent.

    When *pending_alerts* is provided (a pre-fetched list from
    :class:`SqliteAlertRepository`), uses that instead of querying the
    database — necessary when the caller knows the alert rows will be
    deleted before this function runs (e.g. ``replace_scanned``).
    """
    if webhook_config is None or not _adapter_has_build_resolve(webhook_config.kind):
        return 0
    if pending_alerts is None:
        from cert_watch.database import SqliteAlertRepository

        alert_repo = SqliteAlertRepository(db_path)
        cert_alerts = alert_repo.list_for_cert(old_cert_id)
    else:
        cert_alerts = pending_alerts
    seen: set[tuple[str, int | None]] = set()
    resolved = 0
    for alert in cert_alerts:
        key = (alert.alert_type, alert.threshold_days)
        if key in seen:
            continue
        seen.add(key)
        if send_webhook_resolve(
            old_cert_id, alert.alert_type, alert.threshold_days,
            webhook_config,
            summary=f"cert-watch: certificate renewed, resolving {alert.alert_type} alert",
            hostname=alert.hostname,
            subject=alert.subject,
            alert_created_at=alert.created_at,
        ):
            resolved += 1
    return resolved


ALERT_MAX_RETRIES = 3
ALERT_RETRY_DELAY = 2  # seconds between retries


def evaluate_policy_alerts(
    cert_id: str,
    hostname: str,
    violations: list[PolicyViolation],
    db_path: str | Path,
    *,
    subject: str = "",
    conn: sqlite3.Connection | None = None,
) -> list[Alert]:
    """Create pending alerts for critical or warning policy violations.

    Info-level violations are recorded but do not generate alerts.
    Returns the list of created Alert objects.

    Deduplication: before creating a new alert for a (cert_id, rule_id)
    pair, check whether a pending ``policy_violation`` alert already exists
    for the same cert and rule_id. Only create a new alert if no matching
    pending alert is found (mirrors the cooldown logic in
    ``evaluate_thresholds``). When *conn* is provided it is used directly
    and the caller owns commit/rollback.
    """
    from cert_watch.database import SqliteAlertRepository

    alert_repo = SqliteAlertRepository(db_path)
    existing = alert_repo.list_for_cert(cert_id, conn=conn)
    existing_rule_ids: set[str] = set()
    for a in existing:
        if a.alert_type == "policy_violation" and a.status == "pending":
            for v in violations:
                marker = f"[{v.rule_id}]"
                if marker in a.message:
                    existing_rule_ids.add(v.rule_id)
                    break
    created: list[Alert] = []
    for v in violations:
        if v.severity not in ("critical", "warning"):
            continue
        if v.rule_id in existing_rule_ids:
            continue
        alert = Alert(
            cert_id=cert_id,
            alert_type="policy_violation",
            status="pending",
            message=(
                f"Policy violation ({v.severity}) [{v.rule_id}]: {v.message} "
                f"Remediation: {v.remediation}"
            ),
            hostname=hostname,
            subject=subject,
        )
        alert.id = alert_repo.create(alert, conn=conn)
        created.append(alert)
    return created


def _resolve_group_config(
    db_path: str | Path,
) -> tuple[dict[str, list[str]], dict[str, int | None]]:
    """Single-pass resolution of alert-group recipients and threshold overrides.

    Returns (recipients_map, thresholds_map) where:
    - recipients_map: {cert_id: [deduplicated recipients]} for all matching certs
    - thresholds_map: {cert_id: min threshold_days} for certs matching groups
      that have threshold_days set (absent when no group with threshold_days matches)

    Performs the 3 SQL queries (groups, cert tags, manual assignments) once
    instead of duplicating them across resolve_all_group_recipients and
    resolve_group_thresholds.

    Role→alert-group link (WI-061): roles with a non-empty ``scope_tag`` and
    a linked ``alert_group_id`` also route alerts for certs whose effective
    tags intersect the role's scope tags.  The linked alert_group's
    recipients and threshold are included as if the group had matched.
    """
    from cert_watch.database.connection import _connect
    from cert_watch.tags import merge_tags, parse_tags, tags_match

    with _connect(db_path) as conn:
        groups = [
            {
                "id": row["id"],
                "recipients": [r.strip() for r in row["recipients"].split(",") if r.strip()],
                "match_tags": parse_tags(row["match_tags"]),
                "threshold_days": row["threshold_days"],
            }
            for row in conn.execute(
                "SELECT id, recipients, match_tags, threshold_days FROM alert_groups"
            ).fetchall()
        ]
        if not groups:
            return {}, {}

        cert_tags_rows = conn.execute(
            """SELECT c.id, c.tags, h.tags AS host_tags
               FROM certificates c
               LEFT JOIN hosts h ON c.hostname = h.hostname AND c.port = h.port
               WHERE c.is_leaf = 1"""
        ).fetchall()
        cert_tags = {
            row["id"]: merge_tags(row["tags"], row["host_tags"])
            for row in cert_tags_rows
        }

        manual_rows = conn.execute(
            "SELECT cert_id, group_id FROM alert_group_certs"
        ).fetchall()
        manual_map: dict[str, set[str]] = {}
        for row in manual_rows:
            manual_map.setdefault(row["cert_id"], set()).add(row["group_id"])

    # Role→alert-group links (WI-061): load roles that have both a
    # scope_tag and a linked alert_group_id, so their linked group's
    # recipients are included for matching certs.
    role_links: list[dict[str, Any]] = []
    try:
        from cert_watch.database.users_roles import SqliteRoleRepository

        _role_repo = SqliteRoleRepository(db_path)
        for _role in _role_repo.list_all():
            if _role.alert_group_id and _role.scope_tag:
                role_links.append({
                    "alert_group_id": _role.alert_group_id,
                    "scope_tags": parse_tags(_role.scope_tag),
                })
    except (sqlite3.OperationalError, sqlite3.DatabaseError, ImportError):
        logger.warning("Role→alert-group link routing unavailable", exc_info=True)
        role_links = []

    group_by_id = {g["id"]: g for g in groups}

    recipients_map: dict[str, list[str]] = {}
    thresholds_map: dict[str, int | None] = {}
    for cert_id, effective in cert_tags.items():
        seen: set[str] = set()
        out: list[str] = []
        manual_ids = manual_map.get(cert_id, set())
        for g in groups:
            if g["id"] in manual_ids or tags_match(effective, g["match_tags"]):
                for r in g["recipients"]:
                    rc = r.casefold()
                    if rc not in seen:
                        seen.add(rc)
                        out.append(r)
                td = g["threshold_days"]
                if td is not None:
                    existing = thresholds_map.get(cert_id)
                    if existing is None or td < existing:
                        thresholds_map[cert_id] = td

        # Role-linked alert groups (WI-061): match certs against role
        # scope_tags and include the linked alert_group's recipients.
        for rl in role_links:
            if tags_match(effective, rl["scope_tags"]):
                lg = group_by_id.get(rl["alert_group_id"])
                if lg is None:
                    continue
                for r in lg["recipients"]:
                    rc = r.casefold()
                    if rc not in seen:
                        seen.add(rc)
                        out.append(r)
                td = lg["threshold_days"]
                if td is not None:
                    existing = thresholds_map.get(cert_id)
                    if existing is None or td < existing:
                        thresholds_map[cert_id] = td

        if out:
            recipients_map[cert_id] = out
    return recipients_map, thresholds_map


def resolve_all_group_recipients(
    db_path: str | Path,
) -> dict[str, list[str]]:
    """Return {cert_id: [recipients]} for all leaf certs in one pass.

    Uses three targeted SQL queries instead of per-cert N+1 resolution.
    Results are identical to calling resolve_group_recipients() per cert.
    """
    recipients_map, _ = _resolve_group_config(db_path)
    return recipients_map


def resolve_group_thresholds(
    db_path: str | Path,
) -> dict[str, int | None]:
    """Return {cert_id: threshold_days} for certs matching groups with threshold_days set.

    When a cert matches multiple groups with threshold_days, the most urgent
    (smallest) threshold wins. Certs matching only groups without threshold_days
    are absent from the result (caller falls back to per-host or global defaults).
    """
    _, thresholds_map = _resolve_group_config(db_path)
    return thresholds_map


def resolve_group_recipients(
    db_path: str | Path,
    cert_id: str,
) -> list[str]:
    """Resolve alert-group recipients for a single cert (delegates to the batch path).

    Kept as a thin wrapper so callers that need one cert's recipients get the
    exact same result as the batch resolver — the two paths cannot diverge.
    """
    return resolve_all_group_recipients(db_path).get(cert_id, [])


def _build_digest_message(
    certs: list[dict[str, Any]], *, owner_name: str | None = None
) -> tuple[str, str]:
    lines = [
        f"[cert-watch] Expiry Digest — {len(certs)} certificate(s) expiring within 30 days",
        "",
    ]
    if owner_name:
        lines.insert(1, "You are receiving this digest as the owner of the following certificates.")
        lines.insert(2, "")
    for cert in certs:
        host = f"{cert['hostname']}:{cert['port']}" if cert["hostname"] else "(uploaded)"
        status = "EXPIRED" if cert["days_remaining"] < 0 else f"{cert['days_remaining']}d remaining"
        lines.append(f"  - {cert['subject']} ({host}) — {status} — expires {cert['not_after']}")
    message = "\n".join(lines)
    subject = f"[cert-watch] Expiry Digest: {len(certs)} cert(s) expiring soon"
    return message, subject


def _open_smtp_connection(
    config: AlertConfig, *, alert: Alert | None = None
) -> smtplib.SMTP | smtplib.SMTP_SSL | None:
    ssrf_err = _check_smtp_ssrf(config)
    if ssrf_err is not None:
        logger.warning("smtp host %s blocked by SSRF policy", config.smtp_host)
        if alert is not None:
            alert.error_message = "smtp host blocked by SSRF policy"
        return None
    # Pin the resolved IP to close the DNS-rebinding TOCTOU window between
    # validate_smtp_host (SSRF check) and smtplib's own getaddrinfo.  We connect
    # to the pinned IP but override _host to the original hostname so TLS
    # certificate verification (STARTTLS) uses the correct SNI.
    import socket as _socket

    pinned_ip: str | None = None
    try:
        infos = _socket.getaddrinfo(config.smtp_host, config.smtp_port, proto=_socket.IPPROTO_TCP)
        for _fam, _type, _proto, _canon, sockaddr in infos:
            pinned_ip = str(sockaddr[0])
            break
    except _socket.gaierror:
        pass  # let smtplib fail naturally
    s: smtplib.SMTP_SSL | smtplib.SMTP | None = None
    try:
        if pinned_ip:
            if config.smtp_port == 465:
                # SMTP_SSL wraps TLS during connect(); we can't override _host
                # after connect. Fall back to hostname-based connect for TLS
                # correctness — the TOCTOU window is milliseconds for an
                # admin-configured host.
                s = smtplib.SMTP_SSL(config.smtp_host, config.smtp_port, timeout=15)
            else:
                # Connect to the pinned IP, then set _host to the original
                # hostname so starttls() uses the correct server_hostname.
                s = smtplib.SMTP(timeout=15)
                s.connect(pinned_ip, config.smtp_port)
                s._host = config.smtp_host  # type: ignore[attr-defined]
        else:
            if config.smtp_port == 465:
                s = smtplib.SMTP_SSL(config.smtp_host, config.smtp_port, timeout=15)
            else:
                s = smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=15)
        if not negotiate_starttls(s, config.smtp_port, bool(config.smtp_user)):
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
        logger.warning("SMTP connect failed: %s", sanitized)
        if alert is not None:
            alert.error_message = sanitized
        if s is not None:
            with contextlib.suppress(Exception):
                s.quit()
        return None


def _build_digest_email(
    certs: list[dict[str, Any]],
    recipients: list[str],
    from_addr: str,
    *,
    owner_name: str | None = None,
) -> EmailMessage:
    message, subject = _build_digest_message(certs, owner_name=owner_name)
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = ", ".join(recipients)
    msg.set_content(message)
    return msg


def _send_digest_smtp(
    certs: list[dict[str, Any]],
    recipients: list[str],
    config: AlertConfig,
    *,
    owner_name: str | None = None,
    _conn: smtplib.SMTP | smtplib.SMTP_SSL | None = None,
) -> bool:
    msg = _build_digest_email(certs, recipients, config.from_addr, owner_name=owner_name)
    if _conn is not None:
        try:
            _conn.send_message(msg)
            return True
        except Exception as exc:  # noqa: BLE001 — SMTP send, external service, AC-06
            logger.warning("digest email failed: %s", _sanitize_smtp_error(str(exc), config))
            return False
    for _ in backoff_range(ALERT_MAX_RETRIES - 1, ALERT_RETRY_DELAY, strategy="linear"):
        try:
            conn = _open_smtp_connection(config)
            if conn is None:
                continue
            try:
                conn.send_message(msg)
                return True
            finally:
                with contextlib.suppress(Exception):
                    conn.quit()
        except Exception as exc:  # noqa: BLE001 — SMTP retry loop, external service
            logger.warning("digest email failed: %s", _sanitize_smtp_error(str(exc), config))
    return False


def _send_digest_webhook(
    certs: list[dict[str, Any]],
    webhook_config: WebhookConfig,
) -> bool:
    """Dispatch expiry digest through the adapter registry.

    Creates a synthetic ``Alert`` so the digest is formatted correctly for
    Discord, Teams, PagerDuty, Alertmanager, and Slack (not raw JSON).
    """
    from cert_watch.database import Alert

    message, subject = _build_digest_message(certs)
    alert = Alert(
        cert_id=f"digest:{len(certs)}",
        alert_type="expiry_digest",
        status="pending",
        message=message,
        threshold_days=None,
        subject=subject,
    )
    return send_webhook(alert, webhook_config)


def send_expiry_digest(
    db_path: str | Path,
    config: AlertConfig | None,
    webhook_config: WebhookConfig | None = None,
    *,
    cadence_days: int = 30,
) -> bool:
    """Send expiry digest: one per owner (their certs only) + one global (all certs).

    Owners identified via host owner_email. If an owner is also in config.recipients
    they receive only the global digest (no duplicate). Returns True only when all
    deliveries succeeded; False on total or partial failure.
    """
    from cert_watch.database import _connect, _parse_iso

    if config is None and webhook_config is None:
        return False

    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT c.id, c.subject, c.hostname, c.port, c.not_after, "
            "h.owner_email, h.owner_name "
            "FROM certificates c "
            "LEFT JOIN hosts h ON c.hostname = h.hostname AND c.port = h.port "
            "WHERE c.is_leaf = 1 ORDER BY c.not_after"
        ).fetchall()

    now = datetime.now(UTC)
    expiring: list[dict[str, Any]] = []
    for r in rows:
        na = _parse_iso(r["not_after"])
        days = (na - now).days
        if days <= cadence_days:
            expiring.append({
                "subject": r["subject"],
                "hostname": r["hostname"] or "",
                "port": r["port"] or 443,
                "not_after": r["not_after"],
                "days_remaining": days,
                "owner_email": dict(r).get("owner_email") or "",
                "owner_name": dict(r).get("owner_name") or "",
            })

    if not expiring:
        return True

    global_recipients_cf: set[str] = set()
    global_recipients_original: list[str] = []
    if config is not None:
        seen: set[str] = set()
        for r in config.recipients:
            if not _validate_email(r):
                continue
            cf = r.casefold()
            if cf not in seen:
                seen.add(cf)
                global_recipients_original.append(r)
        global_recipients_cf = seen

    original_emails: dict[str, str] = {}
    owner_names: dict[str, str] = {}
    for cert in expiring:
        oe = cert["owner_email"]
        if oe:
            cf = oe.casefold()
            original_emails.setdefault(cf, oe)
            on = cert.get("owner_name", "")
            if on and cf not in owner_names:
                owner_names[cf] = on

    owner_certs: dict[str, list[dict[str, Any]]] = {}
    for cert in expiring:
        oe = cert["owner_email"]
        cf = oe.casefold() if oe else ""
        if cf and cf not in global_recipients_cf:
            owner_certs.setdefault(cf, []).append(cert)

    any_smtp_success = False
    any_smtp_failure = False

    if config is not None:
        smtp_conn = _open_smtp_connection(config)
        if smtp_conn is not None:
            try:
                if global_recipients_cf:
                    msg = _build_digest_email(
                        expiring, global_recipients_original, config.from_addr,
                    )
                    try:
                        smtp_conn.send_message(msg)
                        any_smtp_success = True
                    except Exception as exc:  # noqa: BLE001 — SMTP send, external service, AC-06
                        logger.warning(
                            "global digest failed: %s",
                            _sanitize_smtp_error(str(exc), config),
                        )
                        any_smtp_failure = True
                for cf_email, certs in owner_certs.items():
                    original = original_emails.get(cf_email, cf_email)
                    oname = owner_names.get(cf_email)
                    msg = _build_digest_email(
                        certs, [original], config.from_addr, owner_name=oname,
                    )
                    try:
                        smtp_conn.send_message(msg)
                        any_smtp_success = True
                    except Exception as exc:  # noqa: BLE001 — SMTP send, external service, AC-06
                        logger.warning(
                            "owner digest for %s failed: %s",
                            original,
                            _sanitize_smtp_error(str(exc), config),
                        )
                        any_smtp_failure = True
            finally:
                with contextlib.suppress(Exception):
                    smtp_conn.quit()
        else:
            if global_recipients_cf:
                if _send_digest_smtp(
                    expiring, global_recipients_original, config,
                ):
                    any_smtp_success = True
                else:
                    any_smtp_failure = True
            for cf_email, certs in owner_certs.items():
                original = original_emails.get(cf_email, cf_email)
                oname = owner_names.get(cf_email)
                if _send_digest_smtp(
                    certs, [original], config, owner_name=oname,
                ):
                    any_smtp_success = True
                else:
                    any_smtp_failure = True

    if any_smtp_success and not any_smtp_failure:
        return True

    if webhook_config is not None:
        return _send_digest_webhook(expiring, webhook_config)

    return False


def process_pending(
    alert_repo: AlertRepository,
    config: AlertConfig | None,
    webhook_config: WebhookConfig | None = None,
) -> dict[str, int]:
    """See AC-04. No-ops when both configs are None. Tries webhook if SMTP fails or is absent.

    Failed deliveries are retried up to ALERT_MAX_RETRIES times with a short delay.
    """
    if config is None and webhook_config is None:
        return {"sent": 0, "failed": 0}
    sent = 0
    failed = 0
    for alert in alert_repo.list_pending():
        delivered = False
        last_error = ""
        for _ in backoff_range(ALERT_MAX_RETRIES - 1, ALERT_RETRY_DELAY, strategy="linear"):
            if config is not None:
                delivered = send_alert(alert, config)
            if not delivered and webhook_config is not None:
                delivered = send_webhook(alert, webhook_config)
            if delivered:
                break
            last_error = alert.error_message or "unknown"
        if delivered:
            alert.sent_at = datetime.now(UTC)
            alert_repo.mark_sent(alert.id)
            sent += 1
        else:
            alert_repo.mark_failed(
                alert.id, f"{last_error} (after {ALERT_MAX_RETRIES} attempts)"
            )
            failed += 1
    return {"sent": sent, "failed": failed}
