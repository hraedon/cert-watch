"""Email and webhook alerts. See spec wi_fr04_alerts.md."""

from __future__ import annotations

import contextlib
import json
import logging
import smtplib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.message import EmailMessage
from pathlib import Path

from cert_watch.certificate_model import Certificate
from cert_watch.database import Alert, AlertRepository
from cert_watch.http_client import SSRFBlockedError, ssrf_safe_urlopen
from cert_watch.retry import backoff_range

logger = logging.getLogger("cert_watch.alerts")

LEAF_THRESHOLDS = (14, 7, 3, 1)
CHAIN_THRESHOLDS = (30, 14, 7)


@dataclass
class AlertConfig:
    """SMTP configuration. See AC-01."""

    smtp_host: str
    smtp_user: str
    smtp_password: str
    from_addr: str
    recipients: list[str] = field(default_factory=list)
    smtp_port: int = 587


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
    cooldown_hours: int = 24,
    owner_info: dict | None = None,
    extra_recipients: list[str] | None = None,
    hostname: str = "",
) -> list[Alert]:
    """
    Create pending alerts for thresholds the cert has now crossed, skipping any
    threshold that already has an alert recorded for this cert. See AC-02.

    Escalation: if the most recent alert for a threshold is older than
    cooldown_hours and the cert still crosses that threshold, a new alert
    is created. This ensures persistent expiry issues get re-alerted while
    avoiding noise from repeated alerts within the cooldown window.

    The spec talks about cert_id as the link to existing alerts; we accept it as
    a kwarg so callers that persisted the cert can pass the row id. If omitted we
    use fingerprint_sha256 as a stable handle.

    If custom_thresholds is provided, those are used instead of the defaults.

    If extra_recipients is provided, those addresses are used as the alert's
    extra_recipients (merged from alert-group routing). Otherwise, the
    owner_info["owner_email"] is used (backward-compatible behavior).
    """
    days = cert.days_until_expiry()
    if custom_thresholds is not None:
        thresholds = custom_thresholds
    else:
        thresholds = LEAF_THRESHOLDS if cert.is_leaf else CHAIN_THRESHOLDS
    cid = cert_id or cert.fingerprint_sha256
    now = datetime.now(UTC)

    # Find existing alerts for this cert and their thresholds.
    # Track the most recent alert time per threshold for cooldown logic.
    existing_thresholds: set[int] = set()
    latest_alert_by_threshold: dict[int, datetime] = {}
    cert_alerts = (
        alert_repo.list_for_cert(cid)
        if hasattr(alert_repo, "list_for_cert")
        else [a for a in alert_repo.list_pending() if a.cert_id == cid]
    )
    for a in cert_alerts:
        if a.threshold_days is not None:
            existing_thresholds.add(a.threshold_days)
            prev_latest = latest_alert_by_threshold.get(
                a.threshold_days, datetime.min.replace(tzinfo=UTC)
            )
            if a.created_at > prev_latest:
                latest_alert_by_threshold[a.threshold_days] = a.created_at

    created: list[Alert] = []
    for t in thresholds:
        # Suppress alerts when renewal is complete — certs renewed don't need
        # re-alerting until the next threshold window opens.
        if owner_info and owner_info.get("renewal_status") == "renewed":
            continue
        # Floor semantics: days_until_expiry() returns floor(delta), so a
        # cert with 1d23h remaining shows days=1 and crosses the t=1 threshold.
        # This means a threshold can fire up to ~23h before the nominal expiry
        # day; acceptable because thresholds are calendar-day aligned.
        if days <= t:
            # Check cooldown: skip if a recent alert exists for this threshold
            if t in existing_thresholds:
                last_alert_time = latest_alert_by_threshold.get(t)
                cooldown_secs = cooldown_hours * 3600
                if (
                    last_alert_time
                    and (now - last_alert_time).total_seconds() < cooldown_secs
                ):
                    continue
            alert = Alert(
                cert_id=cid,
                alert_type="expired" if days < 0 else "expiry_warning",
                status="pending",
                message=_format_message(cert, days, t, owner_info=owner_info),
                threshold_days=t,
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
            created.append(alert)
            existing_thresholds.add(t)
    return created


def evaluate_all_certs(
    db_path: str | Path, alert_repo: AlertRepository
) -> list[Alert]:
    """Evaluate thresholds for all leaf certificates in the database.

    Looks up per-host custom thresholds and owner/contact info from the hosts
    table and passes them through to evaluate_thresholds. Also resolves
    alert-group recipients based on effective tags and manual assignment.
    """
    from cert_watch.database import _connect, _parse_iso

    with _connect(db_path) as conn:
        host_thresholds: dict[tuple[str, int], int | None] = {}
        host_owners: dict[tuple[str, int], dict] = {}
        for row in conn.execute("SELECT * FROM hosts").fetchall():
            key = (row["hostname"], row["port"])
            host_thresholds[key] = row["threshold_days"]
            host_owners[key] = {
                "owner_name": dict(row).get("owner_name", ""),
                "owner_email": dict(row).get("owner_email", ""),
                "owner_slack": dict(row).get("owner_slack", ""),
                "renewal_status": dict(row).get("renewal_status", "pending"),
            }

        leaves = conn.execute(
            "SELECT * FROM certificates WHERE is_leaf = 1"
        ).fetchall()

    # Batch-resolve group recipients for all certs in ≤3 queries
    all_group_recipients = resolve_all_group_recipients(db_path)

    # Role-based alert routing: users in a role get alerts for certs owned by
    # the role's team email (host.owner_email matches role.email).
    from cert_watch.database.users_roles import SqliteRoleRepository, SqliteUserRepository

    role_user_emails: dict[str, list[str]] = {}
    try:
        _role_repo = SqliteRoleRepository(db_path)
        _user_repo = SqliteUserRepository(db_path)
        _all_users = _user_repo.list_all()
        for _role in _role_repo.list_all():
            if _role.email:
                _users_in_role = [
                    u for u in _all_users
                    if u.role_id == _role.id and u.email
                ]
                if _users_in_role:
                    role_user_emails[_role.email.casefold()] = [u.email for u in _users_in_role]
    except Exception:
        logger.debug("Role-based alert routing unavailable", exc_info=True)
        role_user_emails = {}

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
            raw_der=bytes(leaf_row["raw_der"]),
            is_leaf=True,
        )
        custom = None
        hostname = leaf_row["hostname"]
        port = leaf_row["port"]
        owner_info: dict | None = None
        if hostname and port:
            host_td = host_thresholds.get((hostname, port))
            if host_td is not None:
                custom = (host_td, max(host_td // 2, 1), max(host_td // 4, 1))
            owner_info = host_owners.get((hostname, port))

        # Resolve alert-group recipients for this cert (batch result)
        group_recipients = all_group_recipients.get(leaf_row["id"], [])

        # Merge group recipients with owner email into extra_recipients
        merged_extra: list[str] = list(group_recipients)
        if owner_info and owner_info.get("owner_email"):
            oe = owner_info["owner_email"]
            if oe not in merged_extra:
                merged_extra.append(oe)

        # Add user emails from the role whose email matches the host's owner_email
        if owner_info and owner_info.get("owner_email"):
            role_emails = role_user_emails.get(owner_info["owner_email"].casefold(), [])
            for re in role_emails:
                if re not in merged_extra:
                    merged_extra.append(re)

        alerts = evaluate_thresholds(
            cert, alert_repo, cert_id=leaf_row["id"], custom_thresholds=custom,
            owner_info=owner_info, extra_recipients=merged_extra or None,
            hostname=leaf_row["hostname"] or "",
        )
        all_alerts.extend(alerts)
    return all_alerts


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
        host_owners: dict[tuple, dict] = {}
        for row in conn.execute("SELECT * FROM hosts").fetchall():
            host_owners[(row["hostname"], row["port"])] = {
                "owner_name": dict(row).get("owner_name", ""),
                "owner_email": dict(row).get("owner_email", ""),
            }
        leaves = conn.execute("SELECT * FROM certificates WHERE is_leaf = 1").fetchall()

    created: list[Alert] = []
    for leaf in leaves:
        cid = leaf["id"]
        if cid in superseded:
            continue  # a successor cert already exists → renewal worked
        try:
            days = (_parse_iso(leaf["not_after"]) - now).days
        except Exception:
            continue
        if days < 0 or days > window_days:
            continue  # expired (expiry_warning owns it) or outside the window
        existing = (
            alert_repo.list_for_cert(cid)
            if hasattr(alert_repo, "list_for_cert")
            else [a for a in alert_repo.list_pending() if a.cert_id == cid]
        )
        if any(
            a.alert_type == "renewal_stalled" and a.status == "pending"
            for a in existing
        ):
            continue  # already flagged this window
        owner = host_owners.get((leaf["hostname"], leaf["port"]), {})
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


def _format_renewal_message(leaf, days: int, window_days: int, owner: dict) -> str:
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
    cert: Certificate, days: int, threshold: int, *, owner_info: dict | None = None
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
    all_recipients = list(config.recipients) + [
        r for r in alert.extra_recipients if r not in config.recipients
    ]
    msg["To"] = ", ".join(all_recipients)
    msg.set_content(alert.message)
    try:
        if config.smtp_port == 465:
            s: smtplib.SMTP_SSL | smtplib.SMTP = smtplib.SMTP_SSL(
                config.smtp_host, config.smtp_port, timeout=15,
            )
        else:
            s = smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=15)
        with s:
            if not negotiate_starttls(s, config.smtp_port, bool(config.smtp_user)):
                alert.error_message = (
                    "STARTTLS not supported by SMTP server; "
                    "refusing to send credentials in cleartext"
                )
                return False
            if config.smtp_user:
                s.login(config.smtp_user, config.smtp_password)
            s.send_message(msg)
        return True
    except Exception as exc:  # noqa: BLE001 — AC-06 says do not raise
        alert.error_message = _sanitize_smtp_error(str(exc), config)
        return False


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
    except Exception as exc:  # noqa: BLE001
        alert.error_message = _sanitize_webhook_error(str(exc), config)
        return False


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
    PagerDuty returns True on HTTP 202; Alertmanager and generic return
    True on 2xx. Returns False if the adapter has no ``build_resolve``.
    """
    from cert_watch.alert_adapters import get_adapter

    if config.kind not in ("pagerduty", "alertmanager"):
        return False

    try:
        adapter = get_adapter(config.kind)
        build_resolve = getattr(adapter, "build_resolve", None)
        if build_resolve is None:
            return False
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
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "%s resolve failed for cert %s: %s",
            config.kind,
            cert_id,
            _sanitize_webhook_error(str(exc), config),
        )
        return False


def send_pagerduty_resolve(
    cert_id: str,
    alert_type: str,
    threshold_days: int | None,
    config: WebhookConfig,
    *,
    summary: str = "",
) -> bool:
    """Send a PagerDuty resolve event to auto-close an incident.

    Deprecated: prefer ``send_webhook_resolve``, which dispatches
    through the adapter registry and also supports Alertmanager.
    """
    if config.kind != "pagerduty":
        return False
    return send_webhook_resolve(
        cert_id, alert_type, threshold_days, config, summary=summary,
    )


def resolve_webhook_for_renewed_cert(
    db_path: str | Path,
    old_cert_id: str,
    webhook_config: WebhookConfig | None = None,
    *,
    pending_alerts: list | None = None,
) -> int:
    """Resolve all open incidents/alerts for a cert that has been renewed.

    Works for PagerDuty and Alertmanager webhook kinds. Looks up pending
    alerts for the old cert and sends a resolve event for each unique
    (alert_type, threshold_days) combination. Returns the number of
    resolve events sent.

    When *pending_alerts* is provided (a pre-fetched list from
    :class:`SqliteAlertRepository`), uses that instead of querying the
    database — necessary when the caller knows the alert rows will be
    deleted before this function runs (e.g. ``replace_scanned``).
    """
    if webhook_config is None or webhook_config.kind not in ("pagerduty", "alertmanager"):
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


def resolve_pagerduty_for_renewed_cert(
    db_path: str | Path,
    old_cert_id: str,
    webhook_config: WebhookConfig | None = None,
) -> int:
    """Resolve all PagerDuty incidents for a cert that has been renewed.

    Delegates to ``resolve_webhook_for_renewed_cert``. Kept for backward
    compatibility with callers that import by the old name.
    """
    if webhook_config is not None and webhook_config.kind != "pagerduty":
        return 0
    return resolve_webhook_for_renewed_cert(db_path, old_cert_id, webhook_config)


ALERT_MAX_RETRIES = 3
ALERT_RETRY_DELAY = 2  # seconds between retries


def evaluate_policy_alerts(
    cert_id: str,
    hostname: str,
    violations: list,
    db_path: str | Path,
    *,
    subject: str = "",
) -> list[Alert]:
    """Create pending alerts for critical or warning policy violations.

    Info-level violations are recorded but do not generate alerts.
    Returns the list of created Alert objects.

    Deduplication: before creating a new alert for a (cert_id, rule_id)
    pair, check whether a pending ``policy_violation`` alert already exists
    for the same cert and rule_id. Only create a new alert if no matching
    pending alert is found (mirrors the cooldown logic in
    ``evaluate_thresholds``).
    """
    from cert_watch.database import SqliteAlertRepository

    alert_repo = SqliteAlertRepository(db_path)
    existing = alert_repo.list_for_cert(cert_id)
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
        alert.id = alert_repo.create(alert)
        created.append(alert)
    return created


def resolve_all_group_recipients(
    db_path: str | Path,
) -> dict[str, list[str]]:
    """Return {cert_id: [recipients]} for all leaf certs in one pass.

    Uses three targeted SQL queries instead of per-cert N+1 resolution.
    Results are identical to calling resolve_group_recipients() per cert.
    """
    from cert_watch.database.connection import _connect
    from cert_watch.tags import merge_tags, parse_tags, tags_match

    # 1. Load all groups
    groups: list[dict] = []
    with _connect(db_path) as conn:
        groups = [
            {
                "id": row["id"],
                "recipients": [r.strip() for r in row["recipients"].split(",") if r.strip()],
                "match_tags": parse_tags(row["match_tags"]),
            }
            for row in conn.execute(
                "SELECT id, recipients, match_tags FROM alert_groups"
            ).fetchall()
        ]
        if not groups:
            return {}

        # 2. Load all leaf certs with their own tags and host tags
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

        # 3. Load all manual assignments
        manual_rows = conn.execute(
            "SELECT cert_id, group_id FROM alert_group_certs"
        ).fetchall()
        manual_map: dict[str, set[str]] = {}
        for row in manual_rows:
            manual_map.setdefault(row["cert_id"], set()).add(row["group_id"])

    result: dict[str, list[str]] = {}
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
        if out:
            result[cert_id] = out
    return result


def resolve_group_recipients(
    db_path: str | Path,
    cert_id: str,
) -> list[str]:
    """Resolve alert-group recipients for a cert based on effective tags + manual assignment.

    Returns de-duped list of email addresses from all matching groups.
    A group matches if the cert's effective tags intersect the group's match_tags,
    OR the cert is manually assigned to the group.
    """
    from cert_watch.database import SqliteAlertGroupRepository, SqliteCertificateRepository
    from cert_watch.tags import tags_match

    cert_repo = SqliteCertificateRepository(db_path)
    group_repo = SqliteAlertGroupRepository(db_path)

    effective = cert_repo.effective_tags(cert_id)
    manual_ids = set(group_repo.groups_for_cert_manual(cert_id))

    seen: set[str] = set()
    out: list[str] = []
    for g in group_repo.list_all():
        if g.id in manual_ids or tags_match(effective, g.match_tags):
            for r in g.recipients:
                rc = r.casefold()
                if rc not in seen:
                    seen.add(rc)
                    out.append(r)
    return out


def _build_digest_message(certs: list[dict], *, owner_name: str | None = None) -> tuple[str, str]:
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


def _open_smtp_connection(config: AlertConfig) -> smtplib.SMTP | smtplib.SMTP_SSL | None:
    try:
        if config.smtp_port == 465:
            s: smtplib.SMTP_SSL | smtplib.SMTP = smtplib.SMTP_SSL(
                config.smtp_host, config.smtp_port, timeout=15,
            )
        else:
            s = smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=15)
        if not negotiate_starttls(s, config.smtp_port, bool(config.smtp_user)):
            logger.warning(
                "digest email aborted: STARTTLS not supported by %s:%s",
                config.smtp_host, config.smtp_port,
            )
            with contextlib.suppress(Exception):
                s.quit()
            return None
        if config.smtp_user:
            s.login(config.smtp_user, config.smtp_password)
        return s
    except Exception as exc:
        logger.warning(
            "SMTP connect failed: %s",
            _sanitize_smtp_error(str(exc), config),
        )
        return None


def _build_digest_email(
    certs: list[dict],
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
    certs: list[dict],
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
        except Exception as exc:
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
        except Exception as exc:
            logger.warning("digest email failed: %s", _sanitize_smtp_error(str(exc), config))
    return False


def _send_digest_webhook(
    certs: list[dict],
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
            "SELECT c.*, h.owner_email, h.owner_name "
            "FROM certificates c "
            "LEFT JOIN hosts h ON c.hostname = h.hostname AND c.port = h.port "
            "WHERE c.is_leaf = 1 ORDER BY c.not_after"
        ).fetchall()

    now = datetime.now(UTC)
    expiring: list[dict] = []
    for r in rows:
        na = _parse_iso(r["not_after"])
        days = (na - now).days
        if days <= 30:
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

    owner_certs: dict[str, list[dict]] = {}
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
                    except Exception as exc:
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
                    except Exception as exc:
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

    if not any_smtp_success and webhook_config is not None:
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
