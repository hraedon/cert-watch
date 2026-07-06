"""Renewal digest — volume-shaped reporting (WI-3.1 / Plan 048)."""
from __future__ import annotations

import concurrent.futures
import json
import logging
import sqlite3
import statistics
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from cert_watch.alerts import _validate_email
from cert_watch.database.connection import _connect
from cert_watch.database.schema import init_schema

if TYPE_CHECKING:
    from cert_watch.alerts import AlertConfig, WebhookConfig

logger = logging.getLogger(__name__)

_digest_pool = concurrent.futures.ThreadPoolExecutor(
    max_workers=2, thread_name_prefix="cw-digest",
)
_digest_pool_lock = threading.Lock()


def _flush_digest_pool() -> None:
    """Wait for all pending digest webhook tasks to finish (test helper)."""
    global _digest_pool
    with _digest_pool_lock:
        _digest_pool.shutdown(wait=True)
        _digest_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=2, thread_name_prefix="cw-digest",
        )


def shutdown_digest_pool() -> None:
    """Shut down the digest webhook pool (called from stop_scheduler)."""
    global _digest_pool
    with _digest_pool_lock:
        _digest_pool.shutdown(wait=True)
        _digest_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=2, thread_name_prefix="cw-digest",
        )


@dataclass
class RenewalDigest:
    days: int
    renewed_count: int
    renewed_hosts: list[str]
    overdue_count: int
    overdue_hosts: list[str]
    shortened_count: int
    shortened_hosts: list[str]
    owner_email: str = ""


def _parse_event_payload(payload_raw: str) -> dict[str, Any]:
    try:
        return cast(dict[str, Any], json.loads(payload_raw))
    except (json.JSONDecodeError, TypeError):
        return {}


def _lifetime_trend_decreasing(entries: list[dict[str, Any]]) -> bool:
    if len(entries) < 2:
        return False
    lifetimes: list[int] = []
    for entry in entries:
        not_after = entry.get("not_after")
        not_before = entry.get("not_before")
        if not_after and not_before:
            from cert_watch.database.connection import _parse_iso
            try:
                na = _parse_iso(not_after)
                nb = _parse_iso(not_before)
                lifetimes.append((na - nb).days)
            except (ValueError, TypeError):
                pass
    if len(lifetimes) < 2:
        return False
    mid = len(lifetimes) // 2
    first_half = lifetimes[:mid] if mid else lifetimes[:1]
    second_half = lifetimes[mid:] if mid else lifetimes[-1:]
    avg_first = statistics.mean(first_half)
    avg_second = statistics.mean(second_half)
    threshold = max(avg_first * 0.05, 1)
    return avg_second < avg_first - threshold


def build_renewal_digest(
    db_path: str | Path, days: int = 7, *, cadence_days: int | None = None,
) -> list[RenewalDigest]:
    """Query event_log for cert_renewed and renewal_overdue events from the
    last *days* days, group by owner, and produce per-owner RenewalDigest objects.
    Zero-activity periods produce an empty list (no empty noise).
    """
    effective_days = cadence_days if cadence_days is not None else days
    init_schema(db_path)
    cutoff = (datetime.now(UTC) - timedelta(days=effective_days)).isoformat()

    with _connect(db_path) as conn:
        renewed_rows = conn.execute(
            """SELECT payload FROM event_log
               WHERE event_type = 'cert_renewed'
               AND timestamp >= ?""",
            (cutoff,),
        ).fetchall()
        overdue_rows = conn.execute(
            """SELECT payload FROM event_log
               WHERE event_type = 'renewal_overdue'
               AND timestamp >= ?""",
            (cutoff,),
        ).fetchall()

    renewed_by_host: dict[str, int] = {}
    renewed_hosts_set: set[str] = set()
    for row in renewed_rows:
        payload = _parse_event_payload(row["payload"])
        hostname = payload.get("hostname", "")
        if hostname:
            renewed_by_host[hostname] = renewed_by_host.get(hostname, 0) + 1
            renewed_hosts_set.add(hostname)

    overdue_by_host: dict[str, int] = {}
    overdue_hosts_set: set[str] = set()
    for row in overdue_rows:
        payload = _parse_event_payload(row["payload"])
        hostname = payload.get("hostname", "")
        if hostname:
            overdue_by_host[hostname] = overdue_by_host.get(hostname, 0) + 1
            overdue_hosts_set.add(hostname)

    if not renewed_hosts_set and not overdue_hosts_set:
        return []

    host_owners: dict[str, str] = {}
    host_entries: dict[str, list[dict[str, Any]]] = {}
    with _connect(db_path) as conn:
        for row in conn.execute("SELECT hostname, owner_email FROM hosts").fetchall():
            host_owners[row["hostname"]] = row["owner_email"] or ""
        all_hosts = sorted(renewed_hosts_set | overdue_hosts_set)
        for hostname in all_hosts:
            cert_rows = conn.execute(
                """SELECT not_after, not_before
                   FROM cert_history
                   WHERE hostname = ?
                   ORDER BY scanned_at DESC
                   LIMIT 10""",
                (hostname,),
            ).fetchall()
            host_entries[hostname] = [dict(r) for r in cert_rows]

    shortened_hosts = set()
    for hostname, entries in host_entries.items():
        if _lifetime_trend_decreasing(entries):
            shortened_hosts.add(hostname)

    by_owner: dict[str, RenewalDigest] = {}

    def _ensure_owner(email: str) -> RenewalDigest:
        if email not in by_owner:
            by_owner[email] = RenewalDigest(
                days=effective_days,
                renewed_count=0,
                renewed_hosts=[],
                overdue_count=0,
                overdue_hosts=[],
                shortened_count=0,
                shortened_hosts=[],
                owner_email=email,
            )
        return by_owner[email]

    for hostname, count in renewed_by_host.items():
        owner = host_owners.get(hostname, "")
        d = _ensure_owner(owner)
        d.renewed_count += count
        if hostname not in d.renewed_hosts:
            d.renewed_hosts.append(hostname)

    for hostname, count in overdue_by_host.items():
        owner = host_owners.get(hostname, "")
        d = _ensure_owner(owner)
        d.overdue_count += count
        if hostname not in d.overdue_hosts:
            d.overdue_hosts.append(hostname)

    for hostname in shortened_hosts:
        owner = host_owners.get(hostname, "")
        d = _ensure_owner(owner)
        d.shortened_count += 1
        if hostname not in d.shortened_hosts:
            d.shortened_hosts.append(hostname)

    return list(by_owner.values())


def _build_digest_message(digest: RenewalDigest) -> str:
    lines = [
        f"[cert-watch] Renewal Digest — last {digest.days} days",
        "",
        f"Renewed on schedule: {digest.renewed_count}",
    ]
    if digest.renewed_hosts:
        for h in digest.renewed_hosts:
            lines.append(f"  - {h}")
    lines.append("")
    lines.append(f"Overdue: {digest.overdue_count}")
    if digest.overdue_hosts:
        for h in digest.overdue_hosts:
            lines.append(f"  - {h}")
    if digest.shortened_hosts:
        lines.append("")
        lines.append(f"Lifetimes shortened: {digest.shortened_count}")
        for h in digest.shortened_hosts:
            lines.append(f"  - {h}")
    return "\n".join(lines)


def _admin_emails(db_path: str | Path) -> list[str]:
    """Emails of users whose role is permission_tier == 'admin' (deduped, order
    preserved). Empty if local auth / roles are unavailable.
    """
    try:
        from cert_watch.database.users_roles import (
            SqliteRoleRepository,
            SqliteUserRepository,
        )

        admin_role_ids = {
            r.id
            for r in SqliteRoleRepository(db_path).list_all()
            if (r.permission_tier or "viewer") == "admin"
        }
        seen: set[str] = set()
        emails: list[str] = []
        for u in SqliteUserRepository(db_path).list_all():
            if u.role_id in admin_role_ids and u.email and u.email.casefold() not in seen:
                seen.add(u.email.casefold())
                emails.append(u.email)
        return emails
    except (ImportError, sqlite3.Error):  # roles table missing or local-auth extra absent
        logger.warning("admin email lookup unavailable", exc_info=True)
        return []


def _build_orphan_message(orphans: list[dict[str, Any]]) -> str:
    lines = [
        f"[cert-watch] Orphaned certificates — no alert routing ({len(orphans)})",
        "",
        "These certificates match no alert group and have no host owner, so they",
        "route to no specific recipient — they fall back to the global recipient",
        "list and are the ones most likely to be silently missed. Assign a tag /",
        "alert group or a host owner to route them deliberately.",
        "",
    ]
    for o in orphans:
        host = o.get("hostname") or "?"
        port = o.get("port")
        where = f"{host}:{port}" if port else host
        lines.append(f"  - [orphan] {where} — {o.get('subject') or '(no subject)'}")
    return "\n".join(lines)


def send_orphan_notice(db_path: str | Path, alert_config: AlertConfig | None) -> bool | None:
    """Email admin-tier users a flagged list of orphaned certs (no alert routing).

    Part of the weekly digest run (Plan 050, decision pinned 2026-06-20): admins
    get standing visibility into certs that resolve to nobody specific, even in a
    week with no renewal activity. Returns ``None`` when there is nothing to send
    (no orphans, no admin recipients, or no SMTP config), ``True`` on delivery,
    ``False`` on SMTP failure. Delivers nothing else; mutates nothing.
    """
    import contextlib
    from email.message import EmailMessage

    from cert_watch.alerts import (
        AlertConfig,
        _open_smtp_connection,
        _sanitize_smtp_error,
        _validate_email,
        find_orphan_certs,
    )

    if not isinstance(alert_config, AlertConfig):
        return None
    orphans = find_orphan_certs(db_path)
    if not orphans:
        return None
    admins = [a for a in _admin_emails(db_path) if _validate_email(a)]
    if not admins:
        return None

    msg = EmailMessage()
    msg["Subject"] = (
        f"[cert-watch] {len(orphans)} orphaned certificate(s) — no alert routing"
    )
    msg["From"] = alert_config.from_addr
    msg["To"] = ", ".join(admins)
    msg.set_content(_build_orphan_message(orphans))

    conn = _open_smtp_connection(alert_config)
    if conn is None:
        return False
    try:
        conn.send_message(msg)
        return True
    except Exception as exc:  # noqa: BLE001 — SMTP failures must not raise
        logger.warning(
            "orphan notice delivery failed: %s",
            _sanitize_smtp_error(str(exc), alert_config),
        )
        return False
    finally:
        with contextlib.suppress(Exception):
            conn.quit()


def _send_digest_email_msg(
    msg: EmailMessage,
    config: AlertConfig,
) -> bool:
    """Send a pre-built EmailMessage via SMTP with retry.

    Unlike ``_send_digest_smtp`` (which constructs its own message from cert
    data), this sends an already-built message — needed for the renewal digest
    where the body is a textual summary, not a per-cert expiry listing.
    """
    import contextlib

    from cert_watch.alerts import (
        ALERT_MAX_RETRIES,
        ALERT_RETRY_DELAY,
        _open_smtp_connection,
        _sanitize_smtp_error,
        backoff_range,
    )

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
            logger.warning(
                "renewal digest email failed: %s",
                _sanitize_smtp_error(str(exc), config),
            )
    return False


def send_renewal_digest(
    db_path: str | Path,
    alert_config: AlertConfig | None,
    webhook_config: WebhookConfig | None = None,
    *,
    days: int = 7,
    cadence_days: int | None = None,
) -> bool:
    """Build and send the renewal digest through the existing alert pipeline.

    When SMTP and webhook configs are both absent, returns False.
    Sends one digest per owner plus one global digest for unowned hosts.
    For SMTP delivery, returns True only when all deliveries succeeded.
    For webhook delivery, returns True after submitting to the thread pool
    (delivery happens asynchronously; failures are logged, not surfaced).
    """
    from cert_watch.alerts import (
        AlertConfig,
        WebhookConfig,
        _open_smtp_connection,
        _sanitize_smtp_error,
    )
    from cert_watch.database import Alert

    if alert_config is None and webhook_config is None:
        return False

    # Surface orphaned certs (no alert routing) to admins as part of the digest
    # run — independent of renewal activity, so a quiet week still flags them.
    # Logs its own failures; does not gate the renewal-digest return value.
    send_orphan_notice(db_path, alert_config)

    digests = build_renewal_digest(db_path, days=days, cadence_days=cadence_days)
    if not digests:
        return True

    global_recipients_cf: set[str] = set()
    global_recipients_original: list[str] = []
    if isinstance(alert_config, AlertConfig):
        seen: set[str] = set()
        for r in alert_config.recipients:
            if not _validate_email(r):
                logger.warning("skipping invalid digest recipient: %r", r)
                continue
            cf = r.casefold()
            if cf not in seen:
                seen.add(cf)
                global_recipients_original.append(r)
        global_recipients_cf = seen

    owner_digests: dict[str, RenewalDigest] = {}
    for d in digests:
        if not _validate_email(d.owner_email):
            logger.warning("skipping invalid owner_email digest: %r", d.owner_email)
            continue
        cf = d.owner_email.casefold()
        if cf and cf not in global_recipients_cf:
            owner_digests.setdefault(cf, d)

    any_smtp_success = False
    any_smtp_failure = False

    if isinstance(alert_config, AlertConfig):
        smtp_conn = _open_smtp_connection(alert_config)
        if smtp_conn is not None:
            try:
                # Global digest: aggregate all owner digests into one fleet summary.
                global_digest = RenewalDigest(
                    days=days,
                    renewed_count=sum(d.renewed_count for d in digests),
                    renewed_hosts=sorted({h for d in digests for h in d.renewed_hosts}),
                    overdue_count=sum(d.overdue_count for d in digests),
                    overdue_hosts=sorted({h for d in digests for h in d.overdue_hosts}),
                    shortened_count=sum(d.shortened_count for d in digests),
                    shortened_hosts=sorted({h for d in digests for h in d.shortened_hosts}),
                )
                global_body = _build_digest_message(global_digest)
                global_subject = (
                    f"[cert-watch] Renewal Digest: "
                    f"{global_digest.renewed_count} renewed, "
                    f"{global_digest.overdue_count} overdue"
                )
                from email.message import EmailMessage
                global_msg = EmailMessage()
                global_msg["Subject"] = global_subject
                global_msg["From"] = alert_config.from_addr
                global_msg["To"] = ", ".join(global_recipients_original)
                global_msg.set_content(global_body)
                try:
                    smtp_conn.send_message(global_msg)
                    any_smtp_success = True
                except Exception as exc:
                    logger.warning(
                        "global renewal digest failed: %s",
                        _sanitize_smtp_error(str(exc), alert_config),
                    )
                    any_smtp_failure = True
                for cf_email, od in owner_digests.items():
                    body = _build_digest_message(od)
                    subject = (
                        f"[cert-watch] Renewal Digest: "
                        f"{od.renewed_count} renewed, {od.overdue_count} overdue"
                    )
                    m = EmailMessage()
                    m["Subject"] = subject
                    m["From"] = alert_config.from_addr
                    m["To"] = cf_email
                    m.set_content(body)
                    try:
                        smtp_conn.send_message(m)
                        any_smtp_success = True
                    except Exception as exc:
                        logger.warning(
                            "owner digest for %s failed: %s",
                            cf_email,
                            _sanitize_smtp_error(str(exc), alert_config),
                        )
                        any_smtp_failure = True
            finally:
                import contextlib
                with contextlib.suppress(Exception):
                    smtp_conn.quit()
        else:
            for cf_email, od in owner_digests.items():
                body = _build_digest_message(od)
                subject = (
                    f"[cert-watch] Renewal Digest: "
                    f"{od.renewed_count} renewed, {od.overdue_count} overdue"
                )
                from email.message import EmailMessage
                m = EmailMessage()
                m["Subject"] = subject
                m["From"] = alert_config.from_addr
                m["To"] = cf_email
                m.set_content(body)
                if _send_digest_email_msg(m, alert_config):
                    any_smtp_success = True
                else:
                    any_smtp_failure = True

    if any_smtp_success and not any_smtp_failure:
        return True

    if any_smtp_failure:
        return False

    if isinstance(webhook_config, WebhookConfig):
        from cert_watch.alerts import ALERT_MAX_RETRIES, ALERT_RETRY_DELAY, send_webhook
        from cert_watch.retry import backoff_range

        def _deliver_digest_webhook(od: RenewalDigest) -> None:
            body = _build_digest_message(od)
            alert = Alert(
                cert_id=f"renewal-digest:{days}",
                alert_type="renewal_digest",
                status="pending",
                message=body,
                threshold_days=None,
                hostname="",
                subject=f"Renewal Digest ({days}d)",
            )
            for _ in backoff_range(
                ALERT_MAX_RETRIES - 1, ALERT_RETRY_DELAY, strategy="linear"
            ):
                if send_webhook(alert, webhook_config):
                    return
            logger.warning(
                "renewal digest webhook failed after %d attempts",
                ALERT_MAX_RETRIES,
            )

        for od in digests:
            try:
                with _digest_pool_lock:
                    _digest_pool.submit(_deliver_digest_webhook, od)
            except Exception:
                logger.warning(
                    "digest webhook pool submit failed; delivering inline",
                    exc_info=True,
                )
                _deliver_digest_webhook(od)
        return True

    return False
