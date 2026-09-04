"""Renewal digest — volume-shaped reporting (WI-3.1 / Plan 048)."""
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import logging
import sqlite3
import statistics
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from cert_watch.alerts import _validate_email
from cert_watch.database.connection import _connect, _parse_iso
from cert_watch.database.schema import init_schema

if TYPE_CHECKING:
    from cert_watch.alerts import AlertConfig, WebhookConfig

logger = logging.getLogger(__name__)

_digest_pool: concurrent.futures.ThreadPoolExecutor | None = concurrent.futures.ThreadPoolExecutor(
    max_workers=2, thread_name_prefix="cw-digest",
)
_digest_pool_lock = threading.Lock()


def _flush_digest_pool() -> None:
    """Drain pending tasks and explicitly reset the pool (test helper)."""
    global _digest_pool
    with _digest_pool_lock:
        pool = _digest_pool
        _digest_pool = None
    if pool is not None:
        pool.shutdown(wait=True)
    start_digest_pool()


def start_digest_pool() -> None:
    """Enable digest task submission for an explicit scheduler startup."""
    global _digest_pool
    with _digest_pool_lock:
        if _digest_pool is None:
            _digest_pool = concurrent.futures.ThreadPoolExecutor(
                max_workers=2, thread_name_prefix="cw-digest",
            )


def shutdown_digest_pool() -> None:
    """Terminally stop digest submissions until ``start_digest_pool``."""
    pool = _detach_digest_pool()
    if pool is not None:
        pool.shutdown(wait=True)


def _detach_digest_pool() -> concurrent.futures.ThreadPoolExecutor | None:
    """Close the submission gate immediately and return the pool to drain."""
    global _digest_pool
    with _digest_pool_lock:
        pool = _digest_pool
        _digest_pool = None
    return pool


def _submit_digest_task(fn: Callable[..., Any], *args: Any) -> bool:
    """Submit only while the pool is accepting work; never revive it implicitly."""
    with _digest_pool_lock:
        if _digest_pool is None:
            return False
        _digest_pool.submit(fn, *args)
    return True


def _webhook_channel(config: WebhookConfig) -> str:
    endpoint = config.routing_key if config.kind == "pagerduty" else config.url
    endpoint_hash = hashlib.sha256(endpoint.encode()).hexdigest()[:16]
    return f"webhook:{config.kind}:{endpoint_hash}"


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
    host_expiry: dict[str, str | None] = field(default_factory=dict)


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

    # Latest known cert expiry per host (most recent scan wins). cert_history is
    # ordered scanned_at DESC, so the first row is the newest observation.
    latest_expiry: dict[str, str | None] = {}
    for hostname, entries in host_entries.items():
        latest_expiry[hostname] = entries[0]["not_after"] if entries else None

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

    for d in by_owner.values():
        d.host_expiry = {
            h: latest_expiry.get(h)
            for h in (*d.renewed_hosts, *d.overdue_hosts, *d.shortened_hosts)
        }

    return list(by_owner.values())


def _fmt_expiry(not_after: str | None) -> str:
    """Render a cert's not_after as ' (expires YYYY-MM-DD)' or '' if unknown."""
    if not not_after:
        return ""
    try:
        return f" (expires {_parse_iso(not_after).strftime('%Y-%m-%d')})"
    except (ValueError, TypeError):
        return ""


def _merge_owner_address_variants(
    digests: list[RenewalDigest],
) -> list[RenewalDigest]:
    """Combine digests whose owner addresses differ only by case.

    Email mailbox comparison and delivery claims are case-insensitive in the
    send path. Keeping case variants as separate digests would let the first
    claim suppress the second and omit some of that owner's hosts.
    """
    merged: dict[str, RenewalDigest] = {}
    for digest in digests:
        key = digest.owner_email.casefold()
        existing = merged.get(key)
        if existing is None:
            merged[key] = digest
            continue
        existing.renewed_count += digest.renewed_count
        existing.overdue_count += digest.overdue_count
        existing.shortened_count += digest.shortened_count
        for destination, additions in (
            (existing.renewed_hosts, digest.renewed_hosts),
            (existing.overdue_hosts, digest.overdue_hosts),
            (existing.shortened_hosts, digest.shortened_hosts),
        ):
            destination.extend(host for host in additions if host not in destination)
        existing.host_expiry.update(digest.host_expiry)
    return list(merged.values())


def _build_digest_message(digest: RenewalDigest) -> str:
    expiry = digest.host_expiry
    lines = [
        f"[cert-watch] Renewal Digest — last {digest.days} days",
        "",
        f"Renewed on schedule: {digest.renewed_count}",
    ]
    if digest.renewed_hosts:
        for h in digest.renewed_hosts:
            lines.append(f"  - {h}{_fmt_expiry(expiry.get(h))}")
    lines.append("")
    lines.append(f"Overdue: {digest.overdue_count}")
    if digest.overdue_hosts:
        for h in digest.overdue_hosts:
            lines.append(f"  - {h}{_fmt_expiry(expiry.get(h))}")
    if digest.shortened_hosts:
        lines.append("")
        lines.append(f"Lifetimes shortened: {digest.shortened_count}")
        for h in digest.shortened_hosts:
            lines.append(f"  - {h}{_fmt_expiry(expiry.get(h))}")
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
    ``False`` on SMTP failure. Successful per-admin deliveries are durably
    recorded so overlapping/repeated weekly runs do not resend them.
    """
    from email.message import EmailMessage

    from cert_watch.alerts import (
        AlertConfig,
        _send_claimed_digest_smtp,
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

    from cert_watch.database.digest_deliveries import digest_period_key

    digest_key = digest_period_key("orphan", 7)

    def _build_message(recipients: list[str]) -> EmailMessage:
        msg = EmailMessage()
        msg["Subject"] = (
            f"[cert-watch] {len(orphans)} orphaned certificate(s) — no alert routing"
        )
        msg["From"] = alert_config.from_addr
        msg["To"] = ", ".join(recipients)
        msg.set_content(_build_orphan_message(orphans))
        return msg

    outcomes, busy = _send_claimed_digest_smtp(
        db_path,
        digest_key,
        admins,
        alert_config,
        _build_message,
        failure_label="orphan notice delivery",
    )
    return bool(outcomes) and all(outcomes.values()) and not busy


def send_renewal_digest(
    db_path: str | Path,
    alert_config: AlertConfig | None,
    webhook_config: WebhookConfig | None = None,
    *,
    days: int = 7,
    cadence_days: int | None = None,
    delivery_completion_callback: Callable[[bool], None] | None = None,
) -> bool | None:
    """Build and send the renewal digest through the existing alert pipeline.

    When SMTP and webhook configs are both absent, returns False.
    Sends one digest per owner plus one global digest for unowned hosts.
    For SMTP delivery, returns True only when all deliveries succeeded.
    For webhook delivery, the default API remains submission-based and returns
    True after queueing. When *delivery_completion_callback* is supplied,
    returns None for an asynchronous submission and invokes the callback with
    the final success/failure result after all webhook deliveries complete.
    """
    from cert_watch.alerts import (
        AlertConfig,
        WebhookConfig,
        _send_claimed_digest_smtp,
    )
    from cert_watch.database import Alert

    if alert_config is None and webhook_config is None:
        return False

    # Surface orphaned certs (no alert routing) to admins as part of the digest
    # run — independent of renewal activity, so a quiet week still flags them.
    # Logs its own failures; does not gate the renewal-digest return value.
    # Offloaded to the thread pool so SMTP latency does not block the scheduler
    # thread (same bug class as WI-134 webhook path).
    try:
        orphan_submitted = _submit_digest_task(send_orphan_notice, db_path, alert_config)
    except Exception:
        logger.warning(
            "orphan notice pool submit failed; delivering inline",
            exc_info=True,
        )
        send_orphan_notice(db_path, alert_config)
    else:
        if not orphan_submitted:
            logger.info("orphan notice not submitted because digest pool is stopped")

    digests = build_renewal_digest(db_path, days=days, cadence_days=cadence_days)
    if not digests:
        return True
    digests = _merge_owner_address_variants(digests)

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

    original_emails: dict[str, str] = {}
    owner_digests: dict[str, RenewalDigest] = {}
    for d in digests:
        if not _validate_email(d.owner_email):
            logger.warning("skipping invalid owner_email digest: %r", d.owner_email)
            continue
        cf = d.owner_email.casefold()
        original_emails.setdefault(cf, d.owner_email)
        if cf and cf not in global_recipients_cf:
            owner_digests.setdefault(cf, d)

    any_smtp_success = False
    any_smtp_failure = False
    smtp_busy = False

    if isinstance(alert_config, AlertConfig):
        from cert_watch.database.digest_deliveries import digest_period_key

        effective_days = cadence_days if cadence_days is not None else days
        digest_key = digest_period_key("renewal", effective_days)

        global_digest = RenewalDigest(
            days=effective_days,
            renewed_count=sum(d.renewed_count for d in digests),
            renewed_hosts=sorted({h for d in digests for h in d.renewed_hosts}),
            overdue_count=sum(d.overdue_count for d in digests),
            overdue_hosts=sorted({h for d in digests for h in d.overdue_hosts}),
            shortened_count=sum(d.shortened_count for d in digests),
            shortened_hosts=sorted({h for d in digests for h in d.shortened_hosts}),
            host_expiry={h: e for d in digests for h, e in d.host_expiry.items()},
        )
        global_body = _build_digest_message(global_digest)
        global_subject = (
            f"[cert-watch] Renewal Digest: "
            f"{global_digest.renewed_count} renewed, "
            f"{global_digest.overdue_count} overdue"
        )

        def _build_global_msg(recipients: list[str]) -> EmailMessage:
            m = EmailMessage()
            m["Subject"] = global_subject
            m["From"] = alert_config.from_addr
            m["To"] = ", ".join(recipients)
            m.set_content(global_body)
            return m

        def _build_owner_msg(cf_email: str, od: RenewalDigest) -> EmailMessage:
            body = _build_digest_message(od)
            subject = (
                f"[cert-watch] Renewal Digest: "
                f"{od.renewed_count} renewed, {od.overdue_count} overdue"
            )
            original = original_emails.get(cf_email, cf_email)
            m = EmailMessage()
            m["Subject"] = subject
            m["From"] = alert_config.from_addr
            m["To"] = original
            m.set_content(body)
            return m

        if global_recipients_original:
            outcomes, busy = _send_claimed_digest_smtp(
                db_path,
                digest_key,
                global_recipients_original,
                alert_config,
                _build_global_msg,
                failure_label="global renewal digest",
            )
            smtp_busy |= busy
            any_smtp_success |= any(outcomes.values())
            any_smtp_failure |= any(not delivered for delivered in outcomes.values())

        for cf_email, od in owner_digests.items():
            original = original_emails.get(cf_email, cf_email)

            def _build_current_owner_msg(
                _recipients: list[str],
                owner_email: str = cf_email,
                owner_digest: RenewalDigest = od,
            ) -> EmailMessage:
                return _build_owner_msg(owner_email, owner_digest)

            outcomes, busy = _send_claimed_digest_smtp(
                db_path,
                digest_key,
                [original],
                alert_config,
                _build_current_owner_msg,
                failure_label=f"owner digest for {original}",
            )
            smtp_busy |= busy
            any_smtp_success |= any(outcomes.values())
            any_smtp_failure |= any(not delivered for delivered in outcomes.values())

        any_smtp_failure |= smtp_busy

    if any_smtp_success and not any_smtp_failure:
        return True

    if any_smtp_failure and webhook_config is None:
        return False

    if smtp_busy:
        return False

    if isinstance(webhook_config, WebhookConfig):
        from cert_watch.alerts import ALERT_MAX_RETRIES, ALERT_RETRY_DELAY, send_webhook
        from cert_watch.database.digest_deliveries import (
            claim_digest_delivery,
            complete_digest_delivery,
            digest_period_key,
            renew_digest_delivery,
        )
        from cert_watch.retry import backoff_range

        effective_days = cadence_days if cadence_days is not None else days
        digest_key = digest_period_key("renewal", effective_days)
        channel = _webhook_channel(webhook_config)

        def _deliver_digest_webhook(od: RenewalDigest) -> bool:
            target = od.owner_email.casefold() or "_unowned"
            claim = claim_digest_delivery(db_path, digest_key, channel, target)
            if claim.state == "sent":
                return True
            if not claim.acquired:
                return False
            body = _build_digest_message(od)
            alert = Alert(
                cert_id=claim.idempotency_key,
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
                if not renew_digest_delivery(db_path, claim):
                    return False
                if send_webhook(alert, webhook_config):
                    complete_digest_delivery(db_path, claim, succeeded=True)
                    return True
            logger.warning(
                "renewal digest webhook failed after %d attempts",
                ALERT_MAX_RETRIES,
            )
            complete_digest_delivery(db_path, claim, succeeded=False)
            return False

        def _deliver_all_digest_webhooks() -> bool:
            delivered = all([_deliver_digest_webhook(od) for od in digests])
            if delivery_completion_callback is not None:
                try:
                    delivery_completion_callback(delivered)
                except Exception:
                    logger.exception("digest delivery completion callback failed")
            return delivered

        try:
            submitted = _submit_digest_task(_deliver_all_digest_webhooks)
        except Exception:
            logger.warning(
                "digest webhook pool submit failed; delivering inline",
                exc_info=True,
            )
            return _deliver_all_digest_webhooks()
        if not submitted:
            logger.info("digest webhook not submitted because digest pool is stopped")
            if delivery_completion_callback is not None:
                delivery_completion_callback(False)
                return None
            return False
        return None if delivery_completion_callback is not None else True

    return False
