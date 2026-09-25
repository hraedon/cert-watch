"""Expiry threshold rules."""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any

from cert_watch.alerting.keys import certificate_alert_key
from cert_watch.alerting.messages import _format_message
from cert_watch.alerting.model import (
    CHAIN_THRESHOLDS,
    LEAF_THRESHOLDS,
    SHORT_CERT_LIFETIME_DAYS,
    SHORT_LIFETIME_CHAIN_PCT,
    SHORT_LIFETIME_LEAF_PCT,
    URGENT_THRESHOLD_DAYS,
)
from cert_watch.alerting.routing import (
    _load_host_owner_maps,
    resolve_routing,
)
from cert_watch.certificate_model import Certificate
from cert_watch.database import Alert, AlertRepository


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


def evaluate_thresholds(
    cert: Certificate,
    alert_repo: AlertRepository,
    *,
    cert_id: str | None = None,
    custom_thresholds: tuple[int, ...] | None = None,
    owner_info: dict[str, Any] | None = None,
    extra_recipients: list[str] | None = None,
    routing: dict[str, Any] | None = None,
    hostname: str = "",
    port: int | None = None,
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
        urgent_thresholds = tuple(t for t in thresholds if t <= URGENT_THRESHOLD_DAYS)
        thresholds = urgent_thresholds or ((min(thresholds),) if thresholds else ())
    cid = cert_id or cert.fingerprint_sha256

    # Collect existing alerts scoped to the current alert_type so that
    # renewal_stalled / policy_violation rows don't interfere with expiry
    # thresholds. Lifecycle failures stay terminal. Migration-marked legacy
    # failures may be revived once, below, if this is still the current stage.
    current_type = "expired" if days < 0 else "expiry_warning"
    cert_alerts = alert_repo.list_for_cert(cid)
    existing_for_type: set[int] = {
        a.threshold_days
        for a in cert_alerts
        if a.threshold_days is not None
        and a.alert_type == current_type
    }
    legacy_failed_for_type: dict[int, Alert] = {
        a.threshold_days: a
        for a in cert_alerts
        if a.threshold_days is not None
        and a.alert_type == current_type
        and a.status == "failed"
        and a.failure_reason == "legacy_failed"
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
        failed_alert = legacy_failed_for_type.get(most_urgent)
        if failed_alert and alert_repo.revive_legacy_expiry(failed_alert.id):
            failed_alert.status = "pending"
            failed_alert.attempt_count = 0
            failed_alert.next_attempt_at = None
            failed_alert.failure_reason = None
            failed_alert.error_message = None
            return [failed_alert]
        return []

    # Don't go backwards: if a more urgent threshold was already alerted
    # for this type, the situation has escalated past this one.
    if any(e < most_urgent for e in existing_for_type):
        return []

    recipients = (
        list(extra_recipients)
        if extra_recipients
        else (
            [owner_info["owner_email"]]
            if owner_info and owner_info.get("owner_email")
            else []
        )
    )
    alert = Alert(
        cert_id=cid,
        alert_type="expired" if days < 0 else "expiry_warning",
        status="pending",
        message=_format_message(cert, days, most_urgent, owner_info=owner_info),
        threshold_days=most_urgent,
        extra_recipients=recipients,
        hostname=hostname,
        subject=cert.subject,
        dedupe_key=certificate_alert_key(
            "expiry",
            cert_id=cid,
            fingerprint=cert.fingerprint_sha256,
            hostname=hostname,
            port=port,
            suffix=(
                "expired" if days < 0 else "expiry_warning",
                str(most_urgent),
            ),
        ),
        routing=routing or {
            "version": 1,
            "recipients": recipients,
            "groups": [],
        },
    )
    alert_id = alert_repo.enqueue(alert, lifetime=True)
    if alert_id is None:
        return []
    alert.id = alert_id
    return [alert]


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
    from cert_watch.database.connection import parse_san_dns_names

    host_thresholds, host_owners = _load_host_owner_maps(db_path)

    with _connect(db_path) as conn:
        leaves = conn.execute(
            "SELECT id, subject, issuer, not_before, not_after, "
            "san_dns_names, fingerprint_sha256, hostname, port "
            "FROM certificates AS current WHERE is_leaf = 1 "
            "AND NOT EXISTS (SELECT 1 FROM certificates AS successor "
            "WHERE successor.replaces_cert_id = current.id "
            "AND successor.id != current.id)"
        ).fetchall()

    # Resolve the complete immutable route once for the batch. The snapshot
    # also carries the matching groups' threshold override.
    routing_map = resolve_routing(
        db_path, tuple(leaf_row["id"] for leaf_row in leaves)
    )

    all_alerts: list[Alert] = []
    for leaf_row in leaves:
        cert = Certificate(
            subject=leaf_row["subject"],
            issuer=leaf_row["issuer"],
            not_before=_parse_iso(leaf_row["not_before"]),
            not_after=_parse_iso(leaf_row["not_after"]),
            san_dns_names=parse_san_dns_names(leaf_row["san_dns_names"]),
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
        routing = routing_map[cert_id]
        group_td = routing.get("threshold_days")
        if group_td is not None:
            custom = (group_td, max(group_td // 2, 1), max(group_td // 4, 1), 1)

        # Resolve alert-group recipients for this cert (batch result), then merge
        # with owner + role members through the shared resolver (single source of
        # truth shared with orphan detection — see resolve_cert_recipients).
        merged_extra = list(routing["recipients"])

        alerts = evaluate_thresholds(
            cert, alert_repo, cert_id=leaf_row["id"], custom_thresholds=custom,
            owner_info=owner_info, extra_recipients=merged_extra or None,
            hostname=leaf_row["hostname"] or "", urgent_only=urgent_only,
            port=port,
            routing=routing,
        )
        all_alerts.extend(alerts)
    return all_alerts
