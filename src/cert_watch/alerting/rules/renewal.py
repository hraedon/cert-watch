"""Renewal-window rule: leaves inside their window with no successor."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cert_watch.alerting.keys import certificate_alert_key
from cert_watch.alerting.messages import _format_renewal_message
from cert_watch.alerting.routing import _load_host_owner_maps
from cert_watch.database import Alert, AlertRepository


def renewal_window_sql(alias: str = "c") -> str:
    """SQL: leaf row *alias* is in its renewal window with the renewal unhandled.

    Binds ``?`` window days, ``?`` now (``_sql_now``), ``?`` window days. The one
    predicate Home's attention queue and the renewal notification share: the
    leaf's own days are within the window (not expired), no successor
    certificate replaces it (a row naming itself doesn't count), and its host
    is not marked in progress. A legacy
    ``renewed`` value is not evidence that a replacement certificate exists.
    """
    return (
        f"(? > 0 AND cw_effective_days({alias}.not_after, NULL, ?) BETWEEN 0 AND ?"
        f" AND NOT EXISTS (SELECT 1 FROM certificates succ"
        # A row naming itself is not replaced by anything (#115 review).
        f" WHERE succ.replaces_cert_id = {alias}.id AND succ.id != {alias}.id)"
        f" AND COALESCE((SELECT rh.renewal_status FROM hosts rh"
        f" WHERE rh.hostname = {alias}.hostname AND rh.port = {alias}.port), '')"
        f" != 'in_progress')"
    )


def renewal_window_candidates(
    db_path: str | Path,
    window_days: int = 30,
) -> list[dict[str, Any]]:
    """Read current, unhandled renewal conditions without consulting alerts.

    Home and notification generation share this predicate
    (:func:`renewal_window_sql`): a leaf is inside the configured window, has
    no successor, and its host is not marked as in progress.
    Delivery success/failure does not resolve it. Each result contains the
    certificate fields, days_remaining, and owner.
    """
    if window_days <= 0:
        return []
    from cert_watch.database import _connect
    from cert_watch.database.connection import _sql_now

    now = _sql_now(datetime.now(UTC))
    with _connect(db_path) as conn:
        leaves = conn.execute(
            "SELECT c.id, c.subject, c.hostname, c.port, c.not_after, c.fingerprint_sha256,"
            " cw_effective_days(c.not_after, NULL, ?) AS days_remaining"
            f" FROM certificates c WHERE c.is_leaf = 1 AND {renewal_window_sql('c')}",
            (now, window_days, now, window_days),
        ).fetchall()

    _host_thresholds, host_owners = _load_host_owner_maps(db_path)
    return [
        {**dict(leaf), "owner": host_owners.get((leaf["hostname"], leaf["port"]), {})}
        for leaf in leaves
    ]


def evaluate_renewal_window(
    db_path: str | Path,
    alert_repo: AlertRepository,
    window_days: int = 30,
    *,
    closed_sent: list[Alert] | None = None,
) -> list[Alert]:
    """Create one notification per fingerprint while its condition persists."""
    from cert_watch.alerting.routing import resolve_routing
    from cert_watch.database import AlertStore, _connect

    candidates = renewal_window_candidates(db_path, window_days)
    routing_map = resolve_routing(
        db_path, tuple(leaf["id"] for leaf in candidates)
    )
    active_keys = {
        certificate_alert_key(
            "renewal",
            cert_id=leaf["id"],
            fingerprint=leaf["fingerprint_sha256"],
            hostname=leaf["hostname"],
            port=leaf["port"],
        )
        for leaf in candidates
    }
    store = AlertStore(db_path)
    with _connect(db_path) as conn:
        open_keys = {
            row["dedupe_key"]
            for row in conn.execute(
                """SELECT dedupe_key FROM alerts
                   WHERE alert_type = 'renewal_stalled' AND closed_at IS NULL
                     AND dedupe_key IS NOT NULL"""
            ).fetchall()
        }
    closed = store.close_keys(open_keys - active_keys)
    if closed_sent is not None:
        closed_sent.extend(closed)

    created: list[Alert] = []
    for leaf in candidates:
        cid = leaf["id"]
        owner = leaf["owner"]
        routing = routing_map[cid]
        alert = Alert(
            cert_id=cid,
            alert_type="renewal_stalled",
            status="pending",
            message=_format_renewal_message(leaf, leaf["days_remaining"], window_days, owner),
            threshold_days=window_days,
            extra_recipients=list(routing["recipients"]),
            hostname=leaf["hostname"] or "",
            subject=leaf["subject"] or "",
            dedupe_key=certificate_alert_key(
                "renewal",
                cert_id=cid,
                fingerprint=leaf["fingerprint_sha256"],
                hostname=leaf["hostname"],
                port=leaf["port"],
            ),
            routing=routing,
        )
        alert_id = alert_repo.enqueue(alert, lifetime=True)
        if alert_id is None:
            continue
        alert.id = alert_id
        created.append(alert)
    return created
