"""The four independent operational facts for a certificate or endpoint.

This module owns the public vocabulary introduced by #126 S1.  SQL queries
select/filter the compact state names while presenters, reports and the JSON
API receive the same nested dictionaries from :func:`attach_status_models`.
Recipient matching is deliberately delegated to :mod:`cert_watch.alerting.routing`.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cert_watch.database.chain_status_cache import StatusContext
from cert_watch.database.connection import _connect
from cert_watch.scan_error_guidance import describe_scan_error

if TYPE_CHECKING:
    from cert_watch.config import Settings

CONDITIONS = ("expired", "le7", "8to30", "ok")
MONITORING_STATES = ("current", "failing", "never_scanned", "not_monitored")
RENEWAL_STATES = ("automation_configured", "manual", "stalled", "in_progress", "unknown")
DELIVERY_STATES = ("ok", "failing", "unrouted")

STATUS_FILTER_VALUES = {
    "condition": frozenset(CONDITIONS),
    "monitoring": frozenset(MONITORING_STATES),
    "renewal": frozenset(RENEWAL_STATES),
    "delivery": frozenset(DELIVERY_STATES),
}

_AUTO_METHODS = frozenset({"acme", "cert-manager"})
_TRUST_PROBLEMS = frozenset({"incomplete", "invalid", "unknown", "self-signed", "unverified"})


def invalid_status_filters(
    *,
    condition: str | None = None,
    monitoring: str | None = None,
    renewal: str | None = None,
    delivery: str | None = None,
) -> dict[str, str]:
    """Return supplied four-axis filters that are outside the public vocabulary."""
    supplied = {
        "condition": condition,
        "monitoring": monitoring,
        "renewal": renewal,
        "delivery": delivery,
    }
    return {
        name: value
        for name, value in supplied.items()
        if value is not None and value not in STATUS_FILTER_VALUES[name]
    }


@dataclass(frozen=True)
class AxisSettings:
    """Only the resolved settings that affect the four-axis read model."""

    sched_hour: int = 6
    sched_min: int = 0
    renewal_window_days: int = 30
    smtp_configured: bool = False
    global_recipients: tuple[str, ...] = ()
    webhook_configured: bool = False
    webhook_kind: str = "generic"

    @classmethod
    def from_settings(cls, settings: Settings) -> AxisSettings:
        return cls(
            sched_hour=settings.sched_hour,
            sched_min=settings.sched_min,
            renewal_window_days=settings.renewal_window_days,
            smtp_configured=bool(settings.smtp_host and settings.alert_from),
            global_recipients=tuple(settings.alert_recipients),
            webhook_configured=bool(settings.webhook_url),
            webhook_kind=settings.webhook_kind,
        )


@dataclass
class StatusModelContext:
    """One instant and one set of derived inputs shared by a request."""

    certificate_status: StatusContext
    settings: AxisSettings
    renewal_analytics: dict[tuple[str, int], str]
    delivery: dict[str, dict[str, Any]]

    @property
    def now(self) -> datetime:
        return self.certificate_status.now

    @property
    def sql_now(self) -> str:
        return self.certificate_status.sql_now


def condition_state(effective_days: int | None) -> str | None:
    """Expiry-only condition; chain trust never changes this state."""
    if effective_days is None:
        return None
    if effective_days < 0:
        return "expired"
    if effective_days <= 7:
        return "le7"
    if effective_days <= 30:
        return "8to30"
    return "ok"


def monitoring_state(
    last_success: str | None,
    last_attempt: str | None,
    attempt_status: str | None,
    interval_hours: int | None,
    sched_hour: int,
    sched_min: int,
    now: str | datetime,
) -> str:
    """Collapse the existing scan-freshness rule into S1's three states."""
    from cert_watch.scan_freshness import cadence_due_at

    current = datetime.fromisoformat(now) if isinstance(now, str) else now
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)

    def parsed(value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            result = datetime.fromisoformat(value)
        except (TypeError, ValueError, OverflowError):
            return None
        return result.replace(tzinfo=UTC) if result.tzinfo is None else result.astimezone(UTC)

    success = parsed(last_success)
    attempt = parsed(last_attempt)
    if (last_success and success is None) or (last_attempt and attempt is None):
        return "failing"
    if success is None:
        return "failing" if attempt is not None and attempt_status != "success" else "never_scanned"
    if success > current or (attempt is not None and attempt > current):
        return "failing"
    try:
        due = cadence_due_at(success, interval_hours, sched_hour, sched_min)
    except (OverflowError, TypeError, ValueError):
        return "failing"
    if due <= current or attempt_status != "success":
        return "failing"
    return "current"


def monitoring_since(
    state: str,
    last_success: str | None,
    attempt_status: str | None,
    interval_hours: int | None,
    sched_hour: int,
    sched_min: int,
    first_failed: str | None,
) -> str | None:
    from cert_watch.scan_freshness import cadence_due_at

    if state != "failing":
        return None
    if attempt_status != "success" and first_failed:
        return first_failed
    if not last_success:
        return first_failed
    try:
        success = datetime.fromisoformat(last_success)
        if success.tzinfo is None:
            success = success.replace(tzinfo=UTC)
        return cadence_due_at(success, interval_hours, sched_hour, sched_min).isoformat()
    except (TypeError, ValueError, OverflowError):
        return first_failed or last_success


def renewal_state(
    renewal_method: str | None,
    operator_status: str | None,
    stalled: bool,
    analytics: str | None,
) -> tuple[str, str]:
    """Return state and evidence source using the documented precedence."""
    if operator_status == "in_progress":
        return "in_progress", "operator_report"
    if stalled:
        return "stalled", "renewal_window"
    method = (renewal_method or "").casefold()
    if method in _AUTO_METHODS:
        return "automation_configured", "renewal_method"
    if method == "manual":
        return "manual", "renewal_method"
    if analytics == "likely-automated":
        return "automation_configured", "renewal_analytics"
    if analytics == "manual":
        return "manual", "renewal_analytics"
    return "unknown", "none"


def prepare_status_model_context(
    db_path: str | Path,
    *,
    certificate_status: StatusContext,
    settings: AxisSettings | None = None,
) -> StatusModelContext:
    """Prepare the cheap request-wide context.

    Historical renewal analytics are deliberately loaded later, for only the
    rows a request will return.  Preparing a page must not scan the estate's
    complete history before SQL pagination has selected that page.
    """
    return StatusModelContext(
        certificate_status=certificate_status,
        settings=settings or AxisSettings(),
        renewal_analytics={},
        delivery={},
    )


def renewal_state_for_row(
    *,
    hostname: str | None,
    port: int | None,
    renewal_method: str | None,
    operator_status: str | None,
    not_after: str | None,
    has_successor: bool,
    context: StatusModelContext,
    analytics: str | None = None,
) -> tuple[str, str]:
    """Classify one selected row from its stored and bounded history evidence."""
    stalled = False
    cfg = context.settings
    if hostname and not_after and not has_successor and cfg.renewal_window_days > 0:
        try:
            expires = datetime.fromisoformat(not_after)
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=UTC)
            days = (expires - context.now).days
            stalled = 0 <= days <= cfg.renewal_window_days
        except (TypeError, ValueError, OverflowError):
            stalled = False
    return renewal_state(
        renewal_method,
        operator_status,
        stalled,
        analytics
        if analytics is not None
        else context.renewal_analytics.get((hostname or "", int(port or 0))),
    )


def delivery_state(
    has_route: object,
    smtp_configured: object,
    smtp_can_deliver: object,
    webhook_configured: object,
    webhook_can_deliver: object,
    smtp_outcome: object,
    webhook_outcome: object,
) -> str:
    """Classify routing and latest per-channel evidence for SQL and display rows."""
    if not bool(has_route):
        return "unrouted"
    if not (bool(smtp_can_deliver) or bool(webhook_can_deliver)):
        return "failing"
    failed = {"failed", "partial", "unknown"}
    if bool(smtp_configured) and smtp_outcome in failed:
        return "failing"
    if bool(webhook_configured) and webhook_outcome in failed:
        return "failing"
    return "ok"


def register_status_model_functions(
    conn: sqlite3.Connection, context: StatusModelContext
) -> None:
    """Register request-bound SQL functions used by filtering and agreement tests."""
    cfg = context.settings
    # Converting the request clock to its SQL representation is request work,
    # not per-row UDF work. Capture it once for the monitoring closure.
    sql_now = context.sql_now
    conn.create_function("cw_condition", 1, condition_state)
    conn.create_function(
        "cw_monitoring_state",
        4,
        lambda success, attempt, status, interval: monitoring_state(
            success,
            attempt,
            status,
            interval,
            cfg.sched_hour,
            cfg.sched_min,
            sql_now,
        ),
    )
    conn.create_function(
        "cw_renewal_analytics",
        2,
        lambda hostname, port: context.renewal_analytics.get(
            (str(hostname or ""), int(port or 0)), "unknown"
        ),
    )
    def sql_renewal(
        hostname: object,
        port: object,
        method: object,
        operator: object,
        not_after: object,
        has_successor: object,
        analytics: object,
    ) -> str:
        state, _source = renewal_state_for_row(
            hostname=str(hostname or ""),
            port=int(str(port or 0)),
            renewal_method=str(method or ""),
            operator_status=str(operator or ""),
            not_after=str(not_after) if not_after else None,
            has_successor=bool(has_successor),
            context=context,
            analytics=str(analytics or "unknown"),
        )
        return state

    conn.create_function("cw_renewal_state", 7, sql_renewal)
    from cert_watch.alerting.model import normalize_channel

    conn.create_function("cw_normalize_channel", 1, lambda value: normalize_channel(str(value)))
    conn.create_function("cw_delivery_state", 7, delivery_state)


def alert_group_match_sql(cert_alias: str, host_alias: str | None) -> str:
    """Return an identity-free predicate for any matching alert group."""
    cert_id = f"{cert_alias}.id"
    cert_tags = f"{cert_alias}.tags"
    host_tags = f"{host_alias}.tags" if host_alias else "''"
    return (
        "EXISTS(SELECT 1 FROM alert_groups ag WHERE "
        f"EXISTS(SELECT 1 FROM alert_group_certs agc WHERE agc.cert_id = {cert_id} "
        "AND agc.group_id = ag.id) OR "
        f"cw_tags_overlap({cert_tags}, {host_tags}, ag.match_tags) OR "
        "EXISTS(SELECT 1 FROM roles ro WHERE ro.alert_group_id = ag.id "
        f"AND cw_tags_overlap({cert_tags}, {host_tags}, ro.scope_tag)))"
    )


def delivery_state_sql(
    cert_alias: str | None,
    host_alias: str | None,
    settings: AxisSettings,
) -> str:
    """Return SQL for the delivery state without expanding recipient identities.

    This is the aggregate/filter path.  Full routing resolution remains the
    display-row path, where names and addresses are actually needed.
    """
    c = cert_alias
    h = host_alias
    cert_id = f"{c}.id" if c else "NULL"
    cert_tags = f"{c}.tags" if c else "''"
    host_tags = f"{h}.tags" if h else "''"
    owner_route = f"NULLIF(TRIM(COALESCE({h}.owner_email, '')), '') IS NOT NULL" if h else "0"
    group_match = alert_group_match_sql(c, h) if c else "0"
    group_recipients = (
        "EXISTS(SELECT 1 FROM alert_groups ag WHERE "
        "NULLIF(TRIM(REPLACE(COALESCE(ag.recipients, ''), ',', '')), '') "
        "IS NOT NULL AND ("
        f"EXISTS(SELECT 1 FROM alert_group_certs agc WHERE agc.cert_id = {cert_id} "
        "AND agc.group_id = ag.id) OR "
        f"cw_tags_overlap({cert_tags}, {host_tags}, ag.match_tags) OR "
        "EXISTS(SELECT 1 FROM roles ro WHERE ro.alert_group_id = ag.id "
        f"AND cw_tags_overlap({cert_tags}, {host_tags}, ro.scope_tag))))"
    )
    global_recips = int(bool(settings.global_recipients))
    global_webhook = int(settings.webhook_configured)
    smtp_can = (
        f"({int(settings.smtp_configured)} AND "
        f"({global_recips} OR {owner_route} OR {group_recipients}))"
    )
    any_route = f"({global_recips} OR {global_webhook} OR {owner_route} OR {group_match})"

    def latest_outcome(channel: str) -> str:
        channel_literal = channel.replace("'", "''")
        return (
            "COALESCE((SELECT CASE "
            "WHEN json_extract(e.details, '$.outcome') IN ('accepted', 'partial', 'failed') "
            "THEN json_extract(e.details, '$.outcome') ELSE 'unknown' END "
            "FROM alert_delivery_events e JOIN alerts a ON a.id = e.alert_id "
            f"WHERE a.cert_id = {cert_id} AND e.event_kind = 'completed' "
            f"AND cw_normalize_channel(e.channel) = '{channel_literal}' "
            "ORDER BY e.id DESC LIMIT 1), '')"
        )

    webhook_channel = f"webhook:{settings.webhook_kind}"
    return (
        f"cw_delivery_state({any_route}, {int(settings.smtp_configured)}, {smtp_can}, "
        f"{global_webhook}, {global_webhook}, {latest_outcome('smtp')}, "
        f"{latest_outcome(webhook_channel)})"
    )


def _latest_channel_outcomes(
    db_path: str | Path, cert_ids: tuple[str, ...]
) -> dict[str, dict[str, str]]:
    if not cert_ids:
        return {}
    result: dict[str, dict[str, str]] = {}
    from cert_watch.alerting.model import normalize_channel

    with _connect(db_path) as conn:
        conn.create_function(
            "cw_normalize_channel", 1, lambda value: normalize_channel(str(value))
        )
        for start in range(0, len(cert_ids), 350):
            chunk = cert_ids[start : start + 350]
            placeholders = ",".join("?" for _ in chunk)
            rows = conn.execute(
                f"""WITH normalized AS (
                    SELECT a.cert_id, cw_normalize_channel(e.channel) AS channel,
                           e.details, e.id
                    FROM alert_delivery_events e
                    JOIN alerts a ON a.id = e.alert_id
                    WHERE e.event_kind = 'completed' AND a.cert_id IN ({placeholders})
                ), completed AS (
                    SELECT cert_id, channel, details, id,
                           ROW_NUMBER() OVER (
                               PARTITION BY cert_id, channel ORDER BY id DESC
                           ) AS n
                    FROM normalized
                )
                SELECT cert_id, channel, json_extract(details, '$.outcome') AS outcome
                FROM completed WHERE n = 1""",
                chunk,
            ).fetchall()
            for row in rows:
                channel = str(row["channel"])
                outcome = row["outcome"]
                result.setdefault(row["cert_id"], {})[channel] = (
                    outcome if outcome in {"accepted", "partial", "failed"} else "unknown"
                )
    return result


def load_delivery_statuses(
    db_path: str | Path,
    cert_ids: tuple[str, ...],
    context: StatusModelContext,
) -> None:
    """Populate delivery states using the one routing resolver and existing ledger."""
    missing = tuple(dict.fromkeys(cid for cid in cert_ids if cid and cid not in context.delivery))
    if not missing:
        return
    from cert_watch.alerting.routing import resolve_routing

    routing = resolve_routing(db_path, missing)
    outcomes = _latest_channel_outcomes(db_path, missing)
    cfg = context.settings
    for cert_id in missing:
        snapshot = routing.get(cert_id, {"recipients": [], "groups": []})
        specific = tuple(
            str(value).strip()
            for value in snapshot.get("recipients", [])
            if str(value).strip()
        )
        groups = tuple(
            str(group.get("name") or group.get("id") or "")
            for group in snapshot.get("groups", [])
            if isinstance(group, dict)
        )
        smtp_recipients = tuple(dict.fromkeys((*cfg.global_recipients, *specific)))
        latest = outcomes.get(cert_id, {})
        smtp_ok = cfg.smtp_configured and bool(smtp_recipients)
        webhook_ok = cfg.webhook_configured
        channels = (
            {
                "channel": "smtp",
                "recipients": list(smtp_recipients),
                "configured": cfg.smtp_configured,
                "can_deliver": smtp_ok,
                "last_outcome": latest.get("smtp"),
            },
            {
                "channel": f"webhook:{cfg.webhook_kind}",
                "recipients": list(groups),
                "configured": cfg.webhook_configured,
                "can_deliver": webhook_ok,
                "last_outcome": latest.get(f"webhook:{cfg.webhook_kind}"),
            },
        )
        state = delivery_state(
            bool(specific or groups or cfg.global_recipients or cfg.webhook_configured),
            cfg.smtp_configured,
            smtp_ok,
            cfg.webhook_configured,
            webhook_ok,
            latest.get("smtp"),
            latest.get(f"webhook:{cfg.webhook_kind}"),
        )
        context.delivery[cert_id] = {
            "state": state,
            "recipients": list(specific),
            "matching_groups": list(groups),
            "channels": list(channels),
        }


def _monitoring_axis(row: dict[str, Any]) -> dict[str, Any]:
    state = str(row.get("monitoring") or "never_scanned")
    raw = row.get("monitoring_error") or row.get("scan_error")
    guidance = describe_scan_error(str(raw)) if raw else None
    cause = guidance.cause if guidance else None
    if state == "failing" and cause is None:
        cause = (
            "No successful scan is recorded."
            if not row.get("monitoring_last_success")
            else "The endpoint has no current successful observation."
        )
    return {
        "state": state,
        "since": row.get("monitoring_since"),
        "cause": cause,
        "raw_error": raw,
    }


def overall_state(row: dict[str, Any]) -> str:
    """Return the safe compatibility token for an endpoint's overall display.

    ``urgency`` remains the historical certificate-condition/trust value for
    internal callers.  APIs and reports use this helper so a stale or failed
    endpoint can never be described as healthy merely because its last seen
    certificate still has plenty of validity.
    """
    if row.get("host_id") and row.get("monitoring") == "failing":
        return "failing"
    if row.get("host_id") and row.get("monitoring") == "never_scanned":
        return "gray"
    return str(row.get("urgency") or "gray")


def attach_status_models(
    db_path: str | Path,
    rows: list[dict[str, Any]],
    context: StatusModelContext,
) -> None:
    """Attach the canonical nested model to built inventory rows, recursively."""
    leaves: list[dict[str, Any]] = []
    for row in rows:
        leaves.extend(row.get("hosts") or [row])
    cert_ids = tuple(
        str(row.get("id"))
        for row in leaves
        if row.get("id") and row.get("kind") != "pending"
    )
    load_delivery_statuses(db_path, cert_ids, context)
    for row in leaves:
        days = row.get("effective_days")
        condition = str(row.get("condition") or condition_state(days) or "") or None
        chain_status = row.get("chain_status")
        delivery = context.delivery.get(
            str(row.get("id") or ""),
            {"state": "unrouted", "recipients": [], "matching_groups": [], "channels": []},
        )
        row["status"] = {
            "condition": {"state": condition, "effective_days": days},
            "chain_trust_problem": chain_status in _TRUST_PROBLEMS,
            "chain_status": chain_status,
            "monitoring": _monitoring_axis(row),
            "renewal": {
                "state": row.get("renewal") or "unknown",
                "source": row.get("renewal_source") or "none",
            },
            "delivery": delivery,
        }
        row["condition"] = condition
        row["monitoring"] = row["status"]["monitoring"]["state"]
        row["renewal"] = row["status"]["renewal"]["state"]
        row["delivery"] = delivery["state"]
        row["overall_state"] = overall_state(row)
    for row in rows:
        children = row.get("hosts") or []
        if not children:
            continue
        conditions = [child["condition"] for child in children if child.get("condition")]
        condition_order = {"expired": 0, "le7": 1, "8to30": 2, "ok": 3}
        monitoring = "current"
        if any(child["monitoring"] == "failing" for child in children):
            monitoring = "failing"
        elif any(child["monitoring"] == "never_scanned" for child in children):
            monitoring = "never_scanned"
        renewal_order = {
            "stalled": 0,
            "in_progress": 1,
            "manual": 2,
            "automation_configured": 3,
            "unknown": 4,
        }
        delivery_order = {"failing": 0, "unrouted": 1, "ok": 2}
        row["condition"] = (
            min(conditions, key=lambda value: condition_order[value])
            if conditions
            else None
        )
        row["monitoring"] = monitoring
        row["renewal"] = min(
            (child["renewal"] for child in children),
            key=lambda value: renewal_order[value],
        )
        row["delivery"] = min(
            (child["delivery"] for child in children),
            key=lambda value: delivery_order[value],
        )
        row["status"] = {
            "condition": {"state": row["condition"], "effective_days": row.get("effective_days")},
            "chain_trust_problem": any(
                child["status"]["chain_trust_problem"] for child in children
            ),
            "chain_status": row.get("chain_status"),
            "monitoring": {"state": monitoring, "since": None, "cause": None, "raw_error": None},
            "renewal": {"state": row["renewal"], "source": "group"},
            "delivery": {
                "state": row["delivery"],
                "recipients": [],
                "matching_groups": [],
                "channels": [],
            },
        }
        row["overall_state"] = overall_state(row)


def status_json(model: dict[str, Any]) -> str:
    """Stable compact representation used only by focused tests/debugging."""
    return json.dumps(model, separators=(",", ":"), sort_keys=True)
