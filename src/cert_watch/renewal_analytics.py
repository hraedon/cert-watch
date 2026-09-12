"""Renewal analytics over the cert_history table."""
from __future__ import annotations

import statistics
from dataclasses import dataclass
from datetime import datetime
from math import ceil
from pathlib import Path
from typing import Any

from cert_watch.database.connection import _connect, _parse_iso
from cert_watch.database.schema import init_schema

ACME_ISSUER_FRAGMENTS = ("let's encrypt", "zerossl", "buypass", "acme")


@dataclass
class RenewalOverdueSignal:
    hostname: str
    cert_fingerprint: str
    days_remaining: float
    expected_renewal_at_days: float
    days_overdue: float
    confidence: str
    port: int | None = None


@dataclass
class HostRenewalAnalytics:
    """Deployment history; lifetimes contain only known certificate validity.

    Missing periods remain in cert_count but never acquire a duration from a
    scan timestamp. A lifetime trend requires validity for every period.
    """

    hostname: str
    observed_lifetimes: list[int]
    lifetime_trend: str
    renewal_lead_times: list[float]
    median_lead_time: float | None
    median_cadence_days: float | None
    automation_classification: str
    classification_evidence: dict[str, Any]
    cert_count: int
    port: int | None = None


def _is_acme_issuer(issuer: str) -> bool:
    issuer_lower = issuer.lower()
    return any(f in issuer_lower for f in ACME_ISSUER_FRAGMENTS)


def _compute_trend(values: list[int]) -> str:
    if len(values) < 2:
        return "unknown"
    first_half = values[: len(values) // 2]
    second_half = values[len(values) // 2 :]
    avg_first = statistics.mean(first_half)
    avg_second = statistics.mean(second_half)
    diff = avg_second - avg_first
    threshold = max(avg_first * 0.05, 1)
    if diff > threshold:
        return "increasing"
    if diff < -threshold:
        return "decreasing"
    return "stable"


def _classify_automation(
    fingerprint_periods: list[dict[str, Any]],
    observed_lifetimes: list[int],
    cadence_intervals: list[float],
    renewal_lead_times: list[float],
) -> tuple[str, dict[str, Any]]:
    known_count = len(observed_lifetimes)
    unknown_count = len(fingerprint_periods) - known_count
    expected_intervals = len(fingerprint_periods) - 1
    chronology_complete = (
        len(cadence_intervals) == expected_intervals
        and len(renewal_lead_times) == expected_intervals
    )
    evidence: dict[str, Any] = {
        "known_validity_count": known_count,
        "unknown_validity_count": unknown_count,
        "chronology_complete": chronology_complete,
    }

    if len(fingerprint_periods) < 2:
        evidence["reason"] = "fewer than 2 observed renewals"
        return "unknown", evidence

    issuers = [p["issuer"] for p in fingerprint_periods]
    has_acme_issuer = any(_is_acme_issuer(iss) for iss in issuers)

    max_lifetime = max(observed_lifetimes) if observed_lifetimes else 0
    all_short_lived = unknown_count == 0 and bool(observed_lifetimes) and all(
        lt <= 90 for lt in observed_lifetimes
    )

    cadence_stdev = statistics.pstdev(cadence_intervals) if len(cadence_intervals) >= 2 else 0.0

    has_late_renewals = any(lt <= 0 for lt in renewal_lead_times) if renewal_lead_times else False
    consistent_cadence = len(cadence_intervals) >= 2 and cadence_stdev <= 3

    evidence["max_lifetime_days"] = max_lifetime
    evidence["all_lifetimes_le_90"] = all_short_lived
    evidence["has_acme_issuer"] = has_acme_issuer
    evidence["cadence_stdev_days"] = round(cadence_stdev, 1) if cadence_intervals else None
    evidence["median_cadence_days"] = (
        round(statistics.median(cadence_intervals), 1) if cadence_intervals else None
    )
    evidence["has_late_renewals"] = has_late_renewals
    evidence["renewal_count"] = len(fingerprint_periods) - 1

    if unknown_count or not chronology_complete:
        evidence["reason"] = "incomplete certificate validity or scan chronology"
        return "unknown", evidence

    if max_lifetime > 90 or has_late_renewals:
        return "manual", evidence

    if all_short_lived and consistent_cadence and has_acme_issuer:
        return "likely-automated", evidence

    return "manual", evidence


def _known_timestamp(value: Any) -> datetime | None:
    try:
        return _parse_iso(value)
    except (ValueError, TypeError):
        return None


def _known_validity_days(entry: dict[str, Any]) -> int | None:
    not_before = _known_timestamp(entry.get("not_before"))
    not_after = _known_timestamp(entry.get("not_after"))
    if not_before is None or not_after is None:
        return None
    seconds = (not_after - not_before).total_seconds()
    # A partial day must not round a certificate under a validity cap.
    return ceil(seconds / 86400) if seconds > 0 else None


def _compute_host_from_entries(
    hostname: str, entries: list[dict[str, Any]], *, port: int | None = None
) -> HostRenewalAnalytics:
    if not entries:
        return HostRenewalAnalytics(
            hostname=hostname,
            observed_lifetimes=[],
            lifetime_trend="unknown",
            renewal_lead_times=[],
            median_lead_time=None,
            median_cadence_days=None,
            automation_classification="unknown",
            classification_evidence={},
            cert_count=0,
            port=port,
        )

    fingerprint_periods: list[dict[str, Any]] = []

    for entry in entries:
        fp = entry["fingerprint_sha256"]
        if not fingerprint_periods or fingerprint_periods[-1]["fingerprint"] != fp:
            fingerprint_periods.append(
                {
                    "fingerprint": fp,
                    "issuer": entry["issuer"],
                    "not_after": entry["not_after"],
                    "not_before": entry.get("not_before"),
                    "validity_days": _known_validity_days(entry),
                    "first_scanned_at": entry["scanned_at"],
                    "last_scanned_at": entry["scanned_at"],
                }
            )
        else:
            period = fingerprint_periods[-1]
            period["last_scanned_at"] = entry["scanned_at"]
            # A post-migration observation may supply the missing issuance
            # date. Recover only inside this contiguous deployment, never
            # from an earlier/later occurrence across a rollback boundary.
            validity = _known_validity_days(entry)
            if period["validity_days"] is None and validity is not None:
                period["not_before"] = entry["not_before"]
                period["not_after"] = entry["not_after"]
                period["validity_days"] = validity

    cert_count = len(fingerprint_periods)

    observed_lifetimes: list[int] = [
        period["validity_days"] for period in fingerprint_periods
        if period["validity_days"] is not None
    ]

    lifetime_trend = (
        _compute_trend(observed_lifetimes)
        if len(observed_lifetimes) == cert_count else "unknown"
    )

    renewal_lead_times: list[float] = []
    for i in range(1, len(fingerprint_periods)):
        prev = fingerprint_periods[i - 1]
        curr = fingerprint_periods[i]
        renewal_time = _known_timestamp(curr["first_scanned_at"])
        prev_not_after = _known_timestamp(prev["not_after"])
        if renewal_time is None or prev_not_after is None:
            continue
        lead_days = (prev_not_after - renewal_time).total_seconds() / 86400
        renewal_lead_times.append(round(lead_days, 1))

    median_lead_time = statistics.median(renewal_lead_times) if renewal_lead_times else None

    cadence_intervals: list[float] = []
    for i in range(1, len(fingerprint_periods)):
        prev_first = _known_timestamp(fingerprint_periods[i - 1]["first_scanned_at"])
        curr_first = _known_timestamp(fingerprint_periods[i]["first_scanned_at"])
        if prev_first is None or curr_first is None or curr_first <= prev_first:
            continue
        interval = (curr_first - prev_first).total_seconds() / 86400
        cadence_intervals.append(round(interval, 1))

    median_cadence_days = statistics.median(cadence_intervals) if cadence_intervals else None

    classification, evidence = _classify_automation(
        fingerprint_periods, observed_lifetimes, cadence_intervals, renewal_lead_times
    )

    return HostRenewalAnalytics(
        hostname=hostname,
        observed_lifetimes=observed_lifetimes,
        lifetime_trend=lifetime_trend,
        renewal_lead_times=renewal_lead_times,
        median_lead_time=median_lead_time,
        median_cadence_days=median_cadence_days,
        automation_classification=classification,
        classification_evidence=evidence,
        cert_count=cert_count,
        port=port,
    )


def compute_host_analytics(
    db_path: str | Path,
    hostname: str,
    *,
    port: int | None = None,
    scope_tags: tuple[str, ...] = (),
) -> HostRenewalAnalytics:
    init_schema(db_path)

    if scope_tags and port is not None:
        from cert_watch.database.dashboard_helpers import _add_effective_tag_filter

        scope_sql = "SELECT 1 FROM hosts h WHERE h.hostname = ?"
        scope_params: list[Any] = [hostname]
        if port is not None:
            scope_sql += " AND h.port = ?"
            scope_params.append(port)
        scope_sql, scope_params = _add_effective_tag_filter(
            scope_sql, scope_params, scope_tags, col_cert=None, col_host="h.tags"
        )
        scope_sql += " LIMIT 1"
        with _connect(db_path) as conn:
            row = conn.execute(scope_sql, scope_params).fetchone()
        if row is None:
            return _compute_host_from_entries(hostname, [], port=port)

    if port is not None:
        with _connect(db_path) as conn:
            rows = conn.execute(
                """SELECT hostname, fingerprint_sha256, issuer, not_after, not_before, scanned_at
                   FROM cert_history
                   WHERE hostname = ? AND port = ?
                   ORDER BY scanned_at ASC""",
                (hostname, port),
            ).fetchall()
    elif scope_tags:
        from cert_watch.database.dashboard_helpers import _add_effective_tag_filter

        sql = (
            "SELECT ch.hostname, ch.fingerprint_sha256, ch.issuer, ch.not_after,"
            " ch.not_before, ch.scanned_at FROM cert_history ch"
            " JOIN hosts h ON h.hostname = ch.hostname AND h.port = ch.port"
            " WHERE ch.hostname = ?"
        )
        sql, params = _add_effective_tag_filter(
            sql, [hostname], scope_tags, col_cert=None, col_host="h.tags"
        )
        sql += " ORDER BY ch.scanned_at ASC"
        with _connect(db_path) as conn:
            rows = conn.execute(sql, params).fetchall()
    else:
        with _connect(db_path) as conn:
            rows = conn.execute(
                """SELECT hostname, fingerprint_sha256, issuer, not_after, not_before, scanned_at
                   FROM cert_history
                   WHERE hostname = ?
                   ORDER BY scanned_at ASC""",
                (hostname,),
            ).fetchall()

    entries = [dict(r) for r in rows]
    return _compute_host_from_entries(hostname, entries, port=port)


def compute_fleet_analytics(
    db_path: str | Path, scope_tags: tuple[str, ...] = ()
) -> list[HostRenewalAnalytics]:
    init_schema(db_path)

    if scope_tags:
        from cert_watch.database.dashboard_helpers import _add_effective_tag_filter

        sql = (
            "SELECT ch.hostname, ch.port, ch.fingerprint_sha256, ch.issuer,"
            " ch.not_after, ch.not_before, ch.scanned_at"
            " FROM cert_history ch"
            " JOIN hosts h ON h.hostname = ch.hostname AND h.port = ch.port"
            " WHERE ch.hostname IS NOT NULL"
        )
        sql, params = _add_effective_tag_filter(
            sql, [], scope_tags, col_cert=None, col_host="h.tags"
        )
        sql += " ORDER BY ch.hostname, ch.port, ch.scanned_at ASC"
        with _connect(db_path) as conn:
            rows = conn.execute(sql, params).fetchall()
    else:
        with _connect(db_path) as conn:
            rows = conn.execute(
                """SELECT hostname, port, fingerprint_sha256, issuer,
                          not_after, not_before, scanned_at
                   FROM cert_history
                   WHERE hostname IS NOT NULL
                   ORDER BY hostname, port, scanned_at ASC"""
            ).fetchall()

    from collections import defaultdict
    by_host: dict[tuple[str, int | None], list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        d = dict(r)
        by_host[(d["hostname"], d.get("port", 0))].append(d)

    results: list[HostRenewalAnalytics] = []
    ordered = sorted(
        by_host.items(),
        key=lambda item: (
            item[0][0].casefold(), item[0][1] is not None, item[0][1] or 0,
        ),
    )
    for (hostname, port), entries in ordered:
        results.append(_compute_host_from_entries(hostname, entries, port=port))
    return results


def detect_renewal_overdue(
    db_path: str | Path, hostname: str, *, port: int | None = None
) -> RenewalOverdueSignal | None:
    from datetime import UTC, datetime, timedelta

    analytics = compute_host_analytics(db_path, hostname, port=port)
    if analytics.cert_count < 2 or analytics.median_lead_time is None:
        return None
    if analytics.median_lead_time <= 0:
        return None

    init_schema(db_path)
    with _connect(db_path) as conn:
        if port is not None:
            row = conn.execute(
                """SELECT fingerprint_sha256, not_after
                   FROM cert_history
                   WHERE hostname = ? AND port = ?
                   ORDER BY scanned_at DESC
                   LIMIT 1""",
                (hostname, port),
            ).fetchone()
        else:
            row = conn.execute(
                """SELECT fingerprint_sha256, not_after
                   FROM cert_history
                   WHERE hostname = ?
                   ORDER BY scanned_at DESC
                   LIMIT 1""",
                (hostname,),
            ).fetchone()
    if row is None:
        return None

    current_fp = row["fingerprint_sha256"]
    not_after = _parse_iso(row["not_after"])
    days_remaining = (not_after - datetime.now(UTC)).total_seconds() / 86400

    if days_remaining >= analytics.median_lead_time:
        return None

    expected_renewal_point = not_after - timedelta(days=analytics.median_lead_time)
    # The current deployment period starts after the most recent observation
    # of a different fingerprint on this endpoint. This keeps another port's
    # history and an earlier A in an A-B-A rollback from making current A look
    # older than it is.
    with _connect(db_path) as conn:
        if port is not None:
            first_seen_row = conn.execute(
                """SELECT MIN(scanned_at) AS first_seen FROM cert_history
                   WHERE hostname = ? AND port = ? AND fingerprint_sha256 = ?
                     AND scanned_at > COALESCE((
                         SELECT MAX(scanned_at) FROM cert_history
                         WHERE hostname = ? AND port = ? AND fingerprint_sha256 != ?
                     ), '')""",
                (hostname, port, current_fp, hostname, port, current_fp),
            ).fetchone()
        else:
            first_seen_row = conn.execute(
                """SELECT MIN(scanned_at) AS first_seen FROM cert_history
                   WHERE hostname = ? AND fingerprint_sha256 = ?
                     AND scanned_at > COALESCE((
                         SELECT MAX(scanned_at) FROM cert_history
                         WHERE hostname = ? AND fingerprint_sha256 != ?
                     ), '')""",
                (hostname, current_fp, hostname, current_fp),
            ).fetchone()
    if first_seen_row is not None and first_seen_row["first_seen"]:
        first_seen = _parse_iso(first_seen_row["first_seen"])
        if first_seen > expected_renewal_point:
            return None

    renewal_count = analytics.cert_count - 1
    if renewal_count >= 5:
        confidence = "high"
    elif renewal_count >= 3:
        confidence = "medium"
    else:
        confidence = "low"

    days_overdue = analytics.median_lead_time - days_remaining

    return RenewalOverdueSignal(
        hostname=hostname,
        cert_fingerprint=current_fp,
        days_remaining=round(days_remaining, 1),
        expected_renewal_at_days=analytics.median_lead_time,
        days_overdue=round(days_overdue, 1),
        confidence=confidence,
        port=port,
    )
