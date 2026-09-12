"""SC-081 readiness report: milestone timeline, per-host margin analysis, workload forecast."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from math import ceil
from pathlib import Path
from typing import Any, TypedDict

from cert_watch.database.connection import _connect, _parse_iso
from cert_watch.database.dashboard_helpers import _add_effective_tag_filter
from cert_watch.database.schema import init_schema
from cert_watch.renewal_analytics import HostRenewalAnalytics, compute_fleet_analytics


class _Milestone(TypedDict):
    label: str
    max_days: int
    date: str


SC081_MILESTONES: list[_Milestone] = [
    {"label": "200d", "max_days": 200, "date": "2026-03-15"},
    {"label": "100d", "max_days": 100, "date": "2027-03-15"},
    {"label": "47d", "max_days": 47, "date": "2029-03-15"},
]


@dataclass
class HostReadiness:
    hostname: str
    classification: str
    current_lead_time: float | None
    current_lifetime: int | None
    margins: list[dict[str, Any]] = field(default_factory=list)
    chain_status: str | None = None
    port: int | None = None


@dataclass
class WorkloadForecast:
    current_renewals_per_month: float
    at_100d_renewals_per_month: float
    at_47d_renewals_per_month: float
    hosts_by_milestone_risk: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class ReadinessReport:
    generated_at: str
    total_hosts: int
    public_trust_hosts: int
    private_ca_hosts: int
    unknown_hosts: int
    milestones: list[dict[str, Any]] = field(default_factory=list)
    hosts: list[HostReadiness] = field(default_factory=list)
    private_hosts: list[HostReadiness] = field(default_factory=list)
    unknown_hosts_list: list[HostReadiness] = field(default_factory=list)
    workload_forecast: WorkloadForecast | None = None



def _current_endpoints(
    db_path: str | Path, scope_tags: tuple[str, ...]
) -> list[dict[str, Any]]:
    """Monitored endpoints, including those without any successful observation.

    Readiness has always used host-tag visibility, like renewal analytics.
    Preserve that boundary; certificate tags alone do not expose another host.
    A current leaf's validity and trust must come from that same certificate,
    not another port, historical deployment, or uploaded certificate.
    """
    sql = """SELECT h.hostname, h.port, c.not_before, c.not_after,
                (SELECT sp.chain_status FROM scan_posture sp WHERE sp.cert_id = c.id
                 ORDER BY sp.scanned_at DESC, sp.rowid DESC LIMIT 1) AS chain_status
             FROM hosts h
             LEFT JOIN certificates c ON c.id = (
                 SELECT current.id FROM certificates current
                 WHERE current.hostname = h.hostname AND current.port = h.port
                   AND current.is_leaf = 1 AND current.source = 'scanned'
                 ORDER BY current.created_at DESC, current.rowid DESC LIMIT 1
             )
             WHERE 1 = 1"""
    sql, params = _add_effective_tag_filter(
        sql, [], scope_tags, col_cert=None, col_host="h.tags",
    )
    sql += " ORDER BY h.hostname, h.port"
    with _connect(db_path) as conn:
        return [dict(row) for row in conn.execute(sql, params).fetchall()]


def _current_lifetime(endpoint: dict[str, Any]) -> int | None:
    """Actual certificate validity, rounded up to avoid understating cap risk."""
    if not endpoint["not_before"] or not endpoint["not_after"]:
        return None
    try:
        duration = _parse_iso(endpoint["not_after"]) - _parse_iso(endpoint["not_before"])
    except (ValueError, TypeError):
        return None
    seconds = duration.total_seconds()
    return ceil(seconds / 86400) if seconds > 0 else None


def _compute_margins(lifetime: int | None) -> list[dict[str, Any]]:
    """SC-081 caps certificate VALIDITY (lifetime), not renewal lead time.

    A cert is non-compliant at a milestone when its lifetime exceeds the cap;
    the margin is how much validity sits under the cap (positive, compliant) or
    over it (negative, non-compliant). Renewal lead time is reported separately
    on the host and is not a SC-081 factor.
    """
    margins: list[dict[str, Any]] = []
    for ms in SC081_MILESTONES:
        max_days = ms["max_days"]
        if lifetime is not None:
            margin_days = max_days - lifetime
            margin_pct = round(margin_days / max_days * 100, 1) if max_days else 0.0
            renew_late = lifetime > max_days
        else:
            # No usable current certificate validity: can't confirm
            # compliance — flag conservatively for operator review.
            margin_days = None
            margin_pct = None
            renew_late = True
        margins.append({
            "milestone": ms["label"],
            "max_days": max_days,
            "margin_days": margin_days,
            "margin_pct": margin_pct,
            "renew_late": renew_late,
        })
    return margins


def _compute_host_readiness(
    endpoint: dict[str, Any],
    analytics: HostRenewalAnalytics | None,
) -> HostReadiness:
    """Current scan supplies validity/trust; history supplies qualified inference."""
    chain_status = endpoint["chain_status"]
    current_lifetime = _current_lifetime(endpoint)
    is_private = chain_status == "private"

    return HostReadiness(
        hostname=endpoint["hostname"],
        port=endpoint["port"],
        classification=analytics.automation_classification if analytics else "unknown",
        current_lead_time=analytics.median_lead_time if analytics else None,
        current_lifetime=current_lifetime,
        margins=_compute_margins(current_lifetime) if not is_private else [],
        chain_status=chain_status,
    )


def _compute_workload_forecast(
    public_hosts: list[HostReadiness],
) -> WorkloadForecast:
    if not public_hosts:
        return WorkloadForecast(
            current_renewals_per_month=0.0,
            at_100d_renewals_per_month=0.0,
            at_47d_renewals_per_month=0.0,
            hosts_by_milestone_risk={},
        )

    total_current = 0.0
    total_100d = 0.0
    total_47d = 0.0
    hosts_by_risk: dict[str, list[str]] = {ms["label"]: [] for ms in SC081_MILESTONES}

    for h in public_hosts:
        lt = h.current_lifetime
        if lt and lt > 0:
            total_current += 365.0 / lt / 12.0
        else:
            total_current += 0.0

        total_100d += 365.0 / 100 / 12.0
        total_47d += 365.0 / 47 / 12.0

        for m in h.margins:
            if m.get("renew_late"):
                label = m["milestone"]
                if label in hosts_by_risk:
                    hosts_by_risk[label].append(
                        f"{h.hostname}:{h.port}" if h.port not in (None, 443) else h.hostname
                    )

    return WorkloadForecast(
        current_renewals_per_month=round(total_current, 1),
        at_100d_renewals_per_month=round(total_100d, 1),
        at_47d_renewals_per_month=round(total_47d, 1),
        hosts_by_milestone_risk=hosts_by_risk,
    )


def build_readiness_report(
    db_path: str | Path, scope_tags: tuple[str, ...] = ()
) -> ReadinessReport:
    init_schema(db_path)
    endpoints = _current_endpoints(db_path, scope_tags)
    analytics_by_endpoint = {
        (analytics.hostname, analytics.port): analytics
        for analytics in compute_fleet_analytics(db_path, scope_tags=scope_tags)
    }

    public_hosts: list[HostReadiness] = []
    private_hosts: list[HostReadiness] = []
    unknown_hosts: list[HostReadiness] = []

    for endpoint in endpoints:
        cs = endpoint["chain_status"]
        analytics = analytics_by_endpoint.get((endpoint["hostname"], endpoint["port"]))
        readiness = _compute_host_readiness(endpoint, analytics)
        if cs == "private":
            private_hosts.append(readiness)
        elif cs == "public":
            public_hosts.append(readiness)
        else:
            unknown_hosts.append(readiness)

    milestones = [
        {"label": ms["label"], "max_days": ms["max_days"], "date": ms["date"]}
        for ms in SC081_MILESTONES
    ]

    forecast = _compute_workload_forecast(public_hosts)

    return ReadinessReport(
        generated_at=datetime.now(UTC).isoformat(),
        total_hosts=len(endpoints),
        public_trust_hosts=len(public_hosts),
        private_ca_hosts=len(private_hosts),
        unknown_hosts=len(unknown_hosts),
        milestones=milestones,
        hosts=public_hosts,
        private_hosts=private_hosts,
        unknown_hosts_list=unknown_hosts,
        workload_forecast=forecast,
    )


def readiness_report_to_dict(report: ReadinessReport) -> dict[str, Any]:
    def _host_dict(h: HostReadiness) -> dict[str, Any]:
        return {
            "hostname": h.hostname,
            "port": h.port,
            "classification": h.classification,
            "current_lead_time": h.current_lead_time,
            "current_lifetime": h.current_lifetime,
            "margins": h.margins,
            "chain_status": h.chain_status,
        }

    d: dict[str, Any] = {
        "generated_at": report.generated_at,
        "total_hosts": report.total_hosts,
        "public_trust_hosts": report.public_trust_hosts,
        "private_ca_hosts": report.private_ca_hosts,
        "unknown_hosts": report.unknown_hosts,
        "milestones": report.milestones,
        "hosts": [_host_dict(h) for h in report.hosts],
        "private_hosts": [_host_dict(h) for h in report.private_hosts],
        "unknown_hosts_list": [_host_dict(h) for h in report.unknown_hosts_list],
    }

    if report.workload_forecast is not None:
        wf = report.workload_forecast
        d["workload_forecast"] = {
            "current_renewals_per_month": wf.current_renewals_per_month,
            "at_100d_renewals_per_month": wf.at_100d_renewals_per_month,
            "at_47d_renewals_per_month": wf.at_47d_renewals_per_month,
            "hosts_by_milestone_risk": wf.hosts_by_milestone_risk,
        }

    return d
