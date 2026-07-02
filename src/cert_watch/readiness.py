"""SC-081 readiness report: milestone timeline, per-host margin analysis, workload forecast."""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypedDict

from cert_watch.database.connection import _connect
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



def _batch_chain_statuses(db_path: str | Path, hostnames: list[str]) -> dict[str, str | None]:
    if not hostnames:
        return {}
    placeholders = ",".join("?" * len(hostnames))
    with _connect(db_path) as conn:
        rows = conn.execute(
            f"""SELECT c.hostname, sp.chain_status FROM scan_posture sp
                JOIN certificates c ON c.id = sp.cert_id
                WHERE c.is_leaf = 1 AND c.hostname IN ({placeholders})
                ORDER BY sp.scanned_at DESC""",
            hostnames,
        ).fetchall()
    # First (latest) row wins, even when its chain_status is NULL — a `seen`
    # set rather than a sentinel value keeps NULL from looking like "no row"
    # (the NULL-collision bug this replaced).
    result: dict[str, str | None] = dict.fromkeys(hostnames)
    seen: set[str] = set()
    for row in rows:
        hn = row["hostname"]
        if hn in result and hn not in seen:
            result[hn] = row["chain_status"]
            seen.add(hn)
    return result


def _compute_margins(
    lead_time: float | None,
    lifetime: int | None,
) -> list[dict[str, Any]]:
    margins: list[dict[str, Any]] = []
    for ms in SC081_MILESTONES:
        max_days = ms["max_days"]
        if lead_time is not None:
            margin_days = lead_time
            margin_pct = round(lead_time / max_days * 100, 1) if max_days else 0.0
            renew_late = lead_time > max_days
        else:
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
    analytics: HostRenewalAnalytics,
    chain_status: str | None,
) -> HostReadiness:
    lead_time = analytics.median_lead_time
    lifetimes = analytics.observed_lifetimes
    current_lifetime = int(statistics.median(lifetimes)) if lifetimes else None

    is_private = chain_status == "private"

    return HostReadiness(
        hostname=analytics.hostname,
        classification=analytics.automation_classification,
        current_lead_time=lead_time,
        current_lifetime=current_lifetime,
        margins=_compute_margins(lead_time, current_lifetime) if not is_private else [],
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
                    hosts_by_risk[label].append(h.hostname)

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
    fleet = compute_fleet_analytics(db_path, scope_tags=scope_tags)

    hostnames = [a.hostname for a in fleet]
    chain_statuses = _batch_chain_statuses(db_path, hostnames)

    public_hosts: list[HostReadiness] = []
    private_hosts: list[HostReadiness] = []
    unknown_hosts: list[HostReadiness] = []

    for a in fleet:
        cs = chain_statuses.get(a.hostname)
        readiness = _compute_host_readiness(a, cs)
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
        total_hosts=len(fleet),
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
