"""Typed presentation model for the operator Home page."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any
from urllib.parse import urlencode

from cert_watch.filters import issuer_cn, subject_cn
from cert_watch.scan_error_guidance import describe_scan_error


class Tone(StrEnum):
    """Template-safe status tone names."""

    NEUTRAL = ""
    WARNING = "t-warn"
    CRITICAL = "t-crit"


@dataclass(frozen=True)
class HomeRiskRow:
    detail_url: str
    name: str
    condition: str
    condition_label: str
    tone: str
    owner_name: str
    difference: str
    chain_url: str | None = None
    chain_label: str = ""


@dataclass(frozen=True)
class HomeMonitoringRow:
    detail_url: str
    name: str
    state: str
    state_label: str
    tone: str
    when_label: str
    when_prefix: str
    when_time_label: str
    last_success_label: str
    cause: str
    cause_time_label: str
    cause_is_raw: bool
    owner_name: str


@dataclass(frozen=True)
class HomeChainGroup:
    issuer: str
    count: int
    browse_url: str
    guidance: str
    examples: tuple[str, ...]
    fix: str = "missing"


@dataclass(frozen=True)
class HomeChainFix:
    """Issuers that need the same fix, so its guidance prints once."""

    fix: str
    label: str
    guidance: str
    groups: tuple[HomeChainGroup, ...]


@dataclass(frozen=True)
class DeliveryLine:
    label: str
    detail: str
    tone: str
    action_url: str | None
    action_label: str
    admin_only: bool


@dataclass(frozen=True)
class HorizonBucketView:
    bucket_start: str
    bucket_label: str
    count: int
    tone: str
    bar_height: int
    browse_url: str
    title: str

    def __getitem__(self, key: str) -> Any:
        """Retain mapping access for route-level tests."""
        return getattr(self, key)


@dataclass(frozen=True)
class HomeView:
    axis_stats: dict[str, dict[str, int]]
    tracked_total: int
    monitored_total: int
    risk_rows: tuple[HomeRiskRow, ...]
    monitoring_rows: tuple[HomeMonitoringRow, ...]
    chain_groups: tuple[HomeChainGroup, ...]
    chain_fixes: tuple[HomeChainFix, ...]
    chain_problem_total: int
    chain_issuer_total: int
    delivery_lines: tuple[DeliveryLine, ...]
    last_scan_activity_label: str
    next_run_label: str
    horizon: tuple[HorizonBucketView, ...]
    error: str | None
    warning: str | None
    saved: str | None

    def template_context(self) -> dict[str, Any]:
        """Return the stable template boundary for the page."""
        return {
            "axis_stats": self.axis_stats,
            "tracked_total": self.tracked_total,
            "monitored_total": self.monitored_total,
            "risk_rows": list(self.risk_rows),
            "monitoring_rows": list(self.monitoring_rows),
            "chain_groups": list(self.chain_groups),
            "chain_fixes": list(self.chain_fixes),
            "chain_problem_total": self.chain_problem_total,
            "chain_issuer_total": self.chain_issuer_total,
            "delivery_lines": list(self.delivery_lines),
            "last_scan_activity_label": self.last_scan_activity_label,
            "next_run_label": self.next_run_label,
            "horizon": list(self.horizon),
            "error": self.error,
            "warning": self.warning,
            "saved": self.saved,
        }


def _parse_datetime(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _format_datetime(value: object) -> str:
    parsed = _parse_datetime(value)
    return parsed.strftime("%Y-%m-%d %H:%M UTC") if parsed is not None else "Not yet"


def _endpoint_name(row: dict[str, Any]) -> str:
    host = str(row.get("host") or "")
    if row.get("source") == "uploaded" or not row.get("host_id"):
        return subject_cn(str(row.get("subject") or "")) or host or "Uploaded certificate"
    return host.removesuffix(":443")


_TRUST_PROBLEMS = {"incomplete", "invalid", "unknown", "self-signed", "unverified"}


def _renewal_method_label(value: object) -> str:
    method = str(value or "")
    return {"acme": "ACME", "cert-manager": "cert-manager"}.get(method.casefold(), method)


def _risk_difference(row: dict[str, Any]) -> str:
    details: list[str] = []
    if row.get("source") == "uploaded" or not row.get("host_id"):
        details.append("Uploaded file — replace by upload")
    else:
        renewal = str(row.get("renewal") or "")
        method = _renewal_method_label(row.get("renewal_method"))
        if renewal in {"failed", "not_deployed"}:
            failed = renewal == "failed"
            label = "Renewal failed" if failed else "Deployment not confirmed"
            when = row.get("renewal_failure_reported_at" if failed else "renewal_raised_at")
            details.append(f"{label} · {_format_datetime(when)}")
        elif renewal == "manual":
            details.append("Manual renewal")
        elif renewal == "in_progress":
            details.append("Renewal in progress (operator report)")
        elif renewal == "stalled" and method:
            # A manual method is not something that is "configured" to renew.
            if method.casefold() == "manual":
                details.append("Manual renewal — no new certificate yet")
            else:
                details.append(f"{method} configured — no new certificate yet")
    return " · ".join(details)


def _chain_browse_url(raw_issuer: str) -> str:
    query: dict[str, str | int] = {"chain_problem": "1"}
    if raw_issuer:
        query["issuer"] = raw_issuer
    query["grouped"] = 0
    return "/browse?" + urlencode(query)


def _risk_chain(row: dict[str, Any]) -> tuple[str | None, str]:
    """Return the hygiene cross-reference for a risk row with an unverified chain."""
    if str(row.get("chain_status") or "") not in _TRUST_PROBLEMS:
        return None, ""
    raw_issuer = str(row.get("issuer") or "")
    issuer = issuer_cn(raw_issuer)
    label = "Chain can\u2019t be verified"
    if issuer:
        label += f" \u2014 view certificates issued by {issuer}"
    return _chain_browse_url(raw_issuer), label


def _condition_label(days: int | None) -> str:
    if days is None:
        return "Expiry unknown"
    if days < 0:
        age = -days
        return f"Expired {age} day{'s' if age != 1 else ''} ago"
    if days == 0:
        return "Expires today"
    return f"{days} day{'s' if days != 1 else ''} left"


def _risk_rows(raw_rows: dict[str, list[dict[str, Any]]]) -> tuple[HomeRiskRow, ...]:
    expiry_rows = [
        row for state in ("expired", "le7", "8to30") for row in raw_rows.get(f"risk:{state}", [])
    ]
    expiry_rows.sort(
        key=lambda row: (
            row.get("effective_days") is None,
            int(row.get("effective_days") or 0),
            _endpoint_name(row),
        )
    )
    renewal_rows = [
        row
        for state in ("failed", "not_deployed")
        for row in raw_rows.get(f"risk:renewal:{state}", [])
    ]

    def present(row: dict[str, Any], *, renewal_problem: bool) -> HomeRiskRow:
        renewal = str(row.get("renewal") or "")
        if renewal_problem:
            failed = renewal == "failed"
            condition_label = "Renewal failed" if failed else "Deployment not confirmed"
            when = row.get("renewal_failure_reported_at" if failed else "renewal_raised_at")
            difference = f"{'Reported' if failed else 'Raised'} {_format_datetime(when)}"
        else:
            condition_label = _condition_label(row.get("effective_days"))
            difference = _risk_difference(row)
        chain_url, chain_label = _risk_chain(row)
        return HomeRiskRow(
            detail_url=f"/certificates/{row['id']}",
            name=_endpoint_name(row),
            condition=renewal if renewal_problem else str(row.get("condition") or ""),
            condition_label=condition_label,
            tone=(
                Tone.CRITICAL
                if renewal_problem or row.get("condition") in {"expired", "le7"}
                else Tone.WARNING
            ),
            owner_name=str(row.get("owner_name") or ""),
            difference=difference,
            chain_url=chain_url,
            chain_label=chain_label,
        )

    return tuple(
        [present(row, renewal_problem=False) for row in expiry_rows]
        + [present(row, renewal_problem=True) for row in renewal_rows]
    )


def _monitoring_rows(
    raw_rows: dict[str, list[dict[str, Any]]],
) -> tuple[HomeMonitoringRow, ...]:
    result: list[HomeMonitoringRow] = []
    for state in ("failing", "never_scanned"):
        for row in raw_rows.get(f"monitoring:{state}", []):
            raw_error = row.get("monitoring_error") or row.get("scan_error")
            guidance = describe_scan_error(str(raw_error)) if raw_error else None
            since = row.get("monitoring_since") or row.get("added_at")
            overdue = (
                state == "failing"
                and row.get("monitoring_attempt_status") == "success"
                and bool(row.get("monitoring_last_success"))
            )
            if overdue:
                cause_time_label = _format_datetime(since)
                cause = f"Scan overdue since {cause_time_label}."
            elif guidance is not None:
                cause_time_label = ""
                cause = guidance.cause
            elif raw_error:
                cause_time_label = ""
                compact = " ".join(str(raw_error).split())
                cause = compact if len(compact) <= 160 else compact[:159].rstrip() + "…"
            elif state == "never_scanned":
                cause_time_label = ""
                cause = "No scan attempt has been recorded; check the endpoint and scan settings."
            else:
                cause_time_label = ""
                cause = "The latest scan attempt failed."
            when_label = ""
            when_prefix = ""
            when_time_label = ""
            if not overdue:
                when_prefix = "added" if state == "never_scanned" else "since"
                when_time_label = _format_datetime(since)
                when_label = f"{when_prefix} {when_time_label}"
            result.append(
                HomeMonitoringRow(
                    detail_url=f"/certificates/{row['id']}",
                    name=_endpoint_name(row),
                    state=state,
                    state_label=(
                        "Overdue"
                        if overdue
                        else "Failing"
                        if state == "failing"
                        else "Never scanned"
                    ),
                    tone=Tone.WARNING,
                    when_label=when_label,
                    when_prefix=when_prefix,
                    when_time_label=when_time_label,
                    last_success_label=_format_datetime(row.get("monitoring_last_success")),
                    cause=cause,
                    cause_time_label=cause_time_label,
                    cause_is_raw=bool(raw_error) and guidance is None and not overdue,
                    owner_name=str(row.get("owner_name") or ""),
                )
            )
    return tuple(result)


def _chain_groups(raw: list[dict[str, Any]]) -> tuple[HomeChainGroup, ...]:
    result: list[HomeChainGroup] = []
    for group in raw:
        raw_issuer = str(group.get("issuer") or "")
        statuses = set(str(group.get("statuses") or "").split(","))
        fix = (
            "self_signed"
            if "self-signed" in statuses
            else "invalid"
            if "invalid" in statuses
            else "missing"
        )
        guidance = _CHAIN_FIXES[fix][1]
        examples: list[str] = []
        for index in (1, 2):
            hostname = str(group.get(f"example_{index}_hostname") or "")
            port = group.get(f"example_{index}_port")
            subject = str(group.get(f"example_{index}_subject") or "")
            if hostname:
                examples.append(hostname if port in (None, 443) else f"{hostname}:{port}")
            elif subject:
                examples.append(f"{subject_cn(subject) or 'Uploaded certificate'} (uploaded)")
        result.append(
            HomeChainGroup(
                issuer=issuer_cn(raw_issuer) or "Unknown issuer",
                count=int(group.get("count") or 0),
                browse_url=_chain_browse_url(raw_issuer),
                guidance=guidance,
                examples=tuple(examples),
                fix=fix,
            )
        )
    return tuple(sorted(result, key=lambda group: (-group.count, group.issuer.casefold())))


# Fix kind -> (heading, guidance), in display order.
_CHAIN_FIXES: dict[str, tuple[str, str]] = {
    "invalid": ("Invalid chain", "Replace the invalid chain, then scan again."),
    "missing": (
        "Missing intermediate or private CA",
        "Serve the intermediate with the leaf, or add a private CA in Trust anchors.",
    ),
    "self_signed": (
        "Self-signed",
        "Add this issuer in Trust anchors, or replace the self-signed certificate.",
    ),
}


def _chain_fixes(groups: tuple[HomeChainGroup, ...]) -> tuple[HomeChainFix, ...]:
    return tuple(
        HomeChainFix(
            fix=fix,
            label=label,
            guidance=guidance,
            groups=tuple(group for group in groups if group.fix == fix),
        )
        for fix, (label, guidance) in _CHAIN_FIXES.items()
        if any(group.fix == fix for group in groups)
    )


def _delivery_lines(
    *,
    tracked_total: int,
    failing: int,
    smtp_configured: bool,
    webhook_configured: bool,
    webhook_kind: str,
    webhook_outcome: object,
    webhook_failed_at: object,
    routing_gap_total: int,
    monitoring_gap_total: int,
) -> tuple[DeliveryLine, ...]:
    if tracked_total == 0:
        return (
            DeliveryLine(
                label="No alerts to route yet",
                detail="Add a monitored endpoint or uploaded certificate to begin.",
                tone=Tone.NEUTRAL,
                action_url=None,
                action_label="",
                admin_only=False,
            ),
        )
    lines: list[DeliveryLine] = []
    if webhook_configured and webhook_outcome in {"failed", "partial", "unknown"}:
        kind = str(webhook_kind or "generic").replace("_", " ").title()
        failed_at = _format_datetime(webhook_failed_at)
        lines.append(
            DeliveryLine(
                label=f"{kind} webhook failing",
                detail=(
                    f"Last failed {failed_at}."
                    if failed_at != "Not yet"
                    else "The latest delivery was not accepted."
                ),
                tone=Tone.CRITICAL,
                action_url="/settings/channels",
                action_label="Channels",
                admin_only=True,
            )
        )
    if not smtp_configured:
        lines.append(
            DeliveryLine(
                label="Email not configured",
                detail="SMTP is not configured; email routes cannot deliver.",
                tone=Tone.WARNING,
                action_url="/settings/channels",
                action_label="Set up SMTP",
                admin_only=True,
            )
        )
    if failing and not lines:
        lines.append(
            DeliveryLine(
                label="Some routes cannot deliver",
                detail="Open the filtered certificate list to review the affected routes.",
                tone=Tone.CRITICAL,
                action_url=None,
                action_label="",
                admin_only=False,
            )
        )
    if not lines:
        lines.append(
            DeliveryLine(
                label="All configured channels are delivering",
                detail="No delivery failure is recorded for the visible estate.",
                tone=Tone.NEUTRAL,
                action_url=None,
                action_label="",
                admin_only=False,
            )
        )
    if routing_gap_total:
        noun = "certificate" if routing_gap_total == 1 else "certificates"
        verb = "has" if routing_gap_total == 1 else "have"
        lines.append(
            DeliveryLine(
                label=f"{routing_gap_total} {noun} {verb} no owner and no alert group",
                detail="Their alerts use only globally configured delivery channels.",
                tone=Tone.NEUTRAL,
                action_url="/browse?routing_gap=1&grouped=0",
                action_label=f"View {routing_gap_total}",
                admin_only=False,
            )
        )
    if monitoring_gap_total:
        noun = "endpoint is" if monitoring_gap_total == 1 else "endpoints are"
        lines.append(
            DeliveryLine(
                label="Scan failures aren\u2019t alerted",
                detail=(
                    f"{monitoring_gap_total} {noun} failing, overdue, or unscanned; "
                    "certificate alerts do not cover scan failures."
                ),
                tone=Tone.NEUTRAL,
                action_url="/settings/events",
                action_label="Alert settings",
                admin_only=True,
            )
        )
    return tuple(lines)


def _horizon(raw: list[dict[str, Any]], current: datetime) -> tuple[HorizonBucketView, ...]:
    monday = (current - timedelta(days=current.weekday())).date()
    buckets = {str(bucket["bucket_start"]): bucket for bucket in raw}
    counts = {key: int(bucket.get("count") or 0) for key, bucket in buckets.items()}
    maximum = max(counts.values(), default=0)
    result: list[HorizonBucketView] = []
    for offset in range(12):
        bucket_date = monday + timedelta(weeks=offset)
        bucket_start = bucket_date.isoformat()
        bucket_label = f"{bucket_date.strftime('%b')} {bucket_date.day}"
        count = counts.get(bucket_start, 0)
        raw_tone = str(buckets.get(bucket_start, {}).get("tone") or "neutral")
        tone = {
            "critical": Tone.CRITICAL,
            "warning": Tone.WARNING,
        }.get(raw_tone, Tone.NEUTRAL)
        height = 2 if count == 0 or maximum == 0 else max(7, round(count / maximum * 44))
        result.append(
            HorizonBucketView(
                bucket_start=bucket_start,
                bucket_label=bucket_label,
                count=count,
                tone=tone,
                bar_height=height,
                browse_url="/browse?" + urlencode({"expiry_week": bucket_start, "grouped": 0}),
                title=(
                    f"Week of {bucket_label}: {count} "
                    f"certificate{'s' if count != 1 else ''} — open in Browse"
                ),
            )
        )
    return tuple(result)


def present_home(
    *,
    axis_stats: dict[str, dict[str, int]],
    home_data: dict[str, Any],
    smtp_configured: bool,
    webhook_configured: bool,
    webhook_kind: str,
    sched_hour: int,
    sched_min: int,
    now: datetime | None = None,
    error: str | None = None,
    warning: str | None = None,
    saved: str | None = None,
) -> HomeView:
    """Build Home A without HTTP, database, or template dependencies."""
    current = now or datetime.now(UTC)
    next_run = current.replace(hour=sched_hour, minute=sched_min, second=0, microsecond=0)
    if next_run <= current:
        next_run += timedelta(days=1)
    monitoring = axis_stats["monitoring"]
    delivery = axis_stats["delivery"]
    raw_chain_groups = list(home_data.get("chain_groups") or [])
    chain_problem_total = (
        int(raw_chain_groups[0].get("total_certs") or 0) if raw_chain_groups else 0
    )
    chain_issuer_total = (
        int(raw_chain_groups[0].get("total_issuers") or 0) if raw_chain_groups else 0
    )
    chain_groups = _chain_groups(raw_chain_groups)
    return HomeView(
        axis_stats=axis_stats,
        tracked_total=int(home_data.get("tracked_total") or 0),
        monitored_total=sum(int(monitoring[state]) for state in monitoring),
        risk_rows=_risk_rows(home_data.get("rows") or {}),
        monitoring_rows=_monitoring_rows(home_data.get("rows") or {}),
        chain_groups=chain_groups,
        chain_fixes=_chain_fixes(chain_groups),
        chain_problem_total=chain_problem_total,
        chain_issuer_total=chain_issuer_total,
        delivery_lines=_delivery_lines(
            tracked_total=int(home_data.get("tracked_total") or 0),
            failing=int(delivery["failing"]),
            smtp_configured=smtp_configured,
            webhook_configured=webhook_configured,
            webhook_kind=webhook_kind,
            webhook_outcome=home_data.get("webhook_outcome"),
            webhook_failed_at=home_data.get("webhook_failed_at"),
            routing_gap_total=int(home_data.get("routing_gap_total") or 0),
            monitoring_gap_total=(int(monitoring["failing"]) + int(monitoring["never_scanned"])),
        ),
        last_scan_activity_label=(
            f"Last scan activity {_format_datetime(home_data.get('last_scan'))}"
            if home_data.get("last_scan")
            else "No scans yet"
        ),
        next_run_label=next_run.strftime("%Y-%m-%d %H:%M UTC"),
        horizon=_horizon(list(home_data.get("calendar") or []), current),
        error=error,
        warning=warning,
        saved=saved,
    )
