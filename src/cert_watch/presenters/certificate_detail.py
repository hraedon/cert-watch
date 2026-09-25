"""Typed, HTTP-free presentation logic for endpoint detail pages."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from itertools import pairwise
from typing import Any

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

from cert_watch.cert_chain import ACTIONABLE_CHAIN_STATUSES, display_urgency
from cert_watch.certificate_model import Certificate
from cert_watch.chain_guidance import ChainGuidance, describe_chain
from cert_watch.database import LatestScanRecord
from cert_watch.filters import compute_urgency, friendly_issuer, issuer_cn, subject_cn
from cert_watch.posture import GRADE_WORST_ORDER
from cert_watch.scan_error_guidance import ScanErrorGuidance, describe_scan_error
from cert_watch.scan_freshness import ScanEvidence
from cert_watch.services.certificate_detail import (
    CertificateDetailData,
    PendingHostDetailData,
)
from cert_watch.tags import parse_tags


@dataclass(frozen=True)
class ChainCertificateView:
    id: str
    subject: str
    issuer: str
    not_after: str
    days_remaining: int
    subject_cn: str
    issuer_org: str
    key_type: str
    self_issued: bool
    urgency: str
    role_label: str


@dataclass(frozen=True)
class CertificateTechnicalView:
    key_type: str
    sig_alg: str
    serial: str
    fingerprint: str
    chain: tuple[ChainCertificateView, ...]
    urgency: str
    days_remaining: int
    subject_cn: str
    issuer_org: str
    issuer_cn: str
    chain_issue: str | None

    def template_context(self) -> dict[str, Any]:
        """Backward-compatible context for focused presenter callers."""
        return {
            "key_type": self.key_type,
            "sig_alg": self.sig_alg,
            "serial": self.serial,
            "fingerprint": self.fingerprint,
            "chain": list(self.chain),
            "urgency": self.urgency,
            "days_remaining": self.days_remaining,
            "subject_cn": self.subject_cn,
            "issuer_org": self.issuer_org,
            "issuer_cn": self.issuer_cn,
            "chain_issue": self.chain_issue,
        }


@dataclass(frozen=True)
class CertificateView:
    issuer: str
    not_before: datetime
    not_after: datetime
    san_dns_names: tuple[str, ...]
    source: str


@dataclass(frozen=True)
class HostInfoView:
    owner_name: str | None
    owner_email: str | None
    owner_slack: str | None
    renewal_method: str
    runbook_url: str | None
    notes: str
    tags: str
    threshold_days: int | None
    scan_interval_hours: int | None
    renewal_status: str
    expected_issuers: str
    settings_writable: bool
    renewal_status_label: str
    scan_cadence_label: str
    threshold_label: str
    runbook_is_link: bool
    legacy_interval: bool


@dataclass(frozen=True)
class PostureFindingView:
    check: str
    status: str
    message: str
    display_message: str


@dataclass(frozen=True)
class PostureView:
    grade: str
    findings: tuple[PostureFindingView, ...]
    protocol_version: str
    scanned_at: str
    chain_incomplete: bool
    chain_status: str


@dataclass(frozen=True)
class DriftEventView:
    field: str
    change: str
    sev: str
    when: str


@dataclass(frozen=True)
class RenewalHistoryView:
    id: str
    fingerprint_short: str
    not_before_date: str
    is_current: bool


@dataclass(frozen=True)
class TagView:
    label: str
    inherited: bool


@dataclass(frozen=True)
class ChainNoteView:
    tone: str
    icon: str
    label: str


@dataclass(frozen=True)
class CertificateAlertView:
    message: str
    status: str
    status_label: str
    status_tone: str


@dataclass(frozen=True)
class CertificateDetailView:
    cert: CertificateView | None
    cert_id: str
    subject_cn: str
    host_id: str
    hostname: str
    port: int
    host_info: HostInfoView | None
    renewal_method_label: str
    renewal_method_indicator: str
    all_tags: tuple[str, ...]
    scan_status: str | None
    scan_error: str | None
    scan_at: str | None
    scan_evidence: ScanEvidence | None
    key_type: str
    sig_alg: str
    serial: str
    fingerprint: str
    chain: tuple[ChainCertificateView, ...]
    urgency: str
    days_remaining: int
    issuer_org: str
    issuer_cn: str
    chain_issue: str | None
    chain_status: str
    chain_guidance: ChainGuidance | None
    chain_note: ChainNoteView | None
    chain_posture_changed: bool
    chain_posture_recorded: bool
    cert_tags: tuple[str, ...]
    effective_tags: tuple[str, ...]
    shown_tags: tuple[TagView, ...]
    renewal_history: tuple[RenewalHistoryView, ...]
    validity_percent: int
    posture: PostureView | None
    drift_events: tuple[DriftEventView, ...]
    certificate_alerts: tuple[CertificateAlertView, ...]
    slack_configured: bool
    source_label: str
    source_icon: str
    source_meta: str
    endpoint_saved: bool
    endpoint_error: str
    # Reached through a link to an earlier certificate for this endpoint.
    superseded: bool = False
    # The latest scan attempt failed; for a stored certificate, what is shown
    # is from the last successful scan (#113).
    scan_failed: bool = False
    scan_at_label: str = ""
    scan_guidance: ScanErrorGuidance | None = None
    scanned: bool = False
    added: bool = False
    status: dict[str, Any] | None = None
    condition: str | None = None
    monitoring: str = "never_scanned"
    renewal: str = "unknown"
    delivery: str = "unrouted"
    overall_label: str = "Unknown"
    overall_tone: str = "t-muted"

    def template_context(self) -> dict[str, Any]:
        """Expose one stable boundary to Jinja or a future JSON serializer."""
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


def _key_type(cert: Certificate) -> str:
    try:
        key = x509.load_der_x509_certificate(cert.raw_der).public_key()
        if isinstance(key, rsa.RSAPublicKey):
            return f"RSA {key.key_size}"
        if isinstance(key, ec.EllipticCurvePublicKey):
            return f"ECDSA {key.curve.name}"
        if isinstance(key, ed25519.Ed25519PublicKey):
            return "Ed25519"
        if isinstance(key, ed448.Ed448PublicKey):
            return "Ed448"
        return type(key).__name__
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return "unknown"


def _days_remaining(cert: Certificate, now: datetime) -> int:
    expires = cert.not_after
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    return (expires - now).days


def present_certificate_technical_details(
    cert: Certificate,
    chain: list[tuple[str, Certificate]] | tuple[tuple[str, Certificate], ...],
    chain_status: str,
    *,
    now: datetime | None = None,
) -> CertificateTechnicalView:
    """Build certificate detail values without HTTP, database, or templates."""
    current = now or datetime.now(UTC)
    try:
        parsed = x509.load_der_x509_certificate(cert.raw_der)
        sig_alg = parsed.signature_algorithm_oid._name
        serial_hex = format(parsed.serial_number, "X")
        serial = ":".join(serial_hex[i : i + 2] for i in range(0, len(serial_hex), 2))
    except (ValueError, TypeError, UnsupportedAlgorithm):
        sig_alg = "unknown"
        serial = "unknown"

    fingerprint = cert.fingerprint_sha256
    if ":" not in fingerprint and len(fingerprint) == 64:
        fingerprint = ":".join(
            fingerprint[i : i + 2] for i in range(0, len(fingerprint), 2)
        ).upper()

    presented_chain = tuple(
        ChainCertificateView(
            id=cert_id,
            subject=item.subject,
            issuer=item.issuer,
            not_after=item.not_after.isoformat(),
            days_remaining=_days_remaining(item, current),
            subject_cn=subject_cn(item.subject),
            issuer_org=friendly_issuer(item.issuer),
            key_type=_key_type(item),
            self_issued=item.subject == item.issuer,
            urgency=compute_urgency(_days_remaining(item, current)),
            role_label=(
                "Root CA (self-issued)" if item.subject == item.issuer else "Intermediate CA"
            ),
        )
        for cert_id, item in chain
    )
    leaf_days = _days_remaining(cert, current)
    worst_days = min((leaf_days, *(item.days_remaining for item in presented_chain)))

    return CertificateTechnicalView(
        key_type=_key_type(cert),
        sig_alg=sig_alg,
        serial=serial,
        fingerprint=fingerprint,
        chain=presented_chain,
        urgency=display_urgency(compute_urgency(worst_days), chain_status),
        days_remaining=leaf_days,
        subject_cn=subject_cn(cert.subject),
        issuer_org=friendly_issuer(cert.issuer),
        issuer_cn=issuer_cn(cert.issuer),
        chain_issue=(chain_status if chain_status in ACTIONABLE_CHAIN_STATUSES else None),
    )


def _renewal_display(method: str) -> tuple[str, str]:
    label = {
        "acme": "ACME",
        "cert-manager": "cert-manager",
        "manual": "Manual",
    }.get(method, method.capitalize() if method else "")
    indicator = (
        "automation configured"
        if method in {"acme", "cert-manager"}
        else ("requires manual action" if method == "manual" else "")
    )
    return label, indicator


def _host_info(host: Any, settings_writable: bool) -> HostInfoView:
    status = host.renewal_status
    interval = host.scan_interval_hours
    return HostInfoView(
        owner_name=host.owner_name or None,
        owner_email=host.owner_email or None,
        owner_slack=host.owner_slack or None,
        renewal_method=host.renewal_method or "",
        runbook_url=host.runbook_url or None,
        notes=host.notes or "",
        tags=host.tags or "",
        threshold_days=host.threshold_days,
        scan_interval_hours=interval,
        renewal_status=status,
        expected_issuers=host.expected_issuers,
        settings_writable=settings_writable,
        renewal_status_label={
            "pending": "No completion reported",
            "in_progress": "In progress — operator reported",
        }.get(status, status),
        scan_cadence_label=(
            f"Every {interval} hours" if interval and interval > 0 else "Daily schedule"
        ),
        threshold_label=(
            f"{host.threshold_days} days"
            if host.threshold_days is not None
            else "Automatic thresholds"
        ),
        runbook_is_link=bool(
            host.runbook_url and host.runbook_url.startswith(("http://", "https://"))
        ),
        legacy_interval=bool(interval is not None and (interval < 1 or interval > 8760)),
    )


def _validity_percent(cert: Certificate, now: datetime) -> int:
    total = (cert.not_after - cert.not_before).days if cert.not_after and cert.not_before else 90
    elapsed = (now - cert.not_before).days if cert.not_before else 0
    return min(int(elapsed / total * 100), 100) if total > 0 else 50


def _drift_events(history: list[dict[str, Any]]) -> tuple[DriftEventView, ...]:
    events: list[DriftEventView] = []
    for current, previous in pairwise(history):
        changes: list[tuple[str, str, str]] = []
        if (
            current.get("issuer")
            and previous.get("issuer")
            and current["issuer"] != previous["issuer"]
        ):
            changes.append(
                (
                    "Issuer changed",
                    f"{issuer_cn(previous['issuer'])} → {issuer_cn(current['issuer'])}",
                    "high",
                )
            )
        if (
            current.get("key_algo")
            and previous.get("key_algo")
            and current["key_algo"] != previous["key_algo"]
        ):
            changes.append(
                (
                    "Key algorithm changed",
                    f"{previous['key_algo']} → {current['key_algo']}",
                    "high",
                )
            )
        if (
            current.get("sig_algo")
            and previous.get("sig_algo")
            and current["sig_algo"] != previous["sig_algo"]
        ):
            downgraded = (
                "sha1" in str(current["sig_algo"]).lower()
                and "sha1" not in str(previous["sig_algo"]).lower()
            )
            changes.append(
                (
                    "Signature algorithm changed",
                    f"{previous['sig_algo']} → {current['sig_algo']}",
                    "high" if downgraded else "info",
                )
            )
        if (
            current.get("posture_grade")
            and previous.get("posture_grade")
            and current["posture_grade"] != previous["posture_grade"]
            and GRADE_WORST_ORDER.get(current["posture_grade"], 0)
            > GRADE_WORST_ORDER.get(previous["posture_grade"], 0)
        ):
            changes.append(
                (
                    "Posture grade dropped",
                    f"{previous['posture_grade']} → {current['posture_grade']}",
                    "high",
                )
            )
        when = str(current.get("scanned_at", ""))[:10]
        events.extend(
            DriftEventView(field, change, severity, when) for field, change, severity in changes
        )
    return tuple(events)


def _posture_view(
    raw: dict[str, Any] | None,
    *,
    chain_changed: bool,
    guidance: ChainGuidance,
) -> PostureView | None:
    if raw is None:
        return None
    chain_incomplete = bool(raw.get("chain_incomplete"))
    findings = tuple(
        PostureFindingView(
            check=str(finding.get("check", "")),
            status=str(finding.get("status", "")),
            message=str(finding.get("message", "")),
            display_message=(
                guidance.title
                if finding.get("check") == "chain_completeness" and not chain_incomplete
                else str(finding.get("message", ""))
            ),
        )
        for finding in raw.get("findings", [])
        if not (chain_changed and finding.get("check") == "chain_completeness")
    )
    return PostureView(
        grade=str(raw.get("grade", "")),
        findings=findings,
        protocol_version=str(raw.get("protocol_version") or ""),
        scanned_at=str(raw.get("scanned_at") or ""),
        chain_incomplete=chain_incomplete,
        chain_status=str(raw.get("chain_status") or ""),
    )


def _chain_note(status: str) -> ChainNoteView:
    tone, icon, label = {
        "public": ("t-muted", "link", "public chain"),
        "private": ("t-accent", "shield", "private root"),
        "incomplete": ("t-warn", "alert", "chain incomplete"),
        "self-signed": ("t-muted", "key", "self-signed"),
        "invalid": ("t-crit", "alert", "chain invalid"),
        "unverified": ("t-warn", "alert", "chain not verified"),
    }.get(status, ("t-muted", "link", "issuer not uploaded"))
    return ChainNoteView(tone, icon, label)


def _scan_time_label(value: str) -> str:
    """``2026-09-24T07:29:36+00:00`` -> ``2026-09-24 07:29 UTC``."""
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")


def _latest_scan_fields(latest: LatestScanRecord | None) -> dict[str, Any]:
    failed = latest is not None and latest.status == "failure"
    return {
        "scan_failed": failed,
        "scan_at_label": _scan_time_label(latest.scanned_at) if latest else "",
        "scan_guidance": describe_scan_error(latest.error_message) if failed and latest else None,
    }


def _axis_display(
    model: dict[str, Any] | None, *, endpoint: bool
) -> tuple[str | None, str, str, str, str, str]:
    model = model or {}
    raw_condition = (model.get("condition") or {}).get("state")
    condition = str(raw_condition) if raw_condition is not None else None
    monitoring = str((model.get("monitoring") or {}).get("state") or "never_scanned")
    renewal = str((model.get("renewal") or {}).get("state") or "unknown")
    delivery = str((model.get("delivery") or {}).get("state") or "unrouted")
    if endpoint and monitoring == "failing":
        label, tone = "Scan failing", "t-crit"
    elif endpoint and monitoring == "never_scanned":
        label, tone = "Never scanned", "t-muted"
    else:
        label, tone = {
            "expired": ("Expired", "t-expired"),
            "le7": ("≤7 days", "t-crit"),
            "8to30": ("8–30 days", "t-warn"),
            "ok": ("OK", "t-ok"),
        }.get(condition or "", ("Unknown", "t-muted"))
    return condition, monitoring, renewal, delivery, label, tone


def present_certificate_detail(
    data: CertificateDetailData,
    *,
    settings_writable: bool,
    slack_configured: bool,
    endpoint_saved: bool = False,
    endpoint_error: str = "",
    superseded: bool = False,
    scanned: bool = False,
    added: bool = False,
    now: datetime | None = None,
) -> CertificateDetailView:
    """Build either stored-certificate or pending-host detail view."""
    current = now or datetime.now(UTC)
    if isinstance(data, PendingHostDetailData):
        host = data.host
        latest = data.latest_scan
        pending_host_info = _host_info(host, settings_writable)
        renewal_label, renewal_indicator = _renewal_display(host.renewal_method or "")
        shown_tags = tuple(TagView(tag, False) for tag in parse_tags(host.tags))
        condition, monitoring, renewal, delivery, overall_label, overall_tone = _axis_display(
            data.status, endpoint=True
        )
        return CertificateDetailView(
            cert=None,
            cert_id=data.cert_id,
            subject_cn=f"{host.hostname}:{host.port}",
            host_id=host.id,
            hostname=host.hostname,
            port=host.port,
            host_info=pending_host_info,
            renewal_method_label=renewal_label,
            renewal_method_indicator=renewal_indicator,
            all_tags=tuple(data.all_tags),
            scan_status=latest.status if latest else None,
            scan_error=latest.error_message if latest else None,
            scan_at=latest.scanned_at if latest else None,
            scan_evidence=data.scan_evidence,
            key_type="",
            sig_alg="",
            serial="",
            fingerprint="",
            chain=(),
            urgency="gray",
            days_remaining=0,
            issuer_org="",
            issuer_cn="",
            chain_issue=None,
            chain_status="",
            chain_guidance=None,
            chain_note=None,
            chain_posture_changed=False,
            chain_posture_recorded=False,
            cert_tags=(),
            effective_tags=tuple(tag.label for tag in shown_tags),
            shown_tags=shown_tags,
            renewal_history=(),
            validity_percent=0,
            posture=None,
            drift_events=(),
            certificate_alerts=(),
            slack_configured=slack_configured,
            source_label="Monitored",
            source_icon="server",
            source_meta=(
                "last scan failed"
                if latest and latest.status == "failure"
                else (
                    f"last scanned {latest.scanned_at[:16].replace('T', ' ')}"
                    if latest
                    else "no scan recorded"
                )
            ),
            endpoint_saved=endpoint_saved,
            endpoint_error=endpoint_error,
            **_latest_scan_fields(latest),
            scanned=scanned,
            added=added,
            status=data.status,
            condition=condition,
            monitoring=monitoring,
            renewal=renewal,
            delivery=delivery,
            overall_label=overall_label,
            overall_tone=overall_tone,
        )

    technical = present_certificate_technical_details(
        data.cert, data.chain, data.chain_status, now=current
    )
    chain_certs = [cert for _, cert in data.chain]
    guidance = describe_chain(data.cert, chain_certs, data.chain_status)
    chain_changed = bool(
        data.posture_is_stored
        and data.posture
        and data.posture.get("chain_status") != data.chain_status
    )
    host_info = _host_info(data.host, settings_writable) if data.host else None
    renewal_label, renewal_indicator = _renewal_display(
        data.host.renewal_method if data.host else ""
    )
    if data.cert.source == "scanned":
        source_label, source_icon = "Scanned", "server"
        source_meta = f"scanned from {data.hostname}:{data.port}" if data.hostname else ""
    elif data.cert.source == "uploaded":
        source_label, source_icon, source_meta = "Uploaded", "file", "uploaded file"
    else:
        source_label, source_icon, source_meta = "Public CT", "globe", ""
    cert_tag_set = set(data.cert_tags)
    condition, monitoring, renewal, delivery, overall_label, overall_tone = _axis_display(
        data.status, endpoint=data.host is not None
    )
    return CertificateDetailView(
        cert=CertificateView(
            issuer=data.cert.issuer,
            not_before=data.cert.not_before,
            not_after=data.cert.not_after,
            san_dns_names=tuple(data.cert.san_dns_names),
            source=data.cert.source,
        ),
        cert_id=data.cert_id,
        subject_cn=technical.subject_cn,
        host_id=data.host.id if data.host else "",
        hostname=data.hostname,
        port=data.port,
        host_info=host_info,
        renewal_method_label=renewal_label,
        renewal_method_indicator=renewal_indicator,
        all_tags=tuple(data.all_tags),
        scan_status=data.latest_scan.status if data.latest_scan else None,
        scan_error=data.latest_scan.error_message if data.latest_scan else None,
        scan_at=data.latest_scan.scanned_at if data.latest_scan else None,
        scan_evidence=data.scan_evidence,
        key_type=technical.key_type,
        sig_alg=technical.sig_alg,
        serial=technical.serial,
        fingerprint=technical.fingerprint,
        chain=technical.chain,
        urgency=technical.urgency,
        days_remaining=technical.days_remaining,
        issuer_org=technical.issuer_org,
        issuer_cn=technical.issuer_cn,
        chain_issue=technical.chain_issue,
        chain_status=data.chain_status,
        chain_guidance=guidance,
        chain_note=_chain_note(data.chain_status),
        chain_posture_changed=chain_changed,
        chain_posture_recorded=bool(data.posture and data.posture.get("chain_status")),
        cert_tags=tuple(data.cert_tags),
        effective_tags=tuple(data.effective_tags),
        shown_tags=tuple(TagView(tag, tag not in cert_tag_set) for tag in data.effective_tags),
        renewal_history=tuple(
            RenewalHistoryView(
                id=str(item["id"]),
                fingerprint_short=(str(item.get("fingerprint_sha256") or "")[:8] or "—"),
                not_before_date=(str(item.get("not_before") or "")[:10] or "—"),
                is_current=bool(item["is_current"]),
            )
            for item in data.renewal_history
        ),
        validity_percent=_validity_percent(data.cert, current),
        posture=_posture_view(
            data.posture,
            chain_changed=chain_changed,
            guidance=guidance,
        ),
        drift_events=_drift_events(data.history_entries),
        certificate_alerts=tuple(
            CertificateAlertView(
                message=alert.message,
                status=alert.status,
                status_label={
                    "sending": "Sending",
                    "sent": "Sent",
                    "failed": "Failed",
                    "cancelled": "Cancelled",
                }.get(alert.status, "Pending"),
                status_tone={
                    "sent": "t-ok",
                    "failed": "t-crit",
                }.get(alert.status, "t-muted"),
            )
            for alert in data.alerts
        ),
        slack_configured=slack_configured,
        source_label=source_label,
        source_icon=source_icon,
        source_meta=source_meta,
        endpoint_saved=endpoint_saved,
        endpoint_error=endpoint_error,
        superseded=superseded,
        **_latest_scan_fields(data.latest_scan),
        scanned=scanned,
        added=added,
        status=data.status,
        condition=condition,
        monitoring=monitoring,
        renewal=renewal,
        delivery=delivery,
        overall_label=overall_label,
        overall_tone=overall_tone,
    )
