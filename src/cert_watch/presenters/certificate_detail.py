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
class DetailAxisView:
    label: str
    value: str
    detail: str
    tone: str = "t-muted"


@dataclass(frozen=True)
class DetailActionView:
    title: str
    detail: str
    command: str = ""
    raw_error: str = ""


@dataclass(frozen=True)
class DeliveryRouteView:
    recipient: str
    via: str
    status: str
    detail: str
    tone: str = "t-muted"


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
    axes: tuple[DetailAxisView, ...] = ()
    actions: tuple[DetailActionView, ...] = ()
    delivery_routes: tuple[DeliveryRouteView, ...] = ()
    reveal_delivery_identities: bool = False

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
        "private": ("t-ink", "shield", "private root"),
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
        label, tone = "Scan failing", "t-warn"
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


def _when(value: object) -> str:
    return _scan_time_label(str(value)) if value else "an unknown time"


def _condition_words(days: int, condition: str | None) -> str:
    if condition == "expired" or days < 0:
        amount = abs(days)
        return f"Expired {amount} day{'s' if amount != 1 else ''} ago"
    return f"Expires in {days} day{'s' if days != 1 else ''}"


def _detail_axes(
    *,
    model: dict[str, Any] | None,
    cert: Certificate | None,
    host: Any,
    evidence: ScanEvidence | None,
    days: int,
    now: datetime,
) -> tuple[DetailAxisView, ...]:
    status = model or {}
    condition = str((status.get("condition") or {}).get("state") or "") or None
    monitoring_data = status.get("monitoring") or {}
    monitoring = str(monitoring_data.get("state") or "never_scanned")
    renewal = str((status.get("renewal") or {}).get("state") or "unknown")
    delivery_data = status.get("delivery") or {}
    delivery = str(delivery_data.get("state") or "unrouted")

    if cert is None:
        certificate_axis = DetailAxisView(
            "Certificate",
            "No certificate observed",
            "A successful scan has not stored certificate evidence yet.",
        )
    else:
        words = _condition_words(days, condition)
        tone = {
            "expired": "t-expired",
            "le7": "t-crit",
            "8to30": "t-warn",
            "ok": "t-ok",
        }.get(condition or "", "t-muted")
        detail = f"Issued {cert.not_before:%Y-%m-%d} · expires {cert.not_after:%Y-%m-%d}."
        if monitoring not in {"current", "not_monitored"}:
            words = (
                f"Last seen OK · expires in {days} day{'s' if days != 1 else ''}"
                if condition == "ok"
                else f"Last seen {words.lower()}"
            )
            tone = "t-muted"
            last_seen = evidence.last_success if evidence else None
            detail = (
                "Certificate facts are earlier evidence from the last successful "
                f"scan at {_when(last_seen)}. "
                "cert-watch can't confirm what the server serves now."
            )
        certificate_axis = DetailAxisView("Certificate", words, detail, tone)

    if monitoring == "not_monitored":
        monitoring_axis = DetailAxisView(
            "Monitoring",
            "Not monitored",
            "Uploaded certificate evidence does not have an endpoint or scan cadence.",
        )
    elif monitoring == "current":
        detail = f"Last scanned {_when(evidence.last_success if evidence else None)}"
        if evidence and evidence.due_at:
            detail += f" · next due {_when(evidence.due_at)}"
        monitoring_axis = DetailAxisView("Monitoring", "Current", detail, "t-ok")
    elif monitoring == "failing":
        since = monitoring_data.get("since")
        cause = str(monitoring_data.get("cause") or "No current successful observation.")
        if evidence and evidence.next_attempt_at:
            retry = evidence.next_attempt_at
            if retry.tzinfo is None:
                retry = retry.replace(tzinfo=UTC)
            cause += (
                f" Automatic retry eligible {_when(retry)}."
                if retry > now
                else " Automatic retry is due now."
            )
        value = f"Failing since {_when(since)}"
        if evidence and evidence.state == "overdue" and evidence.attempt_status != "failure":
            value = f"Scan overdue since {_when(evidence.due_at)}"
        monitoring_axis = DetailAxisView("Monitoring", value, cause, "t-warn")
    else:
        monitoring_axis = DetailAxisView(
            "Monitoring",
            "Never scanned",
            "No successful certificate observation is recorded.",
        )

    renewal_value, renewal_tone = {
        "automation_configured": ("Automation configured", "t-ok"),
        "manual": ("Manual", "t-muted"),
        "stalled": ("Stalled", "t-crit"),
        "in_progress": ("In progress", "t-warn"),
        "unknown": ("Unknown", "t-muted"),
    }.get(renewal, (renewal.replace("_", " ").title(), "t-muted"))
    method = getattr(host, "renewal_method", "") if host else ""
    renewal_detail = {
        "stalled": "The renewal window is open and no replacement certificate has appeared.",
        "in_progress": "An operator reported that renewal work is under way.",
        "manual": "This endpoint is recorded as requiring manual renewal.",
        "automation_configured": (
            f"{_renewal_display(method)[0] or 'Automated renewal'} is configured."
        ),
    }.get(renewal, "No renewal method or reliable renewal pattern is recorded.")
    renewal_axis = DetailAxisView("Renewal", renewal_value, renewal_detail, renewal_tone)

    failed_delivery = any(
        isinstance(channel, dict) and channel.get("last_outcome") == "failed"
        for channel in delivery_data.get("channels") or []
    )
    delivery_value, delivery_tone = {
        "ok": ("Delivery ready", "t-ok"),
        "failing": ("Delivery failing", "t-crit" if failed_delivery else "t-warn"),
        "unrouted": ("No specific route", "t-warn"),
    }.get(delivery, (delivery.replace("_", " ").title(), "t-muted"))
    channels = delivery_data.get("channels") or []
    ready = sum(bool(c.get("can_deliver")) for c in channels if isinstance(c, dict))
    delivery_detail = (
        f"{ready} delivery channel{'s' if ready != 1 else ''} ready."
        if delivery == "ok"
        else (
            "The configured route cannot currently deliver an alert."
            if delivery == "failing"
            else "Assign an owner or matching alert group for certificate-specific routing."
        )
    )
    return (
        certificate_axis,
        monitoring_axis,
        renewal_axis,
        DetailAxisView("Alerts", delivery_value, delivery_detail, delivery_tone),
    )


def _detail_actions(
    *,
    view_status: dict[str, Any] | None,
    hostname: str,
    port: int,
    days: int,
    runbook_url: str,
    chain_guidance: ChainGuidance | None,
    may_write: bool,
    has_host: bool,
    uploaded: bool,
) -> tuple[DetailActionView, ...]:
    status = view_status or {}
    monitoring = status.get("monitoring") or {}
    condition = (status.get("condition") or {}).get("state")
    delivery = status.get("delivery") or {}
    actions: list[DetailActionView] = []
    if monitoring.get("state") == "failing" and monitoring.get("raw_error"):
        cause = str(monitoring.get("cause") or "The endpoint has no current observation.")
        actions.append(
            DetailActionView(
                (
                    f"Check the service on {hostname}:{port}."
                    if may_write
                    else (
                        "Ask an administrator or the certificate's owner to check "
                        f"{hostname}:{port}."
                    )
                ),
                cause,
                (
                    f"openssl s_client -connect {hostname}:{port} -servername {hostname}"
                    if may_write
                    else ""
                ),
                str(monitoring.get("raw_error") or ""),
            )
        )
        if may_write:
            actions.append(
                DetailActionView(
                    "Press Scan now once it is fixed.",
                    "A successful scan will replace the stale certificate evidence.",
                )
            )
    elif monitoring.get("state") == "failing":
        actions.append(
            DetailActionView(
                (
                    "Run the overdue scan and check the scheduler."
                    if may_write
                    else (
                        "Ask an administrator or the certificate's owner to check "
                        "the overdue scan."
                    )
                ),
                "The scheduled scan is overdue; no failed connection attempt is recorded.",
            )
        )
    if condition in {"expired", "le7", "8to30"}:
        timing = "now" if condition == "expired" else ("today" if condition == "le7" else "soon")
        detail = _condition_words(days, str(condition)) + "."
        if runbook_url:
            detail += f" Follow the runbook: {runbook_url}"
        actions.append(
            DetailActionView(
                (
                    f"Renew the certificate {timing}."
                    if may_write
                    else f"Ask the certificate's owner to renew it {timing}."
                ),
                detail,
            )
        )
    if bool(status.get("chain_trust_problem")) and chain_guidance:
        actions.append(
            DetailActionView(
                (
                    chain_guidance.title + "."
                    if may_write
                    else "Ask an administrator to review the certificate chain."
                ),
                chain_guidance.remediation,
            )
        )
    if delivery.get("state") == "unrouted":
        actions.append(
            DetailActionView(
                (
                    "Assign an owner or alert group."
                    if has_host and may_write
                    else (
                        "Ask an administrator or the certificate's owner to add an alert route."
                        if has_host
                        else (
                            "Add an alert group for this uploaded certificate."
                            if may_write and uploaded
                            else (
                                "Ask an administrator to add an alert group for this "
                                "uploaded certificate."
                            )
                        )
                    )
                ),
                "No owner, matching alert group, global email recipient, or global "
                "webhook routes alerts.",
            )
        )
    for channel in delivery.get("channels") or []:
        if not isinstance(channel, dict):
            continue
        name = str(channel.get("channel") or "delivery channel")
        if channel.get("recipients") and not channel.get("configured") and name == "smtp":
            actions.append(
                DetailActionView(
                    (
                        "Configure email delivery."
                        if may_write
                        else "Ask an administrator to configure email delivery."
                    ),
                    "Recipients are resolved, but SMTP and the From address are not configured.",
                )
            )
        outcome = channel.get("last_outcome")
        if outcome in {"failed", "partial", "unknown"}:
            display = (
                "Email"
                if name == "smtp"
                else ("Slack webhook" if name == "webhook:slack" else "Webhook")
            )
            outcome_words = {
                "failed": "failed",
                "partial": "was only partially delivered",
                "unknown": "has an unknown outcome",
            }[str(outcome)]
            actions.append(
                DetailActionView(
                    (
                        f"Check {display} delivery."
                        if may_write
                        else f"Ask an administrator to check {display} delivery."
                    ),
                    f"The latest attempt {outcome_words} at "
                    f"{_when(channel.get('last_attempt_at'))}.",
                )
            )
    return tuple(actions)


def _delivery_routes(
    model: dict[str, Any] | None, *, reveal: bool
) -> tuple[DeliveryRouteView, ...]:
    delivery = (model or {}).get("delivery") or {}
    rows: list[DeliveryRouteView] = []
    for channel in delivery.get("channels") or []:
        if not isinstance(channel, dict):
            continue
        raw_channel = str(channel.get("channel") or "")
        via = "Email" if raw_channel == "smtp" else "Webhook"
        recipients = [str(value) for value in channel.get("recipients") or []]
        if reveal and recipients and not raw_channel.startswith("webhook:"):
            labels = recipients
        elif raw_channel == "smtp":
            labels = [f"{len(recipients)} recipient{'s' if len(recipients) != 1 else ''}"]
        elif recipients:
            labels = [f"{len(recipients)} matched alert group{'s' if len(recipients) != 1 else ''}"]
        else:
            labels = ["Global webhook"]
        configured = bool(channel.get("configured"))
        outcome = channel.get("last_outcome")
        if not configured:
            state, tone, detail = "Not configured", "t-warn", f"{via} is not configured."
        elif outcome == "failed":
            state, tone = "Failed", "t-crit"
            detail = f"Latest delivery failed at {_when(channel.get('last_attempt_at'))}."
        elif outcome == "partial":
            state, tone = "Partially delivered", "t-warn"
            detail = f"Latest delivery was partial at {_when(channel.get('last_attempt_at'))}."
        elif outcome == "unknown":
            state, tone = "Outcome unknown", "t-warn"
            detail = (
                f"Latest delivery outcome is unknown at {_when(channel.get('last_attempt_at'))}."
            )
        elif channel.get("can_deliver"):
            state, tone = (
                ("Last delivery worked", "t-ok") if outcome == "accepted" else ("Ready", "t-ok")
            )
            detail = "The channel is configured and has a route."
        else:
            state, tone, detail = "No route", "t-warn", "No recipient route is available."
        rows.extend(DeliveryRouteView(label, via, state, detail, tone) for label in labels)
    groups = [str(value) for value in delivery.get("matching_groups") or []]
    if reveal:
        rows.extend(
            DeliveryRouteView(group, "Alert group", "Matched", "Routes by effective tags.")
            for group in groups
        )
    elif groups:
        rows.append(
            DeliveryRouteView(
                f"{len(groups)} matching group{'s' if len(groups) != 1 else ''}",
                "Alert group",
                "Matched",
                "Group identities are hidden for read-only access.",
            )
        )
    if not groups:
        rows.append(
            DeliveryRouteView(
                "Alert groups matched by tag: none",
                "Alert groups",
                "None",
                "No alert group matches the effective tags.",
            )
        )
    if delivery.get("state") == "unrouted":
        rows.append(
            DeliveryRouteView(
                "No owner, alert group, or global route",
                "Routing",
                "Routing gap",
                "Assign an owner or add a matching or global alert route.",
                "t-warn",
            )
        )
    return tuple(rows)


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
    reveal_delivery_identities: bool = False,
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
        axes = _detail_axes(
            model=data.status,
            cert=None,
            host=host,
            evidence=data.scan_evidence,
            days=0,
            now=current,
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
            axes=axes,
            actions=_detail_actions(
                view_status=data.status,
                hostname=host.hostname,
                port=host.port,
                days=0,
                runbook_url=host.runbook_url or "",
                chain_guidance=None,
                may_write=settings_writable,
                has_host=True,
                uploaded=False,
            ),
            delivery_routes=_delivery_routes(data.status, reveal=reveal_delivery_identities),
            reveal_delivery_identities=reveal_delivery_identities,
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
    axes = _detail_axes(
        model=data.status,
        cert=data.cert,
        host=data.host,
        evidence=data.scan_evidence,
        days=technical.days_remaining,
        now=current,
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
        axes=axes,
        actions=_detail_actions(
            view_status=data.status,
            hostname=data.hostname or technical.subject_cn,
            port=data.port,
            days=technical.days_remaining,
            runbook_url=data.host.runbook_url if data.host else "",
            chain_guidance=guidance,
            may_write=settings_writable,
            has_host=data.host is not None,
            uploaded=data.cert.source == "uploaded",
        ),
        delivery_routes=_delivery_routes(data.status, reveal=reveal_delivery_identities),
        reveal_delivery_identities=reveal_delivery_identities,
    )
