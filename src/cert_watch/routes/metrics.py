"""Prometheus metrics endpoint."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Request
from fastapi.responses import PlainTextResponse
from prometheus_client import CollectorRegistry, Gauge, generate_latest

from cert_watch.database import get_posture_grades_for_certs
from cert_watch.database.connection import _connect, _parse_iso
from cert_watch.filters import compute_urgency
from cert_watch.middleware import check_metrics_token, rate_limit
from cert_watch.routes._deps import _db_path

logger = logging.getLogger("cert_watch.routes.metrics")

router = APIRouter()


def _scan_error_reason(error_message: str | None) -> str:
    """Map a scan error_message to a canonical counter reason label."""
    if not error_message:
        return "unknown"
    msg = error_message.lower()
    if "refused" in msg:
        return "connection_refused"
    if "timed out" in msg or "timeout" in msg:
        return "timeout"
    if "resolve" in msg or "dns" in msg:
        return "dns_failure"
    if "blocked" in msg:
        return "blocked"
    return "unknown"


@router.get(
    "/metrics",
    response_class=PlainTextResponse,
    dependencies=[Depends(rate_limit("metrics", 120, 60))],
)
def metrics(request: Request) -> PlainTextResponse:
    if not check_metrics_token(request):
        return PlainTextResponse("unauthorized", status_code=401)
    db = _db_path(request)
    registry = CollectorRegistry()

    cert_expiry_gauge = Gauge(
        "cert_watch_cert_expiry_days",
        "Days until certificate expiry",
        ["host", "subject", "fingerprint"],
        registry=registry,
    )
    hosts_gauge = Gauge(
        "cert_watch_hosts_tracked",
        "Number of tracked hosts",
        registry=registry,
    )
    certs_gauge = Gauge(
        "cert_watch_certificates_tracked",
        "Number of leaf certificate groups",
        registry=registry,
    )
    expired_gauge = Gauge(
        "cert_watch_certificates_expired",
        "Number of expired certificates",
        registry=registry,
    )
    urgency_gauge = Gauge(
        "cert_watch_certificates_by_urgency",
        "Leaf certificates grouped by expiry urgency",
        ["urgency"],
        registry=registry,
    )
    posture_gauge = Gauge(
        "cert_watch_certificates_by_posture",
        "Leaf certificates grouped by TLS posture grade",
        ["grade"],
        registry=registry,
    )
    scan_errors_gauge = Gauge(
        "cert_watch_scan_errors",
        "Recorded scan failures by host and reason (gauge, not counter — "
        "old records are purged by retention)",
        ["host", "reason"],
        registry=registry,
    )

    now = datetime.now(UTC)
    with _connect(db) as conn:
        cert_rows = conn.execute(
            "SELECT c.id, c.hostname, c.port, c.subject, c.not_after, "
            "c.fingerprint_sha256 "
            "FROM certificates c WHERE c.is_leaf = 1"
        ).fetchall()

        cert_ids = [r["id"] for r in cert_rows]
        posture_map: dict[str, str] = get_posture_grades_for_certs(db, cert_ids) if cert_ids else {}

        urgency_counts = {"healthy": 0, "warning": 0, "critical": 0, "expired": 0}
        grade_counts: dict[str, int] = {
            "a_plus": 0, "a": 0, "b": 0, "c": 0, "f": 0, "unknown": 0,
        }
        expired = 0
        for r in cert_rows:
            host_label = f'{r["hostname"]}:{r["port"]}' if r["hostname"] else "(uploaded)"
            not_after = _parse_iso(r["not_after"])
            days = (not_after - now).days
            fp_short = (r["fingerprint_sha256"] or "")[:16]
            cert_expiry_gauge.labels(
                host=host_label, subject=r["subject"], fingerprint=fp_short,
            ).set(days)
            urgency_counts[compute_urgency(days)] += 1
            if days < 0:
                expired += 1
            grade = posture_map.get(r["id"], "unknown")
            if grade not in grade_counts:
                grade_counts[grade] = 0
            grade_counts[grade] += 1

        total_certs = len(cert_rows)
        hosts_row = conn.execute("SELECT COUNT(*) FROM hosts").fetchone()
        total_hosts = hosts_row[0] if hosts_row else 0

        error_rows = conn.execute(
            "SELECT hostname, port, error_message, COUNT(*) as cnt "
            "FROM scan_history WHERE status = 'failure' "
            "GROUP BY hostname, port, error_message"
        ).fetchall()
        error_counts: dict[tuple[str, str], int] = {}
        for r in error_rows:
            host_label = f'{r["hostname"]}:{r["port"]}'
            reason = _scan_error_reason(r["error_message"])
            error_counts[(host_label, reason)] = (
                error_counts.get((host_label, reason), 0) + r["cnt"]
            )

        last_scan_row = conn.execute(
            "SELECT MAX(scanned_at) FROM scan_history"
        ).fetchone()
        last_scan_ts: float = 0.0
        if last_scan_row and last_scan_row[0]:
            try:
                last_scan_ts = _parse_iso(last_scan_row[0]).timestamp()
            except (ValueError, TypeError):
                last_scan_ts = 0.0

    for urgency, count in urgency_counts.items():
        urgency_gauge.labels(urgency=urgency).set(count)
    for grade, count in grade_counts.items():
        posture_gauge.labels(grade=grade).set(count)
    for (host_label, reason), count in error_counts.items():
        scan_errors_gauge.labels(host=host_label, reason=reason).set(count)

    hosts_gauge.set(total_hosts)
    certs_gauge.set(total_certs)
    expired_gauge.set(expired)
    if last_scan_ts > 0:
        # Registered only when a scan exists so the series is genuinely
        # ABSENT on never-scanned installs — prometheus_client would
        # otherwise emit 0.0, which reads as "stalled since 1970" to a
        # time()-based staleness rule and pages on every fresh deploy.
        Gauge(
            "cert_watch_last_scan_timestamp_seconds",
            "Unix timestamp of the most recent recorded scan. Alert on "
            "staleness (e.g. time() - metric > 1.5x scan interval) to catch a "
            "silently stalled scheduler — the failure mode where the process "
            "is alive but scans have stopped (or, with external scraping, "
            "where the whole app was down and Prometheus shows the series "
            "going stale on resume).",
            registry=registry,
        ).set(last_scan_ts)

    return PlainTextResponse(
        generate_latest(registry).decode("utf-8"),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )
