"""Read-side service for certificate and pending-host detail pages."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import UnsupportedAlgorithm

from cert_watch import posture
from cert_watch.cert_chain import chain_status
from cert_watch.certificate_model import Certificate
from cert_watch.database import (
    HostEntry,
    LatestScanRecord,
    SqliteCertificateRepository,
    SqliteTrustAnchorRepository,
    distinct_tags,
    get_pending_host_detail_records,
    get_posture_for_cert,
    get_renewal_history,
    get_stored_certificate_detail_records,
    list_cert_history,
)
from cert_watch.scan_freshness import ScanEvidence, load_scan_evidence
from cert_watch.tags import parse_tags

logger = logging.getLogger("cert_watch.services.certificate_detail")


@dataclass(frozen=True)
class StoredCertificateDetailData:
    cert_id: str
    cert: Certificate
    chain: tuple[tuple[str, Certificate], ...]
    chain_status: str
    hostname: str
    port: int
    host: HostEntry | None
    scan_evidence: ScanEvidence | None
    posture: dict[str, Any] | None
    posture_is_stored: bool
    renewal_history: list[dict[str, Any]]
    history_entries: list[dict[str, Any]]
    cert_tags: list[str]
    effective_tags: list[str]
    all_tags: list[str]


@dataclass(frozen=True)
class PendingHostDetailData:
    cert_id: str
    host: HostEntry
    latest_scan: LatestScanRecord | None
    scan_evidence: ScanEvidence | None
    all_tags: list[str]


CertificateDetailData = StoredCertificateDetailData | PendingHostDetailData


def _fallback_posture(cert: Certificate, status: str) -> dict[str, Any] | None:
    try:
        result = posture.evaluate_posture(
            cert=cert,
            chain_status=status,
            chain_incomplete=False,
        )
    except (ValueError, TypeError, UnsupportedAlgorithm):
        logger.exception("posture evaluation failed for certificate detail")
        return None
    return {
        "grade": result.grade,
        "findings": [
            {"check": finding.check, "status": finding.status, "message": finding.message}
            for finding in result.findings
        ],
        "protocol_version": result.protocol_version,
        "ocsp_stapling": result.ocsp_stapling,
        "hsts": result.hsts,
        "must_staple": result.must_staple,
    }


def load_certificate_detail(
    db_path: str | Path,
    cert_id: str,
    *,
    scope_tags: tuple[str, ...],
    sched_hour: int,
    sched_min: int,
) -> CertificateDetailData | None:
    """Fetch the complete read model for either detail-page render path."""
    all_tags = distinct_tags(db_path, scope_tags=scope_tags)
    stored = get_stored_certificate_detail_records(db_path, cert_id)
    if stored is None:
        pending = get_pending_host_detail_records(db_path, cert_id)
        if pending is None:
            return None
        evidence = load_scan_evidence(
            db_path,
            host_id=pending.host.id,
            hour=sched_hour,
            minute=sched_min,
        ).get(pending.host.id)
        return PendingHostDetailData(
            cert_id=cert_id,
            host=pending.host,
            latest_scan=pending.latest_scan,
            scan_evidence=evidence,
            all_tags=all_tags,
        )

    chain_certs = [cert for _, cert in stored.chain]
    status = chain_status(
        stored.cert,
        chain_certs,
        SqliteTrustAnchorRepository(db_path).list_entries(),
    )
    posture = get_posture_for_cert(db_path, cert_id)
    posture_is_stored = posture is not None
    if posture is None:
        posture = _fallback_posture(stored.cert, status)
    repo = SqliteCertificateRepository(db_path)
    evidence = None
    if stored.cert.source == "scanned" and stored.host is not None:
        evidence = load_scan_evidence(
            db_path,
            host_id=stored.host.id,
            hour=sched_hour,
            minute=sched_min,
        ).get(stored.host.id)
    return StoredCertificateDetailData(
        cert_id=cert_id,
        cert=stored.cert,
        chain=stored.chain,
        chain_status=status,
        hostname=stored.hostname,
        port=stored.port,
        host=stored.host,
        scan_evidence=evidence,
        posture=posture,
        posture_is_stored=posture_is_stored,
        renewal_history=get_renewal_history(db_path, cert_id),
        history_entries=(
            list_cert_history(db_path, stored.hostname, stored.port, limit=50)
            if stored.hostname
            else []
        ),
        cert_tags=parse_tags(repo.get_tags(cert_id)),
        effective_tags=repo.effective_tags(cert_id),
        all_tags=all_tags,
    )
