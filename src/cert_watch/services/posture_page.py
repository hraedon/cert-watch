"""Read model for the movable Posture headline."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

from cert_watch.database import get_posture_for_certs, init_schema
from cert_watch.database.connection import _connect
from cert_watch.database.dashboard_helpers import _add_effective_tag_filter
from cert_watch.filters import subject_cn
from cert_watch.posture import grade_contributing_findings

logger = logging.getLogger("cert_watch.services.posture_page")

POSTURE_GRADES = ("A+", "A", "B", "C", "F")
_GRADE_ORDER = {grade: index for index, grade in enumerate(POSTURE_GRADES)}


@dataclass(frozen=True)
class PostureCertificate:
    cert_id: str
    grade: str
    name: str
    subject: str
    reason: str

    @property
    def href(self) -> str:
        return f"/certificates/{quote(self.cert_id, safe='')}"


@dataclass(frozen=True)
class PostureHeadline:
    counts: dict[str, int]
    total: int
    offenders: tuple[PostureCertificate, ...]
    selected_grade: str

    def grade_href(self, grade: str) -> str:
        return f"/posture?grade={quote(grade, safe='')}#certificate-grades"


def _reason(findings: list[Any]) -> str:
    normalized: list[Mapping[str, Any]] = [
        finding for finding in findings if isinstance(finding, dict)
    ]
    normalized = grade_contributing_findings(normalized)
    for status in ("fail", "warn"):
        for finding in normalized:
            if str(finding.get("status") or "").casefold() == status:
                message = str(finding.get("message") or "").strip()
                if message:
                    return message
    return "No failing posture checks recorded."


def _evaluate_missing(row: dict[str, Any]) -> tuple[str, list[dict[str, str]]] | None:
    """Grade an uploaded certificate that has no stored scan posture."""
    raw_der = row.get("raw_der")
    if not raw_der:
        return None
    try:
        from cert_watch.certificate_model import Certificate, parse_certificate
        from cert_watch.posture import evaluate_posture

        cert = parse_certificate(bytes(raw_der))
        if not isinstance(cert, Certificate):
            return None
        result = evaluate_posture(cert=cert, chain_status=None)
        return result.grade, [
            {"status": finding.status, "message": finding.message}
            for finding in result.findings
        ]
    except Exception:
        logger.debug("posture evaluation failed for cert %s", row.get("id"), exc_info=True)
        return None


def load_posture_headline(
    db_path: str | Path,
    *,
    scope_tags: tuple[str, ...] | list[str] = (),
    selected_grade: str = "",
    offender_limit: int = 6,
) -> PostureHeadline:
    """Return one current grade per visible leaf certificate and worst rows.

    A selected grade turns the offender table into the complete matching list;
    the normal headline remains bounded to the worst actionable certificates.
    """
    selected_grade = selected_grade.strip().upper()
    if selected_grade not in POSTURE_GRADES:
        selected_grade = ""

    init_schema(db_path)
    sql = (
        "SELECT c.id, c.subject, c.hostname, c.port, c.raw_der "
        "FROM certificates c LEFT JOIN hosts h "
        "ON h.hostname = c.hostname AND h.port = c.port WHERE c.is_leaf = 1"
    )
    params: list[Any] = []
    sql, params = _add_effective_tag_filter(
        sql, params, scope_tags, col_cert="c.tags", col_host="h.tags"
    )
    sql += " ORDER BY COALESCE(NULLIF(c.hostname, ''), c.subject), c.port, c.id"
    with _connect(db_path) as conn:
        rows = [dict(row) for row in conn.execute(sql, params).fetchall()]

    posture = get_posture_for_certs(db_path, [str(row["id"]) for row in rows])
    counts = {grade: 0 for grade in POSTURE_GRADES}
    certificates: list[PostureCertificate] = []
    for row in rows:
        cert_id = str(row["id"])
        stored = posture.get(cert_id)
        if stored is not None:
            grade = str(stored.get("grade") or "").upper()
            findings = stored.get("findings") or []
        else:
            evaluated = _evaluate_missing(row)
            if evaluated is None:
                continue
            grade, findings = evaluated
            grade = grade.upper()
        if grade not in counts:
            grade = "F"
        counts[grade] += 1
        hostname = str(row.get("hostname") or "").strip()
        port = row.get("port")
        if hostname:
            name = hostname if not port or int(port) == 443 else f"{hostname}:{port}"
        else:
            name = subject_cn(str(row.get("subject") or "")) or "Uploaded certificate"
        certificates.append(
            PostureCertificate(
                cert_id=cert_id,
                grade=grade,
                name=name,
                subject=str(row.get("subject") or "Unknown subject"),
                reason=_reason(findings),
            )
        )

    if selected_grade:
        offenders = [row for row in certificates if row.grade == selected_grade]
    else:
        offenders = [row for row in certificates if _GRADE_ORDER[row.grade] >= _GRADE_ORDER["B"]]
        offenders.sort(key=lambda row: (-_GRADE_ORDER[row.grade], row.name.casefold()))
        offenders = offenders[:offender_limit]
    return PostureHeadline(
        counts=counts,
        total=sum(counts.values()),
        offenders=tuple(offenders),
        selected_grade=selected_grade,
    )
