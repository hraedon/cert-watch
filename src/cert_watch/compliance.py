"""Compliance report aggregation, signing, and verification (Plan 025).

Reads stored posture + certificate data and produces a point-in-time compliance
report suitable for SOC 2 / ISO 27001 / PCI-DSS auditors.  The report is
tamper-evident: a canonical JSON representation is HMAC-SHA256-signed with the
app signing key, and the CLI ``cert-watch verify-report`` can verify it later.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass
class ComplianceMetric:
    label: str
    passing: int
    total: int
    # False when the underlying signal isn't collected yet (e.g. CAA), so the
    # report shows "Not collected" rather than a misleading 0/0 = N/A. This is
    # presentation-only and is deliberately excluded from the signed canonical
    # form (the signed facts are passing/total).
    collected: bool = True

    @property
    def pct(self) -> float:
        return (self.passing / self.total * 100) if self.total else 0.0

    @property
    def display(self) -> str:
        if not self.collected:
            return "Not collected"
        if self.total == 0:
            return "N/A"
        return f"{self.passing} of {self.total} ({self.pct:.1f}%)"


@dataclass
class RemediationEntry:
    host: str
    port: int
    subject: str
    issuer: str
    not_after: str
    days_remaining: int
    urgency: str
    findings: list[str] = field(default_factory=list)
    owner: str = ""
    tags: str = ""


@dataclass
class RemediationBucket:
    label: str
    entries: list[RemediationEntry] = field(default_factory=list)


@dataclass
class ComplianceReport:
    generated_at: str
    version: str = ""
    commit: str = ""
    scope_tag: str = ""
    scope_description: str = "All monitored certificates"
    total_certs: int = 0
    total_hosts: int = 0
    grade_distribution: dict[str, int] = field(default_factory=dict)
    fleet_grade: str = ""
    compliance_metrics: list[ComplianceMetric] = field(default_factory=list)
    remediation_buckets: list[RemediationBucket] = field(default_factory=list)
    content_sha256: str = ""
    signature: str = ""


_GRADE_ORDER = {"A+": 0, "A": 1, "B": 2, "C": 3, "F": 4}


def _fleet_grade(grades: list[str]) -> str:
    """Fleet grade is the worst grade present (the conservative rollup).

    Uses the full grade ordering so an all-``A`` fleet reports ``A`` — not
    ``A+`` — and any single ``F`` drags the fleet to ``F``.
    """
    present = [g for g in grades if g in _GRADE_ORDER]
    if not present:
        return ""
    return max(present, key=lambda g: _GRADE_ORDER[g])


def _canonical_json(report: ComplianceReport) -> bytes:
    """Canonical JSON for HMAC signing.

    M5: covers the FULL ``report_to_dict()`` output (minus signature fields)
    so an attacker can't alter presentation values (pct, display, count) or
    add arbitrary keys without invalidating the signature.
    """
    d = report_to_dict(report)
    d.pop("content_sha256", None)
    d.pop("signature", None)
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def sign_report(report: ComplianceReport, signing_key: str) -> None:
    canonical = _canonical_json(report)
    report.content_sha256 = hashlib.sha256(canonical).hexdigest()
    derived_key = hmac.new(signing_key.encode(), b"compliance-report", hashlib.sha256).hexdigest()
    report.signature = hmac.new(
        derived_key.encode(), canonical, hashlib.sha256
    ).hexdigest()


def verify_report_signature(
    report_json: dict[str, Any], signing_key: str
) -> tuple[bool, str]:
    content_sha256 = report_json.get("content_sha256", "")
    signature = report_json.get("signature", "")
    if not content_sha256 or not signature:
        return False, "missing content_sha256 or signature"
    rebuilt = ComplianceReport(
        generated_at=report_json.get("generated_at", ""),
        version=report_json.get("version", ""),
        commit=report_json.get("commit", ""),
        scope_tag=report_json.get("scope_tag", ""),
        scope_description=report_json.get("scope_description", ""),
        total_certs=report_json.get("total_certs", 0),
        total_hosts=report_json.get("total_hosts", 0),
        grade_distribution=report_json.get("grade_distribution", {}),
        fleet_grade=report_json.get("fleet_grade", ""),
        compliance_metrics=[
            ComplianceMetric(
                label=m["label"], passing=m["passing"], total=m["total"],
                collected=m.get("collected", True),
            )
            for m in report_json.get("compliance_metrics", [])
        ],
        remediation_buckets=[
            RemediationBucket(
                label=b["label"],
                entries=[
                    RemediationEntry(
                        host=e["host"],
                        port=e["port"],
                        subject=e["subject"],
                        issuer=e["issuer"],
                        not_after=e["not_after"],
                        days_remaining=e["days_remaining"],
                        urgency=e["urgency"],
                        findings=e.get("findings", []),
                        owner=e.get("owner", ""),
                        tags=e.get("tags", ""),
                    )
                    for e in b.get("entries", [])
                ],
            )
            for b in report_json.get("remediation_buckets", [])
        ],
    )
    canonical = _canonical_json(rebuilt)
    expected_hash = hashlib.sha256(canonical).hexdigest()
    derived_key = hmac.new(signing_key.encode(), b"compliance-report", hashlib.sha256).hexdigest()
    expected_sig = hmac.new(
        derived_key.encode(), canonical, hashlib.sha256
    ).hexdigest()
    if expected_hash != content_sha256:
        return False, f"content hash mismatch: expected {expected_hash}, got {content_sha256}"
    if not hmac.compare_digest(expected_sig, signature):
        return False, "signature verification failed"
    return True, "PASS"


def _load_compliance_rows(
    db_path: str | Path,
    *,
    scope_tag: str = "",
) -> list[dict[str, Any]]:
    """Fetch minimal leaf-certificate rows for compliance reporting.

    Replaces ``list_dashboard_rows`` for the compliance path so the report
    builder does not materialise full chain children, anchor rows, and
    dashboard metadata (BC-122).  SQL-level tag filtering keeps the candidate
    set tight when ``scope_tag`` is set.
    """
    from cert_watch.database import init_schema
    from cert_watch.database.connection import _connect, _parse_iso

    init_schema(db_path)
    with _connect(db_path) as conn:
        sql = """
            SELECT
                c.id,
                c.subject,
                c.issuer,
                c.not_before,
                c.not_after,
                c.hostname,
                c.port,
                c.tags,
                c.source,
                COALESCE(h.owner_name, '') AS owner_name
            FROM certificates c
            LEFT JOIN hosts h ON c.hostname = h.hostname AND c.port = h.port
            WHERE c.is_leaf = 1
        """
        params: list[Any] = []
        if scope_tag:
            # Tags are stored as comma-separated strings.  The pattern
            # ,{tag}, inside ,{column}, reliably matches exact tags
            # regardless of position (first, last, middle, or only).
            # Escape LIKE wildcards in the tag value so a user-supplied
            # scope_tag of "%" can't match every row, and use cw_casefold
            # for Unicode case-insensitive matching.
            escaped = scope_tag.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            sql += (
                " AND cw_casefold(',' || c.tags || ',')"
                " LIKE cw_casefold(?) ESCAPE '\\'"
            )
            params.append(f"%,{escaped},%")
        rows = conn.execute(sql, params).fetchall()

    result: list[dict[str, Any]] = []
    now = datetime.now(UTC)
    for r in rows:
        d = dict(r)
        days = (_parse_iso(d["not_after"]) - now).days
        host = f"{d['hostname']}:{d['port']}" if d["hostname"] else f"(uploaded:{d['source']})"
        urgency = (
            "expired"
            if days < 0
            else "critical"
            if days < 7
            else "warning"
            if days < 30
            else "healthy"
        )
        result.append(
            {
                "id": d["id"],
                "host": host,
                "source": d["source"],
                "subject": d["subject"],
                "issuer": d["issuer"],
                "not_before": d["not_before"],
                "not_after": d["not_after"],
                "days_remaining": days,
                "urgency": urgency,
                "owner_name": d["owner_name"],
                "tags": d["tags"],
            }
        )
    return result


def build_compliance_report(
    db_path: str | Path,
    *,
    scope_tag: str = "",
    version: str = "",
    commit: str = "",
    signing_key: str = "",
) -> ComplianceReport:
    from cert_watch.database import (
        get_posture_for_certs,
        get_posture_grades_for_certs,
        init_schema,
    )
    from cert_watch.posture import tls_version_meets_1_2

    init_schema(db_path)
    rows = _load_compliance_rows(db_path, scope_tag=scope_tag)

    total_certs = len(rows)
    host_set: set[str] = set()
    for r in rows:
        h = r.get("host", "")
        if h:
            host_set.add(h)
    total_hosts = len(host_set)

    cert_ids = [r["id"] for r in rows if r.get("id")]
    grade_map = get_posture_grades_for_certs(db_path, cert_ids)

    grade_dist: dict[str, int] = {"A+": 0, "A": 0, "B": 0, "C": 0, "F": 0}
    all_grades: list[str] = []
    for g in grade_map.values():
        g_upper = g.upper()
        if g_upper in grade_dist:
            grade_dist[g_upper] += 1
        else:
            grade_dist["F"] += 1
        all_grades.append(g_upper)

    fleet_grade = _fleet_grade(all_grades) if all_grades else ""

    # One batched query for the full latest posture of every cert, rather than
    # an N+1 over a large fleet (the exact scenario this export targets).
    posture_data = get_posture_for_certs(db_path, cert_ids)

    sha1_ok = 0
    sha1_total = 0
    strong_key_ok = 0
    strong_key_total = 0
    tls_ok = 0
    tls_total = 0
    hsts_ok = 0
    hsts_total = 0
    caa_ok = 0
    caa_total = 0
    revoc_ok = 0
    revoc_total = 0

    for r in rows:
        cid = r.get("id", "")
        if cid not in posture_data:
            continue
        p = posture_data[cid]
        _findings = p.get("findings")
        findings = _findings if _findings is not None else []

        sha1_total += 1
        sha1_pass = not any(
            f.get("check") == "sha1_signature" and f.get("status") == "fail"
            for f in findings
        )
        if sha1_pass:
            sha1_ok += 1

        strong_key_total += 1
        key_pass = not any(
            f.get("check") in ("rsa_key_size", "ecdsa_curve") and f.get("status") == "fail"
            for f in findings
        )
        if key_pass:
            strong_key_ok += 1

        tls_total += 1
        if tls_version_meets_1_2(p.get("protocol_version")):
            tls_ok += 1

        hsts_total += 1
        if p.get("hsts"):
            hsts_ok += 1

        caa_present = p.get("caa_present")
        if caa_present is not None:
            caa_total += 1
            if caa_present:
                caa_ok += 1

        revoc_findings = [
            f for f in findings
            if f.get("check") in ("ocsp_endpoint", "crl_endpoint")
        ]
        if revoc_findings:
            revoc_total += 1
            if any(f.get("status") == "pass" for f in revoc_findings):
                revoc_ok += 1

    metrics = [
        ComplianceMetric("No SHA-1 signature (SHA-256+)", sha1_ok, sha1_total),
        ComplianceMetric("Strong key (RSA >= 2048 or ECDSA)", strong_key_ok, strong_key_total),
        ComplianceMetric("TLS >= 1.2 at last scan", tls_ok, tls_total),
        ComplianceMetric("HSTS present (port 443)", hsts_ok, hsts_total),
        ComplianceMetric(
            "CAA present for domain",
            caa_ok, caa_total,
            collected=caa_total > 0,
        ),
        ComplianceMetric(
            "Revocation endpoint reachable",
            revoc_ok, revoc_total,
            collected=revoc_total > 0,
        ),
    ]

    now = datetime.now(UTC)
    expiring_7: list[RemediationEntry] = []
    expiring_30: list[RemediationEntry] = []
    expiring_90: list[RemediationEntry] = []
    failed: list[RemediationEntry] = []

    for r in rows:
        days = r.get("days_remaining")
        if not isinstance(days, (int, float)):
            continue
        cid = r.get("id", "")
        entry = RemediationEntry(
            host=r.get("host", ""),
            port=r.get("port", 443),
            subject=r.get("subject", ""),
            issuer=r.get("issuer", ""),
            not_after=r.get("not_after", ""),
            days_remaining=int(days),
            urgency=r.get("urgency", ""),
            owner=r.get("owner_name", ""),
            tags=r.get("tags", ""),
        )
        _p = posture_data.get(cid)
        if _p:
            p = _p
            _findings = p.get("findings")
            findings = _findings if _findings is not None else []
            entry.findings = [
                f.get("message", "") for f in findings if f.get("status") == "fail"
            ]
            if entry.findings:
                failed.append(entry)
        if days <= 7:
            expiring_7.append(entry)
        elif days <= 30:
            expiring_30.append(entry)
        elif days <= 90:
            expiring_90.append(entry)

    remediation = [
        RemediationBucket(
            "Expiring within 7 days",
            sorted(expiring_7, key=lambda e: e.days_remaining),
        ),
        RemediationBucket(
            "Expiring within 30 days",
            sorted(expiring_30, key=lambda e: e.days_remaining),
        ),
        RemediationBucket(
            "Expiring within 90 days",
            sorted(expiring_90, key=lambda e: e.days_remaining),
        ),
        RemediationBucket(
            "Failed posture checks", sorted(failed, key=lambda e: e.host)
        ),
    ]

    scope_desc = f"Tag: {scope_tag}" if scope_tag else "All monitored certificates"

    report = ComplianceReport(
        generated_at=now.isoformat(),
        version=version,
        commit=commit,
        scope_tag=scope_tag,
        scope_description=scope_desc,
        total_certs=total_certs,
        total_hosts=total_hosts,
        grade_distribution=grade_dist,
        fleet_grade=fleet_grade,
        compliance_metrics=metrics,
        remediation_buckets=remediation,
    )

    if signing_key:
        sign_report(report, signing_key)

    return report


def report_to_dict(report: ComplianceReport) -> dict[str, Any]:
    d: dict[str, Any] = {
        "generated_at": report.generated_at,
        "version": report.version,
        "commit": report.commit,
        "scope_tag": report.scope_tag,
        "scope_description": report.scope_description,
        "total_certs": report.total_certs,
        "total_hosts": report.total_hosts,
        "grade_distribution": report.grade_distribution,
        "fleet_grade": report.fleet_grade,
        "compliance_metrics": [
            {
                "label": m.label,
                "passing": m.passing,
                "total": m.total,
                "collected": m.collected,
                "pct": round(m.pct, 1),
                "display": m.display,
            }
            for m in report.compliance_metrics
        ],
        "remediation_buckets": [
            {
                "label": b.label,
                "count": len(b.entries),
                "entries": [asdict(e) for e in b.entries],
            }
            for b in report.remediation_buckets
        ],
        "content_sha256": report.content_sha256,
        "signature": report.signature,
    }
    return d


def report_to_csv_rows(report: ComplianceReport) -> list[list[str]]:
    rows: list[list[str]] = []
    rows.append(["cert-watch compliance report"])
    rows.append([])
    rows.append(["Generated", report.generated_at])
    rows.append(["Version", report.version])
    rows.append(["Scope", report.scope_description])
    rows.append(["Total certificates", str(report.total_certs)])
    rows.append(["Total hosts", str(report.total_hosts)])
    rows.append(["Fleet grade", report.fleet_grade])
    rows.append([])

    rows.append(["Posture grade distribution"])
    rows.append(["Grade", "Count"])
    for grade in ("A+", "A", "B", "C", "F"):
        rows.append([grade, str(report.grade_distribution.get(grade, 0))])
    rows.append([])

    rows.append(["Compliance metrics"])
    rows.append(["Metric", "Passing", "Total", "Percentage"])
    for m in report.compliance_metrics:
        if not m.collected:
            rows.append([m.label, "—", "—", "Not collected"])
        else:
            rows.append([m.label, str(m.passing), str(m.total), f"{m.pct:.1f}%"])
    rows.append([])

    for b in report.remediation_buckets:
        rows.append([b.label])
        if b.entries:
            rows.append([
                "Host", "Port", "Subject", "Issuer",
                "Not After", "Days Remaining", "Urgency",
                "Owner", "Tags", "Findings",
            ])
            for e in b.entries:
                rows.append([
                    e.host, str(e.port), e.subject, e.issuer,
                    e.not_after, str(e.days_remaining), e.urgency,
                    e.owner, e.tags, "; ".join(e.findings),
                ])
        else:
            rows.append(["(none)"])
        rows.append([])

    rows.append(["Tamper evidence"])
    rows.append(["Content SHA-256", report.content_sha256])
    rows.append(["HMAC-SHA256 signature", report.signature])
    rows.append(["Generated at", report.generated_at])
    rows.append([])
    # The signature covers the canonical JSON report, not these CSV bytes. The
    # SHA-256/signature above are identical to the JSON export's, so an auditor
    # cross-checks them against the verified JSON. verify-report reads JSON only.
    rows.append([
        "The signature above covers the canonical JSON report. To verify "
        "tamper-evidence, download the matching JSON export and run: "
        "cert-watch verify-report compliance-report.json"
    ])

    return rows
