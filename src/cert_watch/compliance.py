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
import logging
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cert_watch.status_rule import CRITICAL_DAYS, WARNING_DAYS

logger = logging.getLogger("cert_watch.compliance")


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
    if not isinstance(report_json, dict):
        return False, "malformed report"
    content_sha256 = report_json.get("content_sha256", "")
    signature = report_json.get("signature", "")
    if not content_sha256 or not signature:
        return False, "missing content_sha256 or signature"
    try:
        supplied_metrics = report_json.get("compliance_metrics", [])
        supplied_buckets = report_json.get("remediation_buckets", [])
        if not isinstance(supplied_metrics, list) or not isinstance(supplied_buckets, list):
            raise TypeError
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
                for m in supplied_metrics
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
                for b in supplied_buckets
            ],
        )
        for supplied, metric in zip(
            supplied_metrics, rebuilt.compliance_metrics, strict=True
        ):
            if (
                supplied["pct"] != round(metric.pct, 1)
                or supplied["display"] != metric.display
            ):
                return False, "presentation value mismatch"
        for supplied, bucket in zip(
            supplied_buckets, rebuilt.remediation_buckets, strict=True
        ):
            if supplied["count"] != len(bucket.entries):
                return False, "presentation value mismatch"
        # The signed digest covers the primitives the report is rebuilt from;
        # everything else in the file is derived. Require the supplied document
        # to be exactly what those primitives render to, so no derived value
        # can be altered and no unsigned key can be added.
        def _unsigned(d: dict[str, Any]) -> str:
            rest = {k: v for k, v in d.items() if k not in ("content_sha256", "signature")}
            return json.dumps(rest, sort_keys=True, default=str)

        if _unsigned(json.loads(json.dumps(report_to_dict(rebuilt), default=str))) != _unsigned(
            report_json
        ):
            return False, "report content does not match its signed values"
        canonical = _canonical_json(rebuilt)
        expected_hash = hashlib.sha256(canonical).hexdigest()
        derived_key = hmac.new(
            signing_key.encode(), b"compliance-report", hashlib.sha256
        ).hexdigest()
        expected_sig = hmac.new(
            derived_key.encode(), canonical, hashlib.sha256
        ).hexdigest()
    except (AttributeError, KeyError, TypeError, ValueError):
        return False, "malformed report"
    if expected_hash != content_sha256:
        return False, f"content hash mismatch: expected {expected_hash}, got {content_sha256}"
    try:
        signature_matches = hmac.compare_digest(expected_sig, signature)
    except TypeError:
        return False, "malformed report"
    if not signature_matches:
        return False, "signature verification failed"
    return True, "PASS"


def _load_compliance_rows(
    db_path: str | Path,
    *,
    scope_tag: str = "",
    scope_tags: tuple[str, ...] | list[str] = (),
) -> list[dict[str, Any]]:
    """Fetch minimal leaf-certificate rows for compliance reporting.

    Replaces ``list_dashboard_rows`` for the compliance path so the report
    builder does not materialise host, scan and dashboard metadata (BC-122).
    Status comes from the SQL form of the one status rule
    (:mod:`cert_watch.status_rule`), the rule Browse and Home use: each row's
    ``days_remaining`` is its *effective* days (the soonest expiry among the
    leaf and its stored chain) and ``not_after`` the matching date, so a row's
    remediation bucket, its days and its urgency always agree (#113 review:
    an expired intermediate on a 99-day leaf was labelled Expired but listed
    in no bucket). SQL-level tag filtering keeps the candidate set tight when
    ``scope_tag`` is set.

    ``scope_tags`` is the acting user's visibility scope (#112): rows must
    also match one of those tags. ``scope_tag`` narrows the report; it never
    widens what a scoped user can see.
    """
    from cert_watch.database import init_schema
    from cert_watch.database.chain_status_cache import prepare_status, verified_chain_status_sql
    from cert_watch.database.connection import _connect, _parse_iso
    from cert_watch.status_rule import effective_days_sql, effective_urgency

    init_schema(db_path)
    status = prepare_status(db_path)
    with _connect(db_path) as conn:
        sql = f"""
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
                {verified_chain_status_sql("c")} AS chain_status,
                {effective_days_sql("c")} AS eff_days,
                (SELECT ch.not_after FROM certificates ch
                 WHERE ch.parent_cert_id = c.id
                 ORDER BY julianday(ch.not_after) LIMIT 1) AS chain_not_after,
                COALESCE(h.owner_name, '') AS owner_name
            FROM certificates c
            LEFT JOIN hosts h ON c.hostname = h.hostname AND c.port = h.port
            WHERE c.is_leaf = 1
        """
        params: list[Any] = [status.trust, status.sql_now]
        # Match EFFECTIVE tags (cert ∪ host) like every other scope path
        # — filtering c.tags alone silently omitted certificates that
        # inherit the tag from their host (plan 055 finding C9).
        from cert_watch.database.dashboard_helpers import (
            _add_effective_tag_filter,
        )

        if scope_tag:
            sql, params = _add_effective_tag_filter(
                sql, params, [scope_tag], col_cert="c.tags", col_host="h.tags"
            )
        if scope_tags:
            sql, params = _add_effective_tag_filter(
                sql, params, scope_tags, col_cert="c.tags", col_host="h.tags"
            )
        rows = conn.execute(sql, params).fetchall()

    result: list[dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        days = int(d["eff_days"])
        not_after = d["not_after"]
        chain_not_after = d["chain_not_after"]
        if chain_not_after and _parse_iso(chain_not_after) < _parse_iso(not_after):
            # A chain certificate expires first; that is the date that needs
            # acting on, and the one the days count.
            not_after = chain_not_after
        # ``host`` is the endpoint (``name:port``); the port is carried
        # separately for the CSV. Uploaded files have no endpoint.
        host = f"{d['hostname']}:{d['port']}" if d["hostname"] else "(uploaded)"
        result.append(
            {
                "id": d["id"],
                "host": host,
                "port": d["port"],
                "source": d["source"],
                "subject": d["subject"],
                "issuer": d["issuer"],
                "not_before": d["not_before"],
                "not_after": not_after,
                "days_remaining": days,
                "urgency": effective_urgency(days, d["chain_status"]),
                "owner_name": d["owner_name"],
                "tags": d["tags"],
            }
        )
    return result


def _describe_scope(
    scope_tag: str, scope_tags: tuple[str, ...] | list[str]
) -> tuple[str, str]:
    """Return ``(team_scope, description)`` for the report header."""
    from cert_watch.tags import format_tags

    team_scope = format_tags(list(scope_tags))
    if scope_tag:
        return team_scope, f"Tag: {scope_tag}"
    if team_scope:
        return team_scope, f"Your team scope: {team_scope}"
    return team_scope, "All monitored certificates"


def _grade_map(db_path: str | Path, cert_ids: list[str]) -> dict[str, str]:
    """Latest posture grade per certificate, one entry per certificate.

    Certificates without a stored scan posture (typically uploaded files that
    were never scanned) are evaluated from their DER, which is what the
    certificate detail page shows for them (Issue 10).
    """
    from cert_watch.certificate_model import Certificate as _Cert
    from cert_watch.certificate_model import parse_certificate
    from cert_watch.database import get_posture_grades_for_certs
    from cert_watch.database.connection import _connect
    from cert_watch.posture import evaluate_posture

    grade_map = get_posture_grades_for_certs(db_path, cert_ids) if cert_ids else {}
    missing_ids = [cid for cid in cert_ids if cid not in grade_map]
    if missing_ids:
        placeholders = ",".join("?" * len(missing_ids))
        with _connect(db_path) as conn:
            cert_rows = conn.execute(
                f"SELECT id, raw_der FROM certificates WHERE id IN ({placeholders})",
                missing_ids,
            ).fetchall()
        for cr in cert_rows:
            cid = cr["id"]
            try:
                if cr["raw_der"]:
                    parsed = parse_certificate(bytes(cr["raw_der"]))
                    if isinstance(parsed, _Cert):
                        grade_map[cid] = evaluate_posture(cert=parsed, chain_status=None).grade
            except Exception:
                logger.debug("posture evaluation failed for cert %s", cid, exc_info=True)
    return grade_map


def _grade_distribution(grade_map: dict[str, str]) -> tuple[dict[str, int], list[str]]:
    grade_dist: dict[str, int] = {"A+": 0, "A": 0, "B": 0, "C": 0, "F": 0}
    all_grades: list[str] = []
    for g in grade_map.values():
        g_upper = g.upper()
        if g_upper in grade_dist:
            grade_dist[g_upper] += 1
        else:
            grade_dist["F"] += 1
        all_grades.append(g_upper)
    return grade_dist, all_grades


def fleet_grade_summary(
    db_path: str | Path, *, scope_tags: list[str] | tuple[str, ...] = (),
) -> dict[str, Any] | None:
    """The Posture page's fleet grade, over the compliance report's population.

    One grade per current leaf certificate -- the latest stored posture, or a
    live evaluation for an uploaded file -- so the Posture card and the
    compliance report grade the same certificates. The page used to count
    every ``scan_posture`` row ever written, so each rescan inflated the total
    (#113). Returns ``None`` when nothing is graded.
    """
    from cert_watch.database import init_schema
    from cert_watch.database.connection import _connect

    init_schema(db_path)
    sql = "SELECT c.id FROM certificates c LEFT JOIN hosts h ON c.hostname = h.hostname " \
          "AND c.port = h.port WHERE c.is_leaf = 1"
    params: list[Any] = []
    if scope_tags:
        from cert_watch.database.dashboard_helpers import _add_effective_tag_filter

        sql, params = _add_effective_tag_filter(
            sql, params, scope_tags, col_cert="c.tags", col_host="h.tags"
        )
    with _connect(db_path) as conn:
        cert_ids = [r["id"] for r in conn.execute(sql, params).fetchall()]
    grade_dist, all_grades = _grade_distribution(_grade_map(db_path, cert_ids))
    if not all_grades:
        return None
    return {
        "grade": _fleet_grade(all_grades),
        "counts": {g: n for g, n in grade_dist.items() if n},
        "total": len(all_grades),
    }


def build_compliance_report(
    db_path: str | Path,
    *,
    scope_tag: str = "",
    scope_tags: tuple[str, ...] | list[str] = (),
    version: str = "",
    commit: str = "",
    signing_key: str = "",
) -> ComplianceReport:
    """Build the compliance report over leaf certificates.

    ``scope_tag`` is the report's requested tag filter. ``scope_tags`` is the
    acting user's visibility scope (``scope_tags_from_auth``): a scoped user's
    report only ever covers certificates they can see, with or without a
    requested tag (#112). Empty means the whole estate.
    """
    from cert_watch.database import get_posture_for_certs, init_schema
    from cert_watch.posture import tls_version_meets_1_2

    init_schema(db_path)
    rows = _load_compliance_rows(db_path, scope_tag=scope_tag, scope_tags=scope_tags)

    total_certs = len(rows)
    host_set: set[str] = set()
    for r in rows:
        h = r.get("host", "")
        if h and not h.startswith("(uploaded"):
            host_set.add(h)
    total_hosts = len(host_set)

    cert_ids = [r["id"] for r in rows if r.get("id")]
    grade_dist, all_grades = _grade_distribution(_grade_map(db_path, cert_ids))

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
    expired: list[RemediationEntry] = []
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
        # ``days`` is the row's effective days, the value its urgency was
        # computed from, and the bucket edges are the status rule's
        # thresholds: a certificate never sits in a bucket its own status
        # contradicts on expiry grounds.
        if days < 0:
            expired.append(entry)
        elif days < CRITICAL_DAYS:
            expiring_7.append(entry)
        elif days < WARNING_DAYS:
            expiring_30.append(entry)
        elif days < 90:
            expiring_90.append(entry)

    remediation = [
        RemediationBucket(
            "Expired",
            sorted(expired, key=lambda e: e.days_remaining),
        ),
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

    team_scope, scope_desc = _describe_scope(scope_tag, scope_tags)

    report = ComplianceReport(
        generated_at=now.isoformat(),
        version=version,
        commit=commit,
        # A scoped user's untagged report is scoped to their team; say so in
        # the signed field too, not just the description.
        scope_tag=scope_tag or team_scope,
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
