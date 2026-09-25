"""One estate, one set of numbers (#113 item 6).

Every surface that counts the estate must count it the same way. The
definitions (docs/operations.md, "What the numbers mean"):

- **endpoint**: a registered ``host:port``. *Scanned* when it has a stored
  certificate, *pending* when it has none yet.
- **certificate**: a stored leaf certificate — the current one for each scanned
  endpoint, plus every uploaded file. Chain certificates are not counted.
- **tracked**: one inventory row per endpoint (scanned or pending) plus one per
  uploaded certificate.
- **status** (expired / critical / warning / healthy): the one rule in
  ``cert_watch.status_rule`` — expiry buckets on the most urgent stored cert,
  with an untrusted-chain floor that lifts "healthy" to "warning". Pending
  endpoints have no status. tests/test_status_rule_everywhere.py checks it per
  certificate against real chains.

This test seeds a single estate and asserts the same counts on Home, every
Browse view, the compliance report, Posture, Scan history and /api/health.
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from cert_watch.certificate_model import parse_certificate

NOW = dt.datetime.now(dt.UTC)

# hostname, port, owner, days to expiry (None = pending), chain status
ENDPOINTS: list[tuple[str, int, str, int | None, str]] = [
    ("a.example.test", 443, "Team A", 90, "public"),      # healthy
    ("b.example.test", 636, "Team A", 3, "public"),       # critical
    ("c.example.test", 8443, "Team B", -4, "public"),     # expired 4 days ago
    ("d.example.test", 443, "", -41, "public"),           # expired 41 days ago
    ("e.example.test", 443, "", -401, "public"),          # expired 401 days ago
    ("f.example.test", 443, "Team B", 30, "unknown"),     # warning (chain floor)
    ("g.example.test", 443, "Team B", 20, "public"),      # warning (expiry)
    ("pending.example.test", 443, "Team A", None, ""),    # pending
]
# common name, days to expiry, chain status
UPLOADS: list[tuple[str, int, str]] = [
    ("hsm.example.test", 30, "unknown"),                  # warning (chain floor)
    ("vault.example.test", 200, "public"),                # healthy
]

EXPECTED_STATS = {"expired": 3, "critical": 1, "warning": 3, "healthy": 2}
EXPECTED_TRACKED = len(ENDPOINTS) + len(UPLOADS)          # 10
EXPECTED_SCANNED_ENDPOINTS = 7
EXPECTED_CERTIFICATES = EXPECTED_SCANNED_ENDPOINTS + len(UPLOADS)  # 9

_CHAIN_BY_CN = {host: chain for host, _, _, _, chain in ENDPOINTS}
_CHAIN_BY_CN.update({cn: chain for cn, _, chain in UPLOADS})


def _der(cn: str, days: int) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Example CA")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - dt.timedelta(days=400 - min(days, 0)))
        # Half a day of slack keeps the integer day count stable during the run.
        .not_valid_after(NOW + dt.timedelta(days=days, hours=12))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _fake_chain_status(leaf, chain, anchors):
    cn = leaf.subject.split("CN=", 1)[-1].split(",", 1)[0]
    return _CHAIN_BY_CN.get(cn, "public")


def _seed_estate(db: Path) -> None:
    from cert_watch.database import (
        SqliteHostRepository,
        init_schema,
        record_cert_history,
        replace_scanned,
        store_scan_posture,
    )
    from cert_watch.database.connection import _connect
    from cert_watch.scheduler import ScanHistory, record_scan_history
    from cert_watch.upload import UploadedEntry, store_uploaded

    init_schema(db)
    hosts = SqliteHostRepository(db)
    for host, port, owner, days, _chain in ENDPOINTS:
        hosts.add(host, port)
        if owner:
            with _connect(db) as conn:
                conn.execute(
                    "UPDATE hosts SET owner_name = ? WHERE hostname = ? AND port = ?",
                    (owner, host, port),
                )
                conn.commit()
        # Two scan runs, ten minutes apart, each touching every endpoint. The
        # pending endpoint is attempted three times and never succeeds.
        for run, offset in enumerate((20, 10)):
            at = NOW - dt.timedelta(minutes=offset)
            if days is None:
                for retry in range(2 if run == 0 else 1):
                    record_scan_history(db, ScanHistory(
                        host, port, "failure", error_message="Connection refused",
                        scanned_at=at + dt.timedelta(seconds=retry),
                    ))
                continue
            parsed = parse_certificate(_der(host, days))
            leaf_id, _, _ = replace_scanned(db, host, port, parsed, [], True)
            store_scan_posture(
                db, leaf_id, host, port, "A", [], protocol_version="TLSv1.3", hsts=True,
            )
            record_cert_history(
                db, host, port, parsed, posture_grade="A",
                protocol_version="TLSv1.3", scanned_at=at.isoformat(),
            )
            record_scan_history(db, ScanHistory(host, port, "success", scanned_at=at))
    for cn, days, _chain in UPLOADS:
        store_uploaded(UploadedEntry(f"{cn}.pem", parse_certificate(_der(cn, days))), db)


@pytest.fixture
def estate(tmp_path, monkeypatch):
    monkeypatch.setattr("cert_watch.cert_chain.chain_status", _fake_chain_status)
    db = tmp_path / "cert-watch.sqlite3"
    _seed_estate(db)
    return db


def _browse(db: Path, view: str = ""):
    from cert_watch.services.browse_page import load_browse_page

    return load_browse_page(
        db, q=None, urgency=None, source=None, sort_by="days", sort_order="asc",
        page=1, grouped=0, view=view, scope_tags=(), sched_hour=6, sched_min=0,
    )


def _status_by_cert_id(db: Path) -> dict[str, str]:
    from cert_watch.database import list_dashboard_page

    rows, _ = list_dashboard_page(db, per_page=0)
    return {r["id"]: r["urgency"] for r in rows if r["kind"] != "pending"}


def test_home_and_every_browse_view_agree(estate):
    from cert_watch.database import dashboard_urgency_stats, list_dashboard_page

    # Home computes its cards exactly this way (routes/dashboard.py).
    home_stats = dashboard_urgency_stats(estate, scope_tags=())
    _, home_tracked = list_dashboard_page(estate, per_page=1, scope_tags=())
    assert home_stats == EXPECTED_STATS
    assert home_tracked == EXPECTED_TRACKED

    for view in ("", "owner", "issuer", "renewal_method", "calendar"):
        data = _browse(estate, view)
        assert data.pivot_stats == {**EXPECTED_STATS, "failing": 0, "gray": 0}, view
        assert data.tracked_total == EXPECTED_TRACKED, view


def test_pivot_groups_partition_the_inventory(estate):
    from cert_watch.database import get_pivot_group_entries

    for view in ("owner", "issuer", "renewal_method"):
        groups = _browse(estate, view).pivot_groups
        assert groups is not None
        assert sum(g["count"] for g in groups) == EXPECTED_TRACKED, view
        for g in groups:
            # Expanding a group lists exactly the rows its count promised.
            assert len(get_pivot_group_entries(estate, view, g["key"])) == g["count"], (
                view, g["key"],
            )


def test_owner_pivot_uses_the_row_status_and_real_expiry(estate):
    groups = {g["key"]: g for g in (_browse(estate, "owner").pivot_groups or [])}
    assert groups["Unassigned"]["count"] == 4  # d, e and both uploads
    assert groups["Unassigned"]["earliest_expiry"] == -401
    assert groups["Unassigned"]["worst_urgency"] == "expired"
    assert groups["Team B"]["earliest_expiry"] == -4
    assert groups["Team A"]["count"] == 3  # a, b and the pending endpoint
    assert groups["Team A"]["worst_urgency"] == "failing"


def test_pivot_expiry_label_is_honest(estate):
    from cert_watch.presenters.browse import present_browse

    data = _browse(estate, "owner")
    view = present_browse(data)
    labels = {g.key: g.earliest_expiry_label for g in (view.pivot_groups or ())}
    assert labels["Unassigned"] == "expired 401 days ago"
    assert labels["Team B"] == "expired 4 days ago"
    assert labels["Team A"] == "3 days"


def test_compliance_report_counts_and_status_match_browse(estate):
    from cert_watch.compliance import build_compliance_report

    report = build_compliance_report(estate, signing_key="k")
    assert report.total_certs == EXPECTED_CERTIFICATES
    assert report.total_hosts == EXPECTED_SCANNED_ENDPOINTS

    status = _status_by_cert_id(estate)
    entries = {
        (e.subject, e.days_remaining): e
        for b in report.remediation_buckets if b.label != "Failed posture checks"
        for e in b.entries
    }
    # hsm (30 days, untrusted chain) is Warning in Browse, so here too.
    hsm = next(e for (subject, _), e in entries.items() if "hsm.example.test" in subject)
    assert hsm.urgency == "warning"
    f_ep = next(e for (subject, _), e in entries.items() if "f.example.test" in subject)
    assert f_ep.urgency == "warning"
    assert sorted(status.values()).count("warning") == EXPECTED_STATS["warning"]


def test_posture_counts_certificates_not_scan_rows(estate):
    from cert_watch.compliance import build_compliance_report, fleet_grade_summary
    from cert_watch.crypto_posture import analyze_fleet_crypto

    # Two scan runs stored two posture rows per endpoint; each certificate
    # still counts once, and the same set the compliance report grades.
    summary = fleet_grade_summary(estate)
    report = build_compliance_report(estate, signing_key="k")
    assert summary["total"] == sum(report.grade_distribution.values())
    assert summary["counts"] == {k: v for k, v in report.grade_distribution.items() if v}
    assert summary["grade"] == report.fleet_grade
    assert analyze_fleet_crypto(estate).total == EXPECTED_CERTIFICATES


def test_posture_trend_counts_each_endpoint_once_per_month(estate):
    from cert_watch.database import list_grade_trends, list_tls_version_trends
    from cert_watch.routes.insights import _pivot_grade_monthly, _pivot_tls_monthly

    grades, _ = _pivot_grade_monthly(list_grade_trends(estate, days=180, bucket="month"))
    tls, _ = _pivot_tls_monthly(list_tls_version_trends(estate, days=180, bucket="month"))
    this_month = NOW.strftime("%Y-%m")
    g = next(m for m in grades if m["month"] == this_month)
    t = next(m for m in tls if m["month"] == this_month)
    assert g["grade_a"] + g["grade_b"] + g["grade_c"] == EXPECTED_SCANNED_ENDPOINTS
    assert t["tls_1_3"] + t["tls_1_2"] + t["tls_1_0"] == EXPECTED_SCANNED_ENDPOINTS


def test_scan_history_counts_endpoints_not_attempts(estate):
    from cert_watch.database import list_scan_batches

    batches, total = list_scan_batches(estate)
    assert total == 2
    for batch in batches:
        # 8 endpoints were attempted in each run; the pending one twice in
        # the first run. That is 8 endpoints, not 9 hosts.
        assert batch["total"] == len(ENDPOINTS)
        assert batch["successes"] == EXPECTED_SCANNED_ENDPOINTS
        assert batch["failures"] == 1
        # No trigger is recorded, so none is claimed.
        assert "trigger" not in batch
    assert batches[1]["attempts"] == len(ENDPOINTS) + 1


def test_api_health_reports_endpoints_without_a_successful_scan(
    tmp_path, reload_app, monkeypatch,
):
    from fastapi.testclient import TestClient

    monkeypatch.setattr("cert_watch.cert_chain.chain_status", _fake_chain_status)
    app_mod = reload_app()
    _seed_estate(tmp_path / "cert-watch.sqlite3")
    with TestClient(app_mod.app) as client:
        data = client.get("/api/health").json()
    assert data["endpoints_without_successful_scan"] == 1
    assert data["overall"] == "warning"


def test_posture_page_grades_each_certificate_once(tmp_path, reload_app, monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setattr("cert_watch.cert_chain.chain_status", _fake_chain_status)
    app_mod = reload_app()
    _seed_estate(tmp_path / "cert-watch.sqlite3")
    with TestClient(app_mod.app) as client:
        html = client.get("/posture").text
    # 7 scanned certificates (two posture rows each) + 2 uploads graded live.
    assert f"worst-weighted across {EXPECTED_CERTIFICATES} graded certificates" in html


def test_metrics_urgency_counts_match_the_dashboard(tmp_path, reload_app, monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setattr("cert_watch.cert_chain.chain_status", _fake_chain_status)
    app_mod = reload_app()
    _seed_estate(tmp_path / "cert-watch.sqlite3")
    with TestClient(app_mod.app) as client:
        text = client.get("/metrics").text
    got = {}
    for line in text.splitlines():
        if line.startswith("cert_watch_certificates_by_urgency{"):
            label = line.split('urgency="', 1)[1].split('"', 1)[0]
            got[label] = int(float(line.rsplit(" ", 1)[1]))
    assert got == {**EXPECTED_STATS, "failing": 0, "gray": 0}


def test_partial_scan_is_not_counted_as_a_success(tmp_path):
    """``partial`` is a valid scan status and means the scan did not get
    everything; a batch of one partial endpoint rendered "1/1, success"
    (#113 review). Only a full success is a success."""
    from cert_watch.database import init_schema, list_scan_batches
    from cert_watch.scheduler import ScanHistory, record_scan_history

    db = tmp_path / "partial.sqlite3"
    init_schema(db)
    record_scan_history(db, ScanHistory("p.example.test", 443, "partial", scanned_at=NOW))
    (batch,), _ = list_scan_batches(db)
    assert (batch["successes"], batch["incomplete"], batch["failures"]) == (0, 1, 0)
    assert batch["result"] != "success"

    record_scan_history(db, ScanHistory(
        "ok.example.test", 443, "success", scanned_at=NOW + dt.timedelta(seconds=5),
    ))
    (batch,), _ = list_scan_batches(db)
    assert (batch["total"], batch["successes"], batch["incomplete"]) == (2, 1, 1)
    assert batch["result"] == "partial"
