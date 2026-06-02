"""Tests for the purpose-built dashboard queries (Plan 018 B2 / BC-073).

These cover ``list_dashboard_page``, ``list_dashboard_grouped_page`` and
``get_cert_detail`` — SQL-level filtering, sorting, pagination, grouping
aggregates, empty-DB behaviour, and equivalence with the prior in-Python
materialise-everything path so the dashboard renders identically.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cert_watch.certificate_model import Certificate
from cert_watch.database import (
    SqliteCertificateRepository,
    SqliteHostRepository,
    get_cert_detail,
    group_entries_by_fingerprint,
    init_schema,
    list_dashboard_grouped_page,
    list_dashboard_page,
    list_unified_entries,
    store_scan_posture,
)
from cert_watch.scan import ScannedEntry, store_scanned


def _cert(cn: str, days: int, *, der: bytes, san: list[str] | None = None) -> Certificate:
    now = datetime.now(UTC)
    return Certificate(
        subject=f"CN={cn}",
        issuer="CN=Test Issuer",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=days),
        san_dns_names=san or [cn],
        fingerprint_sha256=f"fp-{cn}-{days}",
        raw_der=der,
        is_leaf=True,
    )


def _seed(db, self_signed_leaf):
    """Seed three scanned hosts with distinct expiries + one uploaded cert."""
    der = self_signed_leaf.der
    init_schema(db)
    host_repo = SqliteHostRepository(db)
    # alpha: healthy (200d), beta: critical (3d), gamma: warning (20d)
    scanned_hosts = [
        ("alpha.example.com", 200),
        ("beta.example.com", 3),
        ("gamma.example.com", 20),
    ]
    for host, days in scanned_hosts:
        host_repo.add(host, 443)
        store_scanned(
            ScannedEntry(host=host, port=443, leaf=_cert(host, days, der=der), chain=[]),
            db,
        )
    # one pending host (no scan)
    host_repo.add("pending.example.com", 8443)
    # one uploaded cert
    SqliteCertificateRepository(db, source="uploaded").add(
        _cert("uploaded.example.com", 100, der=der)
    )


# ---------- empty DB ----------


def test_dashboard_page_empty_db(tmp_path):
    db = tmp_path / "empty.sqlite3"
    rows, total = list_dashboard_page(db)
    assert rows == []
    assert total == 0


def test_grouped_page_empty_db(tmp_path):
    db = tmp_path / "empty2.sqlite3"
    rows, total = list_dashboard_grouped_page(db)
    assert rows == []
    assert total == 0


def test_get_cert_detail_missing(tmp_path):
    db = tmp_path / "empty3.sqlite3"
    init_schema(db)
    assert get_cert_detail(db, "does-not-exist") is None


# ---------- list_dashboard_page ----------


def test_dashboard_page_total_and_kinds(tmp_path, self_signed_leaf):
    db = tmp_path / "page.sqlite3"
    _seed(db, self_signed_leaf)
    rows, total = list_dashboard_page(db, per_page=0)
    # 3 scanned + 1 pending + 1 uploaded
    assert total == 5
    kinds = sorted(r["kind"] for r in rows)
    assert kinds == ["pending", "scanned", "scanned", "scanned", "uploaded"]


def test_dashboard_page_pagination(tmp_path, self_signed_leaf):
    db = tmp_path / "page2.sqlite3"
    _seed(db, self_signed_leaf)
    p1, total = list_dashboard_page(db, page=1, per_page=2)
    p2, _ = list_dashboard_page(db, page=2, per_page=2)
    p3, _ = list_dashboard_page(db, page=3, per_page=2)
    assert total == 5
    assert len(p1) == 2
    assert len(p2) == 2
    assert len(p3) == 1
    ids = [r["id"] for r in (*p1, *p2, *p3)]
    assert len(set(ids)) == 5  # no overlap across pages


def test_dashboard_page_out_of_range_clamps(tmp_path, self_signed_leaf):
    db = tmp_path / "page_clamp.sqlite3"
    _seed(db, self_signed_leaf)
    # Page far beyond the end clamps to the last page (matches prior behaviour).
    rows, total = list_dashboard_page(db, page=99, per_page=2)
    last, _ = list_dashboard_page(db, page=3, per_page=2)
    assert total == 5
    assert [r["id"] for r in rows] == [r["id"] for r in last]


def test_dashboard_page_source_filter(tmp_path, self_signed_leaf):
    db = tmp_path / "src.sqlite3"
    _seed(db, self_signed_leaf)
    scanned, st = list_dashboard_page(db, source="scanned", per_page=0)
    assert st == 4  # 3 scanned + 1 pending
    assert all(r["kind"] in ("scanned", "pending") for r in scanned)
    uploaded, ut = list_dashboard_page(db, source="uploaded", per_page=0)
    assert ut == 1
    assert uploaded[0]["kind"] == "uploaded"


def test_dashboard_page_q_filter(tmp_path, self_signed_leaf):
    db = tmp_path / "q.sqlite3"
    _seed(db, self_signed_leaf)
    rows, total = list_dashboard_page(db, q="beta", per_page=0)
    assert total == 1
    assert rows[0]["host"] == "beta.example.com:443"
    # pending host matches by host text too
    prows, ptotal = list_dashboard_page(db, q="pending", per_page=0)
    assert ptotal == 1
    assert prows[0]["kind"] == "pending"


def test_dashboard_page_urgency_filter(tmp_path, self_signed_leaf):
    db = tmp_path / "urg.sqlite3"
    _seed(db, self_signed_leaf)
    crit, ct = list_dashboard_page(db, urgency="critical", per_page=0)
    assert ct == 1
    assert crit[0]["host"] == "beta.example.com:443"
    gray, gt = list_dashboard_page(db, urgency="gray", per_page=0)
    assert gt == 1
    assert gray[0]["kind"] == "pending"


def test_dashboard_page_sort_by_expiry(tmp_path, self_signed_leaf):
    db = tmp_path / "sort.sqlite3"
    _seed(db, self_signed_leaf)
    asc, _ = list_dashboard_page(
        db, source="scanned", sort_by="expiry", sort_order="asc", per_page=0
    )
    asc_hosts = [r["host"] for r in asc if r["kind"] == "scanned"]
    # earliest expiry first: beta(3) < gamma(20) < alpha(200)
    assert asc_hosts == [
        "beta.example.com:443",
        "gamma.example.com:443",
        "alpha.example.com:443",
    ]
    desc, _ = list_dashboard_page(
        db, source="scanned", sort_by="expiry", sort_order="desc", per_page=0
    )
    desc_hosts = [r["host"] for r in desc if r["kind"] == "scanned"]
    assert desc_hosts == list(reversed(asc_hosts))


def test_dashboard_page_matches_legacy_path(tmp_path, self_signed_leaf):
    """The new SQL path must yield the same entry ids as the old Python path."""
    db = tmp_path / "equiv.sqlite3"
    _seed(db, self_signed_leaf)

    legacy = list_unified_entries(db)
    legacy.sort(key=lambda e: (e.get("not_after") or "9999", e["id"]))
    new_rows, _ = list_dashboard_page(db, sort_by="expiry", per_page=0)
    new_rows_sorted = sorted(new_rows, key=lambda e: (e.get("not_after") or "9999", e["id"]))
    assert [e["id"] for e in new_rows_sorted] == [e["id"] for e in legacy]


# ---------- list_dashboard_grouped_page ----------


def test_grouped_page_collapses_shared_fingerprint(tmp_path, self_signed_leaf):
    """Two hosts sharing a leaf fingerprint collapse into one grouped row."""
    db = tmp_path / "grp.sqlite3"
    init_schema(db)
    der = self_signed_leaf.der
    shared = _cert("shared.example.com", 90, der=der)
    shared.fingerprint_sha256 = "shared-fp"
    host_repo = SqliteHostRepository(db)
    for host in ("h1.example.com", "h2.example.com"):
        host_repo.add(host, 443)
        c = _cert(host, 90, der=der)
        c.fingerprint_sha256 = "shared-fp"
        store_scanned(ScannedEntry(host=host, port=443, leaf=c, chain=[]), db)

    rows, total = list_dashboard_grouped_page(db, per_page=0)
    assert total == 1
    grouped_row = rows[0]
    assert grouped_row["kind"] == "grouped"
    assert grouped_row["host_count"] == 2


def test_grouped_page_worst_urgency(tmp_path, self_signed_leaf):
    """Grouped row urgency is the worst urgency across hosts in the group."""
    db = tmp_path / "grp2.sqlite3"
    init_schema(db)
    der = self_signed_leaf.der
    host_repo = SqliteHostRepository(db)
    # same fingerprint, but one host critical (3d) and one healthy (200d)
    for host, days in [("a.example.com", 3), ("b.example.com", 200)]:
        host_repo.add(host, 443)
        c = _cert(host, days, der=der)
        c.fingerprint_sha256 = "wfp"
        store_scanned(ScannedEntry(host=host, port=443, leaf=c, chain=[]), db)

    rows, total = list_dashboard_grouped_page(db, per_page=0)
    assert total == 1
    assert rows[0]["kind"] == "grouped"
    assert rows[0]["urgency"] == "critical"


def test_grouped_page_pagination_and_filter(tmp_path, self_signed_leaf):
    db = tmp_path / "grp3.sqlite3"
    _seed(db, self_signed_leaf)
    # No shared fingerprints in _seed → grouped count == ungrouped count.
    all_rows, total = list_dashboard_grouped_page(db, per_page=0)
    assert total == 5
    p1, t1 = list_dashboard_grouped_page(db, page=1, per_page=2)
    assert t1 == 5
    assert len(p1) == 2
    # urgency filter on grouped path
    crit, ct = list_dashboard_grouped_page(db, urgency="critical", per_page=0)
    assert ct == 1
    assert crit[0]["host"] == "beta.example.com:443"


def test_grouped_page_matches_legacy_path(tmp_path, self_signed_leaf):
    """Grouped SQL path equals group_entries_by_fingerprint over the raw list."""
    db = tmp_path / "grp_equiv.sqlite3"
    init_schema(db)
    der = self_signed_leaf.der
    host_repo = SqliteHostRepository(db)
    for host in ("g1.example.com", "g2.example.com", "g3.example.com"):
        host_repo.add(host, 443)
        c = _cert(host, 90, der=der)
        c.fingerprint_sha256 = "samefp"
        store_scanned(ScannedEntry(host=host, port=443, leaf=c, chain=[]), db)

    legacy = group_entries_by_fingerprint(list_unified_entries(db))
    new_rows, total = list_dashboard_grouped_page(db, sort_by="expiry", per_page=0)
    assert total == len(legacy)
    legacy_hostcounts = sorted(e.get("host_count", 1) for e in legacy)
    new_hostcounts = sorted(e.get("host_count", 1) for e in new_rows)
    assert legacy_hostcounts == new_hostcounts


# ---------- get_cert_detail ----------


def test_get_cert_detail_scanned(tmp_path, self_signed_leaf):
    db = tmp_path / "detail.sqlite3"
    _seed(db, self_signed_leaf)
    # find the beta cert id via the page query
    rows, _ = list_dashboard_page(db, q="beta", per_page=0)
    cert_id = rows[0]["id"]

    detail = get_cert_detail(db, cert_id)
    assert detail is not None
    assert detail["id"] == cert_id
    assert detail["host"] == "beta.example.com:443"
    assert detail["urgency"] == "critical"
    assert "chain" in detail
    # store_scanned evaluates + stores posture, so the key is present.
    assert "posture" in detail


def test_get_cert_detail_includes_posture(tmp_path, self_signed_leaf):
    db = tmp_path / "detail2.sqlite3"
    _seed(db, self_signed_leaf)
    rows, _ = list_dashboard_page(db, q="alpha", per_page=0)
    cert_id = rows[0]["id"]
    store_scan_posture(
        db, cert_id, "alpha.example.com", 443, "A+", [], protocol_version="TLSv1.3"
    )
    detail = get_cert_detail(db, cert_id)
    assert detail is not None
    assert detail["posture"] is not None
    assert detail["posture"]["grade"] == "A+"


def test_get_cert_detail_uploaded(tmp_path, self_signed_leaf):
    db = tmp_path / "detail3.sqlite3"
    _seed(db, self_signed_leaf)
    rows, _ = list_dashboard_page(db, source="uploaded", per_page=0)
    cert_id = rows[0]["id"]
    detail = get_cert_detail(db, cert_id)
    assert detail is not None
    assert detail["id"] == cert_id
    assert detail["source"] == "uploaded"
