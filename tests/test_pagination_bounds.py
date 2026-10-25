"""Pagination stays within SQLite's signed-integer binding range."""

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from cert_watch.audit import list_audit, record_audit
from cert_watch.certificate_model import parse_certificate
from cert_watch.database import (
    Alert,
    SqliteAlertRepository,
    SqliteCertificateRepository,
    SqliteHostRepository,
    get_pivot_group_page,
    init_schema,
    list_alerts_with_subject,
    list_dashboard_rows,
    list_scan_history,
)
from cert_watch.database.connection import _connect


def _seed(db, leaves):
    init_schema(db)
    hosts = SqliteHostRepository(db)
    alerts = SqliteAlertRepository(db)
    ids = []
    for index, (tag, leaf) in enumerate(zip(("blue", "red"), leaves, strict=True)):
        hostname = f"{tag}.pagination.example.test"
        cert_id = SqliteCertificateRepository(
            db,
            source="scanned",
            hostname=hostname,
            port=443,
        ).add(parse_certificate(leaf.der))
        ids.append(cert_id)
        host_id = hosts.add(hostname, 443)
        alerts.create(
            Alert(
                cert_id=cert_id,
                alert_type="policy_violation",
                status="pending",
                message="Pagination boundary",
                hostname=hostname,
            )
        )
        record_audit(
            db,
            actor="pagination-test",
            action="test.seed",
            target_type="certificate",
            target_id=cert_id,
        )
        with _connect(db) as conn:
            conn.execute("UPDATE certificates SET tags = ? WHERE id = ?", (tag, cert_id))
            conn.execute("UPDATE hosts SET tags = ? WHERE id = ?", (tag, host_id))
            conn.execute(
                "INSERT INTO scan_history (id,hostname,port,status,scanned_at) "
                "VALUES (?,?,443,'ok',?)",
                (f"pagination-{index}", hostname, datetime.now(UTC).isoformat()),
            )
            conn.commit()
    return ids


@pytest.mark.parametrize(
    "path,extra",
    [
        ("/api/events", {}),
        ("/api/reports/policy-violations", {}),
        ("/api/reports/policy-violations", {"format": "csv"}),
    ],
)
@pytest.mark.parametrize("offset", [-1, 2**63, 10**100])
def test_invalid_explicit_offsets_are_rejected(reload_app, path, extra, offset):
    with TestClient(reload_app().app, raise_server_exceptions=False) as client:
        response = client.get(path, params={**extra, "offset": str(offset)})
    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"] == ["query", "offset"]


@pytest.mark.parametrize("path", ["/api/events", "/api/reports/policy-violations"])
@pytest.mark.parametrize("offset", [0, 2**63 - 1])
def test_valid_explicit_offsets_remain_supported(reload_app, path, offset):
    with TestClient(reload_app().app) as client:
        response = client.get(path, params={"offset": str(offset)})
    assert response.status_code == 200


def _page(kind, db, page, *, scoped=False):
    scope = {"scope_tags": ("blue",)} if scoped else {}
    if kind == "alerts":
        return list_alerts_with_subject(db, page=page, limit=1, **scope)
    if kind == "history":
        return list_scan_history(db, page=page, limit=1, **scope)
    if kind == "audit":
        return list_audit(db, page=page, limit=1)
    if kind == "dashboard":
        return list_dashboard_rows(db, page=page, per_page=1)
    assert kind == "pivot"
    return get_pivot_group_page(db, "owner", "Unassigned", page=page, per_page=1, **scope)[0]


@pytest.mark.parametrize("kind", ["alerts", "history", "audit", "dashboard", "pivot"])
@pytest.mark.parametrize(
    "page,count", [(1, 1), (2, 1), (3, 0), (2**63, 0), (2**63 + 1, 0), (10**100, 0)]
)
def test_populated_queries_keep_page_results_at_integer_boundaries(
    db,
    self_signed_leaf,
    expiring_soon_leaf,
    kind,
    page,
    count,
):
    _seed(db, (self_signed_leaf, expiring_soon_leaf))
    assert len(_page(kind, db, page)) == count
    # A far-out page must not wrap to page one or change the stored rows.
    assert len(_page(kind, db, 1)) == 1


@pytest.mark.parametrize("kind", ["alerts", "history", "pivot"])
def test_large_pages_keep_tag_scope(db, self_signed_leaf, expiring_soon_leaf, kind):
    blue, _red = _seed(db, (self_signed_leaf, expiring_soon_leaf))
    rows = _page(kind, db, 1, scoped=True)
    assert len(rows) == 1
    if kind == "history":
        assert rows[0]["hostname"] == "blue.pagination.example.test"
    elif kind == "alerts":
        assert rows[0]["cert_id"] == blue
    else:
        assert rows[0]["id"] == blue
    assert _page(kind, db, 10**100, scoped=True) == []


@pytest.mark.parametrize(
    "path", ["/api/alerts", "/api/audit", "/alerts", "/api/pivot/owner/Unassigned"]
)
@pytest.mark.parametrize("page", [2**63, 10**100])
def test_populated_routes_return_empty_pages_instead_of_sqlite_overflow(
    tmp_path,
    reload_app,
    self_signed_leaf,
    expiring_soon_leaf,
    path,
    page,
):
    app = reload_app().app
    _seed(tmp_path / "cert-watch.sqlite3", (self_signed_leaf, expiring_soon_leaf))
    with TestClient(app, raise_server_exceptions=False) as client:
        normal = client.get(path)
        assert normal.status_code == 200
        response = client.get(path, params={"page": str(page)})
        assert response.status_code == 200
        if path.startswith("/api/"):
            key = "entries" if "/pivot/" in path else path.rsplit("/", 1)[1]
            assert normal.json()[key]
            assert response.json()[key] == []
