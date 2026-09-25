"""The scan scope guard survives every async handoff to the real store."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from cert_watch.certificate_model import parse_certificate
from cert_watch.config import Settings
from cert_watch.database import SqliteHostRepository, init_schema
from cert_watch.database.connection import _connect
from cert_watch.scan import ScanError, ScannedEntry
from tests._helpers import seed_scanned
from tests.conftest import _make_cert

_MOVE_TO_TEAM_B = r"""
import sys
from cert_watch.auth.rbac import AuthContext
from cert_watch.services.resource_metadata import update_host_tags
update_host_tags(sys.argv[1], sys.argv[2], "team-b", auth=AuthContext.system(),
                 actor="admin", source_ip=None)
"""


@pytest.fixture(autouse=True)
def _no_scheduler(monkeypatch):
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.start", lambda self: None)
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.stop", lambda self: None)


def _client(db: Path, tmp_path: Path):
    from tests.test_tag_scoped_access import _make_scoped_app, _scoped_client

    app, groups = _make_scoped_app(db, tmp_path, scope_tag="team-a")
    return _scoped_client(app, groups)


def _move(db: Path, host_id: str) -> None:
    result = subprocess.run(
        [sys.executable, "-c", _MOVE_TO_TEAM_B, str(db), host_id],
        cwd=Path(__file__).resolve().parent.parent,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr


def _leaf_id(db: Path, hostname: str) -> str | None:
    with _connect(db) as conn:
        row = conn.execute(
            "SELECT id FROM certificates WHERE hostname = ? AND port = 443 AND is_leaf = 1",
            (hostname,),
        ).fetchone()
    return row["id"] if row else None


def _move_during_scan(monkeypatch, db: Path, moved: set[str], *, fail: bool = False) -> None:
    async def scan(hostname: str, port: int, *args, **kwargs):
        if hostname not in moved:
            host = SqliteHostRepository(db).get_by_endpoint(hostname, port)
            assert host is not None
            _move(db, host.id)
            moved.add(hostname)
        if fail:
            return ScanError(hostname=hostname, port=port, error_message="probe failed")
        return ScannedEntry(
            host=hostname,
            port=port,
            leaf=parse_certificate(_make_cert(hostname).der),
            chain=[],
        )

    monkeypatch.setattr("cert_watch.services.host_management.scan_host_async", scan)
    monkeypatch.setattr("cert_watch.routes.hosts.scan_host_async", scan)


@pytest.mark.parametrize(
    ("path_kind", "expected_status"),
    [("html", 303), ("api", 403)],
)
def test_manual_scan_real_store_refuses_a_host_moved_during_network_scan(
    tmp_path, monkeypatch, path_kind, expected_status
):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    hostname = f"manual-{path_kind}.example.test"
    host_id = SqliteHostRepository(db).add(hostname, 443, tags="team-a")
    old_id = seed_scanned(db, hostname, 443, parse_certificate(_make_cert(hostname).der))
    moved: set[str] = set()
    _move_during_scan(monkeypatch, db, moved)

    path = f"/hosts/{host_id}/scan" if path_kind == "html" else f"/api/hosts/{host_id}/scan"
    with _client(db, tmp_path) as client:
        response = client.post(path, follow_redirects=False)

    assert response.status_code == expected_status
    assert moved == {hostname}
    assert _leaf_id(db, hostname) == old_id


@pytest.mark.parametrize("path_kind", ["html", "api"])
def test_scan_failure_bookkeeping_refuses_a_host_moved_during_network_scan(
    tmp_path, monkeypatch, path_kind
):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    hostname = f"failure-{path_kind}.example.test"
    host_id = SqliteHostRepository(db).add(hostname, 443, tags="team-a")
    moved: set[str] = set()
    _move_during_scan(monkeypatch, db, moved, fail=True)

    path = f"/hosts/{host_id}/scan" if path_kind == "html" else f"/api/hosts/{host_id}/scan"
    with _client(db, tmp_path) as client:
        response = client.post(path, follow_redirects=False)

    assert response.status_code == (303 if path_kind == "html" else 403)
    with _connect(db) as conn:
        history = conn.execute(
            "SELECT COUNT(*) FROM scan_history WHERE hostname = ?", (hostname,)
        ).fetchone()[0]
        events = conn.execute(
            "SELECT COUNT(*) FROM event_log WHERE event_type = 'scan_failed'"
        ).fetchone()[0]
    assert (history, events) == (0, 0)


@pytest.mark.parametrize("path_kind", ["html", "api"])
def test_create_reports_a_refused_real_follow_up_scan(
    tmp_path, monkeypatch, path_kind
):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    hostname = f"create-{path_kind}.example.test"
    monkeypatch.setattr(
        "cert_watch.services.host_management.resolve_and_validate_host",
        lambda *args, **kwargs: (None, "192.0.2.1"),
    )
    monkeypatch.setattr(
        "cert_watch.routes.hosts.resolve_and_validate_host",
        lambda *args, **kwargs: (None, "192.0.2.1"),
    )
    moved: set[str] = set()
    _move_during_scan(monkeypatch, db, moved)

    with _client(db, tmp_path) as client:
        response = (
            client.post("/hosts", data={"hostname": hostname}, follow_redirects=False)
            if path_kind == "html"
            else client.post("/api/hosts", json={"hostname": hostname})
        )

    assert response.status_code == (303 if path_kind == "html" else 201)
    assert SqliteHostRepository(db).get_by_endpoint(hostname, 443) is not None
    assert _leaf_id(db, hostname) is None
    if path_kind == "html":
        assert "warning" in parse_qs(urlsplit(response.headers["location"]).query)
    else:
        assert response.json()["refused"] == 1


@pytest.mark.parametrize("path_kind", ["html", "api"])
def test_csv_import_reports_each_refused_real_follow_up_scan(
    tmp_path, monkeypatch, path_kind
):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    hostname = f"import-{path_kind}.example.test"
    monkeypatch.setattr(
        "cert_watch.services.host_management.resolve_and_validate_host",
        lambda *args, **kwargs: (None, "192.0.2.1"),
    )
    monkeypatch.setattr(
        "cert_watch.routes.hosts.resolve_and_validate_host",
        lambda *args, **kwargs: (None, "192.0.2.1"),
    )
    moved: set[str] = set()
    _move_during_scan(monkeypatch, db, moved)
    content = f"hostname,port\n{hostname},443\n"

    with _client(db, tmp_path) as client:
        path = "/hosts/import" if path_kind == "html" else "/api/hosts/import"
        response = client.post(
            path,
            files={"file": ("hosts.csv", content, "text/csv")},
            follow_redirects=False,
        )

    assert response.status_code == (303 if path_kind == "html" else 201)
    assert SqliteHostRepository(db).get_by_endpoint(hostname, 443) is not None
    assert _leaf_id(db, hostname) is None
    if path_kind == "html":
        query = parse_qs(urlsplit(response.headers["location"]).query)
        assert "warning" in query and "follow-up scan refused" in query["warning"][0]
    else:
        assert response.json() == {
            "imported": 1,
            "errors": [
                "row 2: follow-up scan refused: operation not permitted outside your team scope"
            ],
        }


@pytest.mark.parametrize("path_kind", ["html", "api"])
def test_scan_all_counts_a_midflight_refusal_and_completes_other_hosts(
    tmp_path, monkeypatch, path_kind
):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    moved_name = "scan-all-moved.example.test"
    kept_name = "scan-all-kept.example.test"
    repo = SqliteHostRepository(db)
    repo.add(moved_name, 443, tags="team-a")
    repo.add(kept_name, 443, tags="team-a")
    moved: set[str] = set()

    async def scan(hostname: str, port: int, *args, **kwargs):
        if hostname == moved_name and hostname not in moved:
            host = repo.get_by_endpoint(hostname, port)
            assert host is not None
            _move(db, host.id)
            moved.add(hostname)
        return ScannedEntry(
            host=hostname,
            port=port,
            leaf=parse_certificate(_make_cert(hostname).der),
            chain=[],
        )

    monkeypatch.setattr("cert_watch.services.host_management.scan_host_async", scan)
    monkeypatch.setattr("cert_watch.routes.hosts.scan_host_async", scan)
    path = "/hosts/all/scan" if path_kind == "html" else "/api/hosts/scan"
    with _client(db, tmp_path) as client:
        response = client.post(path, follow_redirects=False)

    assert response.status_code == (303 if path_kind == "html" else 200)
    assert _leaf_id(db, moved_name) is None
    assert _leaf_id(db, kept_name) is not None
    if path_kind == "html":
        query = parse_qs(urlsplit(response.headers["location"]).query)
        assert query["refused"] == ["1"]
    else:
        assert response.json() == {"scanned": 1, "failures": 0, "refused": 1}


def test_scan_all_selects_only_tags_the_caller_may_write(tmp_path, monkeypatch):
    from cert_watch.auth.rbac import AuthContext
    from cert_watch.services.host_management import scan_all_hosts

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    repo = SqliteHostRepository(db)
    repo.add("writable.example.test", 443, tags="team-a")
    repo.add("read-only.example.test", 443, tags="team-b")
    scanned: list[str] = []

    async def scan(hostname: str, port: int, *args, **kwargs):
        scanned.append(hostname)
        return ScannedEntry(
            host=hostname,
            port=port,
            leaf=parse_certificate(_make_cert(hostname).der),
            chain=[],
        )

    monkeypatch.setattr("cert_watch.services.host_management.scan_host_async", scan)
    auth = AuthContext(
        username="mixed",
        roles=["viewer"],
        tier="viewer",
        scope_tag="team-a,team-b",
        tag_tiers={"team-a": "operator", "team-b": "viewer"},
    )

    result = __import__("asyncio").run(
        scan_all_hosts(
            db,
            Settings(db_path=db, data_dir=tmp_path),
            auth=auth,
            actor="mixed",
            source_ip=None,
        )
    )

    assert result == (1, 0, 0)
    assert scanned == ["writable.example.test"]
    assert _leaf_id(db, "read-only.example.test") is None
