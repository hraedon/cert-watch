"""The scope check that authorizes a write holds when the write commits
(#115 review round 10).

Sol's probe: a team-a delete passed its scope check, an administrator then
moved the host to team-b through the normal service -- in another process --
and the delete went ahead on what was now team-b's certificate. Every write
this PR made transactional now re-checks the caller's scope on the writing
connection after ``BEGIN IMMEDIATE``, immediately before the write.

Each test pauses the request right after its (advisory) scope check, moves
the host to team-b from a second process, then lets the request continue.
"""

from __future__ import annotations

import importlib
import subprocess
import sys
from pathlib import Path

import pytest

from cert_watch.auth.rbac import AuthContext
from cert_watch.certificate_model import parse_certificate
from cert_watch.database import (
    Alert,
    SqliteAlertRepository,
    SqliteCertificateRepository,
    SqliteHostRepository,
    init_schema,
)
from cert_watch.database.connection import _connect
from tests._helpers import seed_scanned
from tests.conftest import _make_cert

_HOST = "transfer.example.test"

_MOVE_TO_TEAM_B = r"""
import sys
from cert_watch.auth.rbac import AuthContext
from cert_watch.services.resource_metadata import update_host_tags
update_host_tags(sys.argv[1], sys.argv[2], "team-b", auth=AuthContext.system(),
                 actor="admin", source_ip=None)
print("moved")
"""


@pytest.fixture(autouse=True)
def _no_startup_scan(monkeypatch):
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.start", lambda self: None)
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.stop", lambda self: None)


def _estate(tmp_path: Path) -> tuple[Path, str, str]:
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    host_id = SqliteHostRepository(db).add(_HOST, 443, tags="team-a")
    cert_id = seed_scanned(db, _HOST, 443, parse_certificate(_make_cert(_HOST).der))
    return db, host_id, cert_id


def _alert_estate(tmp_path: Path, *, status: str = "pending") -> tuple[Path, str, str]:
    db, host_id, cert_id = _estate(tmp_path)
    alert_id = SqliteAlertRepository(db).create(
        Alert(
            cert_id=cert_id,
            alert_type="expiry_warning",
            status=status,
            message="Synthetic alert for transaction-scope testing.",
        )
    )
    return db, host_id, alert_id


def _move_after_check(monkeypatch, module: str, db: Path, host_id: str, moved: list) -> None:
    """Once *module*'s advisory scope check has passed, an administrator in
    another process moves the host to team-b."""
    target = importlib.import_module(module)
    real = target.ensure_write_scope

    def check_then_move(*args, **kwargs):
        real(*args, **kwargs)
        if not moved:
            done = subprocess.run(
                [sys.executable, "-c", _MOVE_TO_TEAM_B, str(db), host_id],
                cwd=Path(__file__).resolve().parent.parent,
                capture_output=True,
                text=True,
                timeout=60,
            )
            assert done.returncode == 0, done.stderr
            moved.append(done.stdout.strip())

    monkeypatch.setattr(target, "ensure_write_scope", check_then_move)


def _move_host(db: Path, host_id: str) -> str:
    done = subprocess.run(
        [sys.executable, "-c", _MOVE_TO_TEAM_B, str(db), host_id],
        cwd=Path(__file__).resolve().parent.parent,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert done.returncode == 0, done.stderr
    return done.stdout.strip()


def _fake_successful_scan(monkeypatch) -> None:
    from cert_watch.scan import ScannedEntry

    scanned = ScannedEntry(
        host=_HOST,
        port=443,
        leaf=parse_certificate(_make_cert(_HOST).der),
        chain=[],
    )

    async def scan(*args, **kwargs):
        return scanned

    async def store(entry, db_path, *, guard=None, **kwargs):
        conn = _connect(db_path)
        conn.execute("BEGIN IMMEDIATE")
        try:
            if guard is not None:
                guard(conn)
            conn.rollback()
        except Exception:
            conn.rollback()
            raise
        return "stored"

    monkeypatch.setattr("cert_watch.services.host_management.scan_host_async", scan)
    monkeypatch.setattr("cert_watch.services.host_management.store_scanned_async", store)


def _team_a_client(db: Path, tmp_path: Path):
    from tests.test_tag_scoped_access import _make_scoped_app, _scoped_client

    app, groups = _make_scoped_app(db, tmp_path, scope_tag="team-a")
    return _scoped_client(app, groups)


_REFUSED = {"error": "operation not permitted outside your team scope"}


def test_certificate_delete(tmp_path, monkeypatch):
    db, host_id, cert_id = _estate(tmp_path)
    moved: list = []
    _move_after_check(monkeypatch, "cert_watch.services.certificate_management", db, host_id, moved)
    with _team_a_client(db, tmp_path) as client:
        r = client.delete(f"/api/certificates/{cert_id}")
    assert moved == ["moved"]
    assert (r.status_code, r.json()) == (403, _REFUSED)
    assert SqliteCertificateRepository(db).get_by_id(cert_id) is not None


def test_certificate_tags(tmp_path, monkeypatch):
    db, host_id, cert_id = _estate(tmp_path)
    moved: list = []
    _move_after_check(monkeypatch, "cert_watch.services.resource_metadata", db, host_id, moved)
    with _team_a_client(db, tmp_path) as client:
        r = client.put(f"/api/certificates/{cert_id}/tags", json={"tags": "team-a"})
    assert moved == ["moved"]
    assert (r.status_code, r.json()) == (403, _REFUSED)
    assert SqliteCertificateRepository(db).get_tags(cert_id) == ""


@pytest.mark.parametrize("addressed_by", ["certificate", "host"])
def test_ownership(tmp_path, monkeypatch, addressed_by):
    db, host_id, cert_id = _estate(tmp_path)
    moved: list = []
    _move_after_check(monkeypatch, "cert_watch.services.host_ownership", db, host_id, moved)
    route = (
        f"/certificates/{cert_id}/owner"
        if addressed_by == "certificate"
        else f"/hosts/{host_id}/owner"
    )
    with _team_a_client(db, tmp_path) as client:
        r = client.post(route, data={"owner_name": "team-a-took-it"}, follow_redirects=False)
    assert moved == ["moved"]
    assert r.status_code == 303
    assert "outside%20your%20team%20scope" in r.headers["location"]
    [host] = SqliteHostRepository(db).list_all()
    assert host.owner_name == ""


@pytest.mark.parametrize("field", ["notes", "tags"])
def test_host_notes_and_tags(tmp_path, monkeypatch, field):
    db, host_id, _cert_id = _estate(tmp_path)
    moved: list = []
    _move_after_check(monkeypatch, "cert_watch.services.resource_metadata", db, host_id, moved)
    body = {"notes": "team-a was here"} if field == "notes" else {"tags": "team-a"}
    method = "patch" if field == "notes" else "put"
    with _team_a_client(db, tmp_path) as client:
        r = getattr(client, method)(f"/api/hosts/{host_id}/{field}", json=body)
    assert moved == ["moved"]
    assert (r.status_code, r.json()) == (403, _REFUSED)
    [host] = SqliteHostRepository(db).list_all()
    assert (host.tags, host.notes) == ("team-b", "")


def test_host_settings(tmp_path, monkeypatch):
    db, host_id, _cert_id = _estate(tmp_path)
    moved: list = []
    _move_after_check(monkeypatch, "cert_watch.services.host_management", db, host_id, moved)
    with _team_a_client(db, tmp_path) as client:
        r = client.patch(
            f"/api/hosts/{host_id}/settings",
            json={"scan_interval_hours": 12, "threshold_days": 14, "renewal_status": "pending"},
        )
    assert moved == ["moved"]
    assert (r.status_code, r.json()) == (403, _REFUSED)
    host = SqliteHostRepository(db).get(host_id)
    assert host is not None
    assert (host.scan_interval_hours, host.threshold_days) == (None, None)


def test_host_delete(tmp_path, monkeypatch):
    db, host_id, _cert_id = _estate(tmp_path)
    moved: list = []
    _move_after_check(monkeypatch, "cert_watch.services.host_management", db, host_id, moved)
    with _team_a_client(db, tmp_path) as client:
        r = client.delete(f"/api/hosts/{host_id}")
    assert moved == ["moved"]
    assert (r.status_code, r.json()) == (403, _REFUSED)
    assert SqliteHostRepository(db).get(host_id) is not None


def test_alert_mark_read(tmp_path, monkeypatch):
    db, host_id, alert_id = _alert_estate(tmp_path)
    moved: list = []
    _move_after_check(monkeypatch, "cert_watch.services.alert_state", db, host_id, moved)
    with _team_a_client(db, tmp_path) as client:
        r = client.post(f"/api/alerts/{alert_id}/read")
    assert moved == ["moved"]
    assert (r.status_code, r.json()) == (403, {"ok": False, **_REFUSED})
    with _connect(db) as conn:
        assert conn.execute("SELECT read FROM alerts WHERE id = ?", (alert_id,)).fetchone()[0] == 0


def test_alert_retry(tmp_path, monkeypatch):
    db, host_id, alert_id = _alert_estate(tmp_path, status="failed")
    moved: list = []
    _move_after_check(monkeypatch, "cert_watch.auth.scope", db, host_id, moved)
    with _team_a_client(db, tmp_path) as client:
        r = client.post(f"/api/alerts/{alert_id}/retry")
    assert moved == ["moved"]
    # Alert ids are deliberately hidden from out-of-scope callers.
    assert (r.status_code, r.json()) == (404, {"error": "alert not found"})
    with _connect(db) as conn:
        row = conn.execute("SELECT status FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        assert row[0] == "failed"


def test_existing_host_create_rechecks_inside_the_insert_transaction(tmp_path, monkeypatch):
    db, host_id, _cert_id = _estate(tmp_path)
    moved: list = []
    _move_after_check(monkeypatch, "cert_watch.services.host_management", db, host_id, moved)
    monkeypatch.setattr(
        "cert_watch.routes.hosts.resolve_and_validate_host",
        lambda *args, **kwargs: (None, "192.0.2.1"),
    )

    async def scan(*args, **kwargs):
        return "success", None

    monkeypatch.setattr("cert_watch.routes.hosts._scan_and_store", scan)
    with _team_a_client(db, tmp_path) as client:
        r = client.post(
            "/hosts",
            data={"hostname": _HOST, "port": "443"},
            follow_redirects=False,
        )
    assert moved == ["moved"]
    assert r.status_code == 303
    assert "outside%20your%20team%20scope" in r.headers["location"]
    host = SqliteHostRepository(db).get(host_id)
    assert host is not None and host.tags == "team-b"


def test_existing_host_import_rechecks_inside_the_insert_transaction(tmp_path, monkeypatch):
    db, host_id, _cert_id = _estate(tmp_path)
    moved: list = []
    _move_after_check(monkeypatch, "cert_watch.services.host_management", db, host_id, moved)
    monkeypatch.setattr(
        "cert_watch.routes.hosts.resolve_and_validate_host",
        lambda *args, **kwargs: (None, "192.0.2.1"),
    )

    async def scan(*args, **kwargs):
        return "success", None

    monkeypatch.setattr("cert_watch.routes.hosts._scan_and_store", scan)
    content = f"hostname,port\n{_HOST},443\n"
    with _team_a_client(db, tmp_path) as client:
        r = client.post(
            "/hosts/import",
            files={"file": ("hosts.csv", content, "text/csv")},
            follow_redirects=False,
        )
    assert moved == ["moved"]
    assert r.status_code == 303
    assert "outside%20your%20team%20scope" in r.headers["location"]
    host = SqliteHostRepository(db).get(host_id)
    assert host is not None and host.tags == "team-b"


def test_manual_scan_rechecks_inside_the_scan_store_transaction(tmp_path, monkeypatch):
    db, host_id, cert_id = _estate(tmp_path)
    original = SqliteCertificateRepository(db).get_by_id(cert_id)
    moved: list = []
    _move_after_check(monkeypatch, "cert_watch.services.host_management", db, host_id, moved)
    _fake_successful_scan(monkeypatch)
    with _team_a_client(db, tmp_path) as client:
        r = client.post(f"/api/hosts/{host_id}/scan")
    assert moved == ["moved"]
    assert (r.status_code, r.json()) == (403, _REFUSED)
    assert SqliteCertificateRepository(db).get_by_id(cert_id) == original


def test_scan_all_rechecks_each_host_inside_its_store_transaction(tmp_path, monkeypatch):
    db, host_id, cert_id = _estate(tmp_path)
    original = SqliteCertificateRepository(db).get_by_id(cert_id)
    real = SqliteHostRepository.list_scoped
    moved: list[str] = []

    def list_then_move(repo, scope_tags):
        hosts = real(repo, scope_tags)
        if not moved:
            moved.append(_move_host(db, host_id))
        return hosts

    monkeypatch.setattr(SqliteHostRepository, "list_scoped", list_then_move)
    _fake_successful_scan(monkeypatch)
    with _team_a_client(db, tmp_path) as client:
        r = client.post("/api/hosts/scan")
    assert moved == ["moved"]
    assert (r.status_code, r.json()) == (403, _REFUSED)
    assert SqliteCertificateRepository(db).get_by_id(cert_id) == original


@pytest.mark.parametrize(
    "operation", ["settings", "delete", "read", "retry", "create", "import", "scan", "scan_all"]
)
def test_new_transaction_scope_routes_still_work_without_a_transfer(
    tmp_path, monkeypatch, operation
):
    if operation in {"read", "retry"}:
        db, host_id, target_id = _alert_estate(
            tmp_path, status="failed" if operation == "retry" else "pending"
        )
    else:
        db, host_id, _cert_id = _estate(tmp_path)
        target_id = host_id
    if operation in {"create", "import"}:
        monkeypatch.setattr(
            "cert_watch.routes.hosts.resolve_and_validate_host",
            lambda *args, **kwargs: (None, "192.0.2.1"),
        )

        async def route_scan(*args, **kwargs):
            return "success", None

        monkeypatch.setattr("cert_watch.routes.hosts._scan_and_store", route_scan)
    elif operation in {"scan", "scan_all"}:
        _fake_successful_scan(monkeypatch)
    with _team_a_client(db, tmp_path) as client:
        if operation == "settings":
            r = client.patch(
                f"/api/hosts/{target_id}/settings",
                json={
                    "scan_interval_hours": 12,
                    "threshold_days": 14,
                    "renewal_status": "pending",
                },
            )
        elif operation == "delete":
            r = client.delete(f"/api/hosts/{target_id}")
        elif operation == "read":
            r = client.post(f"/api/alerts/{target_id}/read")
        elif operation == "retry":
            r = client.post(f"/api/alerts/{target_id}/retry")
        elif operation == "create":
            r = client.post(
                "/hosts",
                data={"hostname": _HOST, "port": "443"},
                follow_redirects=False,
            )
        elif operation == "import":
            content = f"hostname,port\n{_HOST},443\n"
            r = client.post(
                "/hosts/import",
                files={"file": ("hosts.csv", content, "text/csv")},
                follow_redirects=False,
            )
        elif operation == "scan":
            r = client.post(f"/api/hosts/{target_id}/scan")
        else:
            r = client.post("/api/hosts/scan")
    assert r.status_code in ({303} if operation in {"create", "import"} else {200}), r.text


def test_a_caller_still_in_scope_is_not_refused(tmp_path, monkeypatch):
    """Control: without the transfer, the same request succeeds."""
    db, _host_id, cert_id = _estate(tmp_path)
    with _team_a_client(db, tmp_path) as client:
        r = client.put(f"/api/certificates/{cert_id}/tags", json={"tags": "team-a"})
    assert r.status_code == 200, r.text


def _conn_with_host_tags(tmp_path: Path, tags: str):
    from cert_watch.database.connection import _connect

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    host_id = SqliteHostRepository(db).add(_HOST, 443, tags=tags)
    return _connect(db), host_id


def test_the_in_transaction_check_keeps_the_read_only_tier(tmp_path):
    """A caller who sees team-b but may only read it is refused in the
    transaction too -- the tier half of the scope check."""
    from cert_watch.auth.rbac import AuthContext
    from cert_watch.auth.scope import ScopeDeniedError, ensure_write_scope_on

    conn, host_id = _conn_with_host_tags(tmp_path, "team-b")
    auth = AuthContext(
        username="u",
        roles=["viewer"],
        tier="viewer",
        scope_tag="team-a,team-b",
        tag_tiers={"team-a": "operator", "team-b": "viewer"},
    )
    with pytest.raises(ScopeDeniedError, match="read-only"):
        ensure_write_scope_on(conn, auth, host_id=host_id)


def test_the_in_transaction_check_lets_an_admin_through(tmp_path):
    """As the advisory check does: an administrator is never scope-limited,
    even one whose role also carries a scope tag."""
    from dataclasses import replace

    from cert_watch.auth.rbac import AuthContext
    from cert_watch.auth.scope import ensure_write_scope_on, write_scope_error

    conn, host_id = _conn_with_host_tags(tmp_path, "team-b")
    admin = replace(AuthContext.from_roles("u", ["admin"]), scope_tag="team-a")
    assert write_scope_error(admin, conn.execute("PRAGMA database_list").fetchone()[2]) is None
    ensure_write_scope_on(conn, admin, host_id=host_id)


def test_the_in_transaction_check_matches_scope_tags_case_insensitively(tmp_path):
    from cert_watch.auth.scope import ensure_write_scope_on

    conn, host_id = _conn_with_host_tags(tmp_path, "team-a")
    auth = AuthContext(
        username="u",
        roles=["operator"],
        tier="viewer",
        scope_tag="Team-A",
        tag_tiers={"Team-A": "operator"},
    )
    conn.execute("BEGIN IMMEDIATE")
    ensure_write_scope_on(conn, auth, host_id=host_id)
    conn.rollback()


def test_cross_process_transfer_is_endpoint_specific_for_same_name_other_port(
    tmp_path, monkeypatch
):
    db, host_id, cert_id = _estate(tmp_path)
    other_id = SqliteHostRepository(db).add(_HOST, 8443, tags="team-b")
    moved: list = []
    _move_after_check(monkeypatch, "cert_watch.services.resource_metadata", db, host_id, moved)
    with _team_a_client(db, tmp_path) as client:
        r = client.put(f"/api/certificates/{cert_id}/tags", json={"tags": "team-a"})
    assert moved == ["moved"]
    assert (r.status_code, r.json()) == (403, _REFUSED)
    assert SqliteHostRepository(db).get(host_id).tags == "team-b"  # type: ignore[union-attr]
    assert SqliteHostRepository(db).get(other_id).tags == "team-b"  # type: ignore[union-attr]
