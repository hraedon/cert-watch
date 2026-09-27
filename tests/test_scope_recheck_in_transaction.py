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


def _admin_client(db: Path, tmp_path: Path):
    from fastapi.testclient import TestClient

    from cert_watch.app import create_app
    from cert_watch.auth import SESSION_COOKIE, create_session
    from cert_watch.config import Settings
    from cert_watch.database import Role, SqliteRoleRepository

    SqliteRoleRepository(db).add(Role(name="admin", permission_tier="admin"))
    settings = Settings(
        db_path=db,
        data_dir=tmp_path,
        role_map={"admin": {"groups": ["admin-group"]}},
    )

    class _Provider:
        provider_name = "mock"

    client = TestClient(create_app(auth_provider=_Provider(), settings=settings))
    client.cookies.set(SESSION_COOKIE, create_session("alice", groups=["admin-group"]))
    return client


_REFUSED = {"error": "operation not permitted outside your team scope"}

_RACE_CASES = {
    "alert_retry": (
        ("POST", "/alerts/{alert_id}/retry"),
        ("POST", "/api/alerts/{alert_id}/retry"),
    ),
    "create": (("POST", "/hosts"), ("POST", "/api/hosts")),
    "import": (("POST", "/hosts/import"), ("POST", "/api/hosts/import")),
    "scan_all": (("POST", "/hosts/all/scan"), ("POST", "/api/hosts/scan")),
    "edit": (
        ("POST", "/hosts/{resource_id}/edit"),
        ("PUT", "/api/hosts/{resource_id}"),
    ),
    "settings": (
        ("POST", "/hosts/{host_id}/settings"),
        ("PATCH", "/api/hosts/{host_id}/settings"),
    ),
    "notes": (
        ("POST", "/hosts/{host_id}/notes"),
        ("PATCH", "/api/hosts/{host_id}/notes"),
    ),
    "host_tags": (
        ("POST", "/hosts/{host_id}/tags"),
        ("PUT", "/api/hosts/{host_id}/tags"),
    ),
    "expected_issuers": (
        ("POST", "/hosts/{host_id}/expected-issuers"),
        ("PUT", "/api/hosts/{host_id}/issuers"),
    ),
    "host_delete": (
        ("POST", "/hosts/{host_id}/delete"),
        ("DELETE", "/api/hosts/{host_id}"),
    ),
    "host_scan": (
        ("POST", "/hosts/{host_id}/scan"),
        ("POST", "/api/hosts/{host_id}/scan"),
    ),
    "certificate_delete": (
        ("POST", "/certificates/{cert_id}/delete"),
        ("DELETE", "/api/certificates/{cert_id}"),
    ),
    "certificate_tags": (
        ("POST", "/certificates/{cert_id}/tags"),
        ("PUT", "/api/certificates/{cert_id}/tags"),
    ),
    "certificate_owner": (
        ("POST", "/certificates/{cert_id}/owner"),
        ("PATCH", "/api/hosts/{host_id}/owner"),
    ),
    "host_owner": (
        ("POST", "/hosts/{host_id}/owner"),
        ("PATCH", "/api/hosts/{host_id}/owner"),
    ),
}
_RACE_ROUTE_PAIRS = set(_RACE_CASES.values())
_COLLECTED_RACE_CASES: set[str] = set()


def _race_adapters(*case_names: str):
    assert set(case_names) <= set(_RACE_CASES)
    _COLLECTED_RACE_CASES.update(case_names)
    return pytest.mark.parametrize("adapter", ("html", "api"))


def test_race_matrix_covers_every_paired_target_scoped_route() -> None:
    from tests.test_api_completeness import HTML_TO_JSON
    from tests.test_write_scope_transaction_inventory import _TARGET_CONTRACTS

    target_routes = {tuple(key.split(" ", 1)) for key in _TARGET_CONTRACTS}

    def is_existing_estate_target(route: tuple[str, str]) -> bool:
        return route in target_routes or any(
            parameter in route[1] for parameter in ("{host_id}", "{resource_id}", "{cert_id}")
        )

    expected = {
        (html, api)
        for html, api in HTML_TO_JSON.items()
        if is_existing_estate_target(html) and is_existing_estate_target(api)
    }
    assert expected == _RACE_ROUTE_PAIRS
    assert set(_RACE_CASES) == _COLLECTED_RACE_CASES
    paired_routes = {route for pair in expected for route in pair}
    assert target_routes - paired_routes == {("POST", "/api/alerts/{alert_id}/read")}


@_race_adapters("certificate_delete")
def test_certificate_delete(tmp_path, monkeypatch, adapter):
    db, host_id, cert_id = _estate(tmp_path)
    moved: list = []
    _move_after_check(monkeypatch, "cert_watch.services.certificate_management", db, host_id, moved)
    with _team_a_client(db, tmp_path) as client:
        if adapter == "html":
            r = client.post(f"/certificates/{cert_id}/delete", follow_redirects=False)
        else:
            r = client.delete(f"/api/certificates/{cert_id}")
    assert moved == ["moved"]
    if adapter == "html":
        assert r.status_code == 303
        assert "outside%20your%20team%20scope" in r.headers["location"]
    else:
        assert (r.status_code, r.json()) == (403, _REFUSED)
    assert SqliteCertificateRepository(db).get_by_id(cert_id) is not None


@_race_adapters("certificate_tags")
def test_certificate_tags(tmp_path, monkeypatch, adapter):
    db, host_id, cert_id = _estate(tmp_path)
    moved: list = []
    _move_after_check(monkeypatch, "cert_watch.services.resource_metadata", db, host_id, moved)
    with _team_a_client(db, tmp_path) as client:
        if adapter == "html":
            r = client.post(
                f"/certificates/{cert_id}/tags",
                data={"tags": "team-a"},
                follow_redirects=False,
            )
        else:
            r = client.put(f"/api/certificates/{cert_id}/tags", json={"tags": "team-a"})
    assert moved == ["moved"]
    if adapter == "html":
        assert r.status_code == 303
        assert "outside%20your%20team%20scope" in r.headers["location"]
    else:
        assert (r.status_code, r.json()) == (403, _REFUSED)
    assert SqliteCertificateRepository(db).get_tags(cert_id) == ""


@_race_adapters("edit")
def test_combined_certificate_edit_rechecks_host_scope_after_two_process_race(
    tmp_path, monkeypatch, adapter
):
    db, host_id, cert_id = _estate(tmp_path)
    SqliteCertificateRepository(db).set_tags(cert_id, "team-a")
    moved: list = []
    _move_after_check(monkeypatch, "cert_watch.services.host_edit", db, host_id, moved)
    body = {
        "owner_name": "attempted",
        "owner_email": "owner@example.test",
        "owner_slack": "",
        "renewal_method": "manual",
        "runbook_url": "https://runbooks.example.test/tls",
        "scan_interval_hours": 12,
        "threshold_days": 30,
        "renewal_status": "pending",
        "notes": "attempted",
        "tags": "team-a",
    }
    with _team_a_client(db, tmp_path) as client:
        if adapter == "html":
            r = client.post(f"/hosts/{cert_id}/edit", data=body, follow_redirects=False)
        else:
            r = client.put(f"/api/hosts/{cert_id}", json=body)
    assert moved == ["moved"]
    if adapter == "html":
        assert r.status_code == 303
        assert "outside%20your%20team%20scope" in r.headers["location"]
    else:
        assert (r.status_code, r.json()) == (403, _REFUSED)
    host = SqliteHostRepository(db).get(host_id)
    assert host is not None
    assert (host.tags, host.notes, host.owner_name) == ("team-b", "", "")
    assert SqliteCertificateRepository(db).get_tags(cert_id) == "team-a"


@_race_adapters("certificate_owner", "host_owner")
@pytest.mark.parametrize("addressed_by", ["certificate", "host"])
def test_ownership(tmp_path, monkeypatch, addressed_by, adapter):
    db, host_id, cert_id = _estate(tmp_path)
    # The certificate remains visible to team-a after the host moves.  That
    # must not let its own tag authorize a write to the now-team-b host.
    SqliteCertificateRepository(db).set_tags(cert_id, "team-a")
    moved: list = []
    _move_after_check(monkeypatch, "cert_watch.services.host_ownership", db, host_id, moved)
    with _team_a_client(db, tmp_path) as client:
        if adapter == "html":
            route = (
                f"/certificates/{cert_id}/owner"
                if addressed_by == "certificate"
                else f"/hosts/{host_id}/owner"
            )
            r = client.post(
                route,
                data={"owner_name": "team-a-took-it", "renewal_method": "manual"},
                follow_redirects=False,
            )
        else:
            r = client.patch(
                f"/api/hosts/{host_id}/owner",
                json={"owner_name": "team-a-took-it", "renewal_method": "manual"},
            )
    assert moved == ["moved"]
    if adapter == "html":
        assert r.status_code == 303
        assert "outside%20your%20team%20scope" in r.headers["location"]
    else:
        assert (r.status_code, r.json()) == (403, _REFUSED)
    [host] = SqliteHostRepository(db).list_all()
    assert host.owner_name == ""


@pytest.mark.parametrize("field", ["notes", "tags"])
@_race_adapters("notes", "host_tags")
def test_host_notes_and_tags(tmp_path, monkeypatch, field, adapter):
    db, host_id, _cert_id = _estate(tmp_path)
    moved: list = []
    _move_after_check(monkeypatch, "cert_watch.services.resource_metadata", db, host_id, moved)
    body = {"notes": "team-a was here"} if field == "notes" else {"tags": "team-a"}
    with _team_a_client(db, tmp_path) as client:
        if adapter == "html":
            r = client.post(f"/hosts/{host_id}/{field}", data=body, follow_redirects=False)
        else:
            method = "patch" if field == "notes" else "put"
            r = getattr(client, method)(f"/api/hosts/{host_id}/{field}", json=body)
    assert moved == ["moved"]
    if adapter == "html":
        assert r.status_code == 303
        assert "outside%20your%20team%20scope" in r.headers["location"]
    else:
        assert (r.status_code, r.json()) == (403, _REFUSED)
    [host] = SqliteHostRepository(db).list_all()
    assert (host.tags, host.notes) == ("team-b", "")


@_race_adapters("settings")
def test_host_settings(tmp_path, monkeypatch, adapter):
    db, host_id, _cert_id = _estate(tmp_path)
    moved: list = []
    _move_after_check(monkeypatch, "cert_watch.services.host_management", db, host_id, moved)
    with _team_a_client(db, tmp_path) as client:
        body = {
            "scan_interval_hours": 12,
            "threshold_days": 14,
            "renewal_status": "in_progress",
        }
        if adapter == "html":
            r = client.post(f"/hosts/{host_id}/settings", data=body, follow_redirects=False)
        else:
            r = client.patch(f"/api/hosts/{host_id}/settings", json=body)
    assert moved == ["moved"]
    if adapter == "html":
        assert r.status_code == 303
        assert "outside%20your%20team%20scope" in r.headers["location"]
    else:
        assert (r.status_code, r.json()) == (403, _REFUSED)
    host = SqliteHostRepository(db).get(host_id)
    assert host is not None
    assert (host.scan_interval_hours, host.threshold_days, host.renewal_status) == (
        None,
        None,
        "pending",
    )


@_race_adapters("expected_issuers")
def test_expected_issuers_admin_adapters_share_service_during_tag_change(
    tmp_path, monkeypatch, adapter
):
    """Both admin adapters reach the service; no scope re-check is expected."""
    db, host_id, _cert_id = _estate(tmp_path)
    moved: list = []
    _move_after_check(monkeypatch, "cert_watch.services.host_management", db, host_id, moved)
    with _admin_client(db, tmp_path) as client:
        if adapter == "html":
            r = client.post(
                f"/hosts/{host_id}/expected-issuers",
                data={"expected_issuers": "Example CA"},
                follow_redirects=False,
            )
        else:
            r = client.put(
                f"/api/hosts/{host_id}/issuers",
                json={"issuers": ["Example CA"]},
            )
    assert moved == ["moved"]
    assert r.status_code == (303 if adapter == "html" else 200), r.text
    assert SqliteHostRepository(db).get_expected_issuers(host_id) == ["Example CA"]


@_race_adapters("host_delete")
def test_host_delete(tmp_path, monkeypatch, adapter):
    db, host_id, _cert_id = _estate(tmp_path)
    moved: list = []
    _move_after_check(monkeypatch, "cert_watch.services.host_management", db, host_id, moved)
    with _team_a_client(db, tmp_path) as client:
        if adapter == "html":
            r = client.post(f"/hosts/{host_id}/delete", follow_redirects=False)
        else:
            r = client.delete(f"/api/hosts/{host_id}")
    assert moved == ["moved"]
    if adapter == "html":
        assert r.status_code == 303
        assert "outside%20your%20team%20scope" in r.headers["location"]
    else:
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


@_race_adapters("alert_retry")
def test_alert_retry(tmp_path, monkeypatch, adapter):
    db, host_id, alert_id = _alert_estate(tmp_path, status="failed")
    moved: list = []
    _move_after_check(monkeypatch, "cert_watch.auth.scope", db, host_id, moved)
    with _team_a_client(db, tmp_path) as client:
        path = f"/alerts/{alert_id}/retry" if adapter == "html" else f"/api/alerts/{alert_id}/retry"
        r = client.post(path, follow_redirects=False)
    assert moved == ["moved"]
    # Alert ids are deliberately hidden from out-of-scope callers.
    if adapter == "html":
        assert r.status_code == 303
        assert r.headers["location"] == "/alerts?error=alert+not+found"
    else:
        assert (r.status_code, r.json()) == (404, {"error": "alert not found"})
    with _connect(db) as conn:
        row = conn.execute("SELECT status FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        assert row[0] == "failed"


@_race_adapters("create")
def test_existing_host_create_rechecks_inside_the_insert_transaction(
    tmp_path, monkeypatch, adapter
):
    db, host_id, _cert_id = _estate(tmp_path)
    moved: list = []
    _move_after_check(monkeypatch, "cert_watch.services.host_management", db, host_id, moved)
    monkeypatch.setattr(
        "cert_watch.routes.hosts.resolve_and_validate_host",
        lambda *args, **kwargs: (None, "192.0.2.1"),
    )
    api_host_routes = importlib.import_module("cert_watch.routes.api.hosts")
    monkeypatch.setattr(
        api_host_routes,
        "resolve_and_validate_host",
        lambda *args, **kwargs: (None, "192.0.2.1"),
    )

    async def scan(*args, **kwargs):
        return "success", None

    monkeypatch.setattr("cert_watch.routes.hosts._scan_and_store", scan)
    with _team_a_client(db, tmp_path) as client:
        if adapter == "html":
            r = client.post(
                "/hosts",
                data={"hostname": _HOST, "port": "443"},
                follow_redirects=False,
            )
        else:
            r = client.post("/api/hosts", json={"hostname": _HOST, "port": 443})
    assert moved == ["moved"]
    if adapter == "html":
        assert r.status_code == 303
        assert "outside%20your%20team%20scope" in r.headers["location"]
    else:
        assert (r.status_code, r.json()) == (403, _REFUSED)
    host = SqliteHostRepository(db).get(host_id)
    assert host is not None and host.tags == "team-b"


@_race_adapters("import")
def test_existing_host_import_rechecks_inside_the_insert_transaction(
    tmp_path, monkeypatch, adapter
):
    db, host_id, _cert_id = _estate(tmp_path)
    moved: list = []
    _move_after_check(monkeypatch, "cert_watch.services.host_management", db, host_id, moved)
    monkeypatch.setattr(
        "cert_watch.routes.hosts.resolve_and_validate_host",
        lambda *args, **kwargs: (None, "192.0.2.1"),
    )
    api_host_routes = importlib.import_module("cert_watch.routes.api.hosts")
    monkeypatch.setattr(
        api_host_routes,
        "resolve_and_validate_host",
        lambda *args, **kwargs: (None, "192.0.2.1"),
    )

    async def scan(*args, **kwargs):
        return "success", None

    monkeypatch.setattr("cert_watch.routes.hosts._scan_and_store", scan)
    content = f"hostname,port\n{_HOST},443\n"
    with _team_a_client(db, tmp_path) as client:
        path = "/hosts/import" if adapter == "html" else "/api/hosts/import"
        r = client.post(
            path,
            files={"file": ("hosts.csv", content, "text/csv")},
            follow_redirects=False,
        )
    assert moved == ["moved"]
    if adapter == "html":
        assert r.status_code == 303
        assert "outside%20your%20team%20scope" in r.headers["location"]
    else:
        assert r.status_code == 400
        assert "outside your team scope" in r.json()["errors"][0]
    host = SqliteHostRepository(db).get(host_id)
    assert host is not None and host.tags == "team-b"


@_race_adapters("host_scan")
def test_manual_scan_rechecks_inside_the_scan_store_transaction(tmp_path, monkeypatch, adapter):
    db, host_id, cert_id = _estate(tmp_path)
    original = SqliteCertificateRepository(db).get_by_id(cert_id)
    moved: list = []
    _move_after_check(monkeypatch, "cert_watch.services.host_management", db, host_id, moved)
    _fake_successful_scan(monkeypatch)
    with _team_a_client(db, tmp_path) as client:
        path = f"/hosts/{host_id}/scan" if adapter == "html" else f"/api/hosts/{host_id}/scan"
        r = client.post(path, follow_redirects=False)
    assert moved == ["moved"]
    if adapter == "html":
        assert r.status_code == 303
        assert "outside%20your%20team%20scope" in r.headers["location"]
    else:
        assert (r.status_code, r.json()) == (403, _REFUSED)
    assert SqliteCertificateRepository(db).get_by_id(cert_id) == original


@_race_adapters("scan_all")
def test_scan_all_rechecks_each_host_inside_its_store_transaction(tmp_path, monkeypatch, adapter):
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
        path = "/hosts/all/scan" if adapter == "html" else "/api/hosts/scan"
        r = client.post(path, follow_redirects=False)
    assert moved == ["moved"]
    if adapter == "html":
        assert r.status_code == 303
        assert "scanned=0&failures=0&refused=1" in r.headers["location"]
    else:
        assert (r.status_code, r.json()) == (
            200,
            {"scanned": 0, "failures": 0, "refused": 1},
        )
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
