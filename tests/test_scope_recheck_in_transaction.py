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

from cert_watch.certificate_model import parse_certificate
from cert_watch.database import SqliteCertificateRepository, SqliteHostRepository, init_schema
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
