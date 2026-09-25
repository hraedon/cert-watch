"""Mutations addressed by a renewed-away certificate id (#115 review round 2).

A renewal gives the endpoint's certificate a new id and moves the operator's
tags and manual alert-group assignments to it. A request still naming the
old id -- a form left open, an API call queued behind the scan that renewed
it -- used to fall through: an unassign deleted nothing yet answered
"unassigned" (the group kept receiving alerts), and a delete answered
success for nothing deleted.

The rule, applied to every certificate-id-addressed mutation, inside the
write lock: refuse with 409 naming the current certificate (JSON) or send
the form back to the current certificate with a note (HTML). Never retarget,
never report success for a no-op; out of scope, answer as for an unknown id.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from cert_watch.certificate_model import parse_certificate
from cert_watch.database import (
    SqliteAlertGroupRepository,
    SqliteCertificateRepository,
    SqliteHostRepository,
    get_write_lock,
    init_schema,
)
from tests._helpers import seed_scanned
from tests.conftest import _make_cert

_HOST = "renewed.example.test"


@pytest.fixture(autouse=True)
def _no_startup_scan(monkeypatch):
    """The lifespan's scheduler would scan the registered host at startup."""
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.start", lambda self: None)
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.stop", lambda self: None)


def _renewed(tmp_path: Path, self_signed_leaf, *, assign: bool = False):
    """(db, old id, current id, group id): a certificate renewed after it was
    tagged and (optionally) assigned to a group."""
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    SqliteHostRepository(db).add(_HOST, 443)
    old = seed_scanned(db, _HOST, 443, parse_certificate(self_signed_leaf.der))
    SqliteCertificateRepository(db).set_tags(old, "team-a")
    groups = SqliteAlertGroupRepository(db)
    group_id = groups.create(name="G", recipients=["g@example.test"], match_tags=[])
    if assign:
        groups.assign_cert(group_id, old)
    new = _renew(db)
    return db, old, new, group_id


def _renew(db: Path) -> str:
    return seed_scanned(db, _HOST, 443, parse_certificate(_make_cert(_HOST, days_valid=90).der))


def _assert_conflict(r, old: str, new: str) -> None:
    assert r.status_code == 409, r.text
    body = r.json()
    assert body["cert_id"] == old
    assert body["current_cert_id"] == new


def _assert_sent_to_current(r, new: str) -> None:
    assert r.status_code == 303
    location = urlsplit(r.headers["location"])
    assert location.path == f"/certificates/{new}"
    assert "renewed" in parse_qs(location.query)["error"][0]


# -- JSON API ------------------------------------------------------------


def test_api_unassign_by_old_id_is_refused_and_the_route_is_kept(
    tmp_path, reload_app, self_signed_leaf
):
    db, old, new, group_id = _renewed(tmp_path, self_signed_leaf, assign=True)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.delete(f"/api/alert-groups/{group_id}/certs/{old}")
    _assert_conflict(r, old, new)
    assert SqliteAlertGroupRepository(db).groups_for_cert_manual(new) == [group_id]


def test_api_unassign_queued_behind_the_renewing_scan_is_refused(
    tmp_path, reload_app, self_signed_leaf
):
    """The request is judged inside the write lock: one that was waiting on
    the lock while the scan renewed the certificate sees the renewal."""
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    SqliteHostRepository(db).add(_HOST, 443)
    old = seed_scanned(db, _HOST, 443, parse_certificate(self_signed_leaf.der))
    groups = SqliteAlertGroupRepository(db)
    group_id = groups.create(name="G", recipients=["g@example.test"], match_tags=[])
    groups.assign_cert(group_id, old)
    app_mod = reload_app()
    result: dict = {}
    with TestClient(app_mod.app) as client:
        with get_write_lock():  # the scan holds the lock ...
            worker = threading.Thread(
                target=lambda: result.update(
                    r=client.delete(f"/api/alert-groups/{group_id}/certs/{old}")
                )
            )
            worker.start()
            time.sleep(0.3)  # ... while the unassign queues behind it
            assert "r" not in result
            new = _renew(db)  # and renews the certificate
        worker.join(timeout=10)
    _assert_conflict(result["r"], old, new)
    assert groups.groups_for_cert_manual(new) == [group_id]


def test_api_unassign_that_removes_nothing_says_so(tmp_path, reload_app, self_signed_leaf):
    _db, _old, new, group_id = _renewed(tmp_path, self_signed_leaf)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.delete(f"/api/alert-groups/{group_id}/certs/{new}")
    assert r.status_code == 404
    assert "not assigned" in r.json()["error"]


def test_api_assign_by_old_id_is_refused(tmp_path, reload_app, self_signed_leaf):
    db, old, new, group_id = _renewed(tmp_path, self_signed_leaf)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(f"/api/alert-groups/{group_id}/certs/{old}")
    _assert_conflict(r, old, new)
    assert SqliteAlertGroupRepository(db).groups_for_cert_manual(new) == []


def test_api_tags_put_by_old_id_is_refused(tmp_path, reload_app, self_signed_leaf):
    db, old, new, _ = _renewed(tmp_path, self_signed_leaf)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.put(f"/api/certificates/{old}/tags", json={"tags": "team-b"})
    _assert_conflict(r, old, new)
    assert SqliteCertificateRepository(db).get_tags(new) == "team-a"


def test_api_delete_by_old_id_is_refused_and_deletes_nothing(
    tmp_path, reload_app, self_signed_leaf
):
    db, old, new, _ = _renewed(tmp_path, self_signed_leaf)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.delete(f"/api/certificates/{old}")
    _assert_conflict(r, old, new)
    assert SqliteCertificateRepository(db).get_by_id(new) is not None


# -- HTML forms ----------------------------------------------------------


def test_form_delete_by_old_id_returns_to_the_current_certificate(
    tmp_path, reload_app, self_signed_leaf
):
    """Pre-fix this answered a plain redirect Home, as if it had deleted."""
    db, old, new, _ = _renewed(tmp_path, self_signed_leaf)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(f"/certificates/{old}/delete", follow_redirects=False)
    _assert_sent_to_current(r, new)
    assert SqliteCertificateRepository(db).get_by_id(new) is not None


def test_form_tags_by_old_id_returns_to_the_current_certificate(
    tmp_path, reload_app, self_signed_leaf
):
    db, old, new, _ = _renewed(tmp_path, self_signed_leaf)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            f"/certificates/{old}/tags", data={"tags": "team-b"}, follow_redirects=False
        )
    _assert_sent_to_current(r, new)
    assert SqliteCertificateRepository(db).get_tags(new) == "team-a"


@pytest.mark.parametrize("route", ["/certificates/{id}/owner", "/hosts/{id}/owner"])
def test_form_owner_by_old_id_returns_to_the_current_certificate(
    tmp_path, reload_app, self_signed_leaf, route
):
    db, old, new, _ = _renewed(tmp_path, self_signed_leaf)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            route.format(id=old),
            data={"owner_name": "Someone", "owner_email": "someone@example.test"},
            follow_redirects=False,
        )
    _assert_sent_to_current(r, new)
    [host] = SqliteHostRepository(db).list_all()
    assert host.owner_name == ""


# -- services: the check sits inside the write lock ----------------------


def test_owner_target_resolved_before_the_renewal_is_refused(tmp_path, self_signed_leaf):
    """A route resolves the ownership target from the certificate id before
    taking the lock; if a renewal lands in between, the write is refused."""
    from cert_watch.auth.rbac import AuthContext
    from cert_watch.services.certificate_identity import CertificateSupersededError
    from cert_watch.services.host_ownership import (
        HostOwnershipUpdate,
        resolve_host_ownership_target,
        update_host_ownership,
    )

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    SqliteHostRepository(db).add(_HOST, 443)
    old = seed_scanned(db, _HOST, 443, parse_certificate(self_signed_leaf.der))
    target = resolve_host_ownership_target(db, old, auth=AuthContext.system())
    new = _renew(db)
    with pytest.raises(CertificateSupersededError) as info:
        update_host_ownership(
            db,
            target,
            HostOwnershipUpdate(owner_name="Someone"),
            auth=AuthContext.system(),
            actor="t",
            source_ip=None,
        )
    assert info.value.current_id == new


def _answers(client, cert_id: str) -> list[tuple[int, str]]:
    """What each certificate-id mutation answers for *cert_id*."""
    out = []
    for r in (
        client.put(f"/api/certificates/{cert_id}/tags", json={"tags": "x"}),
        client.delete(f"/api/certificates/{cert_id}"),
        client.post(f"/certificates/{cert_id}/tags", data={"tags": "x"}, follow_redirects=False),
        client.post(f"/certificates/{cert_id}/delete", follow_redirects=False),
        client.post(
            f"/certificates/{cert_id}/owner", data={"owner_name": "x"}, follow_redirects=False
        ),
    ):
        detail = r.headers.get("location") or str(r.json())
        out.append((r.status_code, detail))
    return out


def test_out_of_scope_caller_gets_exactly_the_unknown_id_answer(tmp_path, self_signed_leaf):
    """Round 3 (Fable): a superseded id whose successor the caller can't see
    must be indistinguishable from an id that never existed, route by route.
    Pre-fix it was the only case answering 404 "not found" (an unknown id
    gets the scope refusal), which revealed that the id was real and renewed."""
    from tests.test_tag_scoped_access import _make_scoped_app, _scoped_client

    db, old, _new, _ = _renewed(tmp_path, self_signed_leaf)  # the successor is team-a
    app, groups = _make_scoped_app(db, tmp_path, scope_tag="team-b")
    with _scoped_client(app, groups) as client:
        unknown = _answers(client, "00000000-0000-0000-0000-000000000000")
        superseded = _answers(client, old)
    assert unknown[0] == (403, "{'error': 'operation not permitted outside your team scope'}")
    assert superseded == unknown


def test_a_deleted_id_is_not_reported_as_renewed(tmp_path, reload_app, self_signed_leaf):
    """Round 3 (Fable): an operator deletes certificate D; a later scan adds
    E. D has no successor row, so a mutation naming D is an ordinary
    not-found -- not "renewed", which the lifecycle-event fallback used to
    claim by resolving D's endpoint to E."""
    from cert_watch.database import delete_certificate_cascade

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    SqliteHostRepository(db).add(_HOST, 443)
    deleted = seed_scanned(db, _HOST, 443, parse_certificate(self_signed_leaf.der))
    assert delete_certificate_cascade(db, deleted)
    _renew(db)  # the endpoint's next certificate: a cert_added, no lineage to D
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.delete(f"/api/certificates/{deleted}")
        f = client.post(f"/certificates/{deleted}/tags", data={"tags": "x"}, follow_redirects=False)
    assert (r.status_code, r.json()) == (404, {"error": "certificate not found"})
    assert f.headers["location"] == "/?error=certificate+not+found"


def test_unknown_and_current_ids_pass_through(tmp_path, self_signed_leaf):
    from cert_watch.auth.rbac import AuthContext
    from cert_watch.database.connection import _connect
    from cert_watch.services.certificate_identity import ensure_not_superseded

    db, _old, new, _ = _renewed(tmp_path, self_signed_leaf)
    conn = _connect(db)
    ensure_not_superseded(conn, new, auth=AuthContext.system())
    ensure_not_superseded(conn, "00000000-0000-0000-0000-000000000000", auth=AuthContext.system())


# -- a second process can't renew between the check and the write -------

_RENEW = r"""
import sys
from cert_watch.certificate_model import parse_certificate
from cert_watch.database import replace_scanned
from tests.conftest import _make_cert
db, host = sys.argv[1], sys.argv[2]
leaf = parse_certificate(_make_cert(host, days_valid=90).der)
print(replace_scanned(db, host, 443, leaf, [], None)[0])
"""


def _checking_then_racing(monkeypatch, module: str, db: Path, seen: dict) -> None:
    """Wrap *module*'s ``ensure_not_superseded`` so that, right after the real
    check passes, another PROCESS tries to renew the certificate. It records
    whether that renewal was still waiting when the write went ahead."""
    import importlib
    import subprocess
    import sys

    target = importlib.import_module(module)
    real = target.ensure_not_superseded

    def racing(*args, **kwargs):
        real(*args, **kwargs)
        if "proc" in seen:
            return
        proc = subprocess.Popen(
            [sys.executable, "-c", _RENEW, str(db), _HOST],
            cwd=Path(__file__).resolve().parent.parent,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        seen["proc"] = proc
        try:
            proc.wait(timeout=2.5)
        except subprocess.TimeoutExpired:
            seen["blocked"] = True
        else:
            seen["blocked"] = False

    monkeypatch.setattr(target, "ensure_not_superseded", racing)


def test_cross_process_renewal_waits_for_the_owner_write(tmp_path, monkeypatch, self_signed_leaf):
    """Round 3 (Sol): process A passed the check, process B renewed, and A's
    stale owner write then succeeded. The check and the write now share one
    BEGIN IMMEDIATE transaction, so B waits until A has committed."""
    from cert_watch.auth.rbac import AuthContext
    from cert_watch.services.host_ownership import (
        HostOwnershipUpdate,
        resolve_host_ownership_target,
        update_host_ownership,
    )

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    SqliteHostRepository(db).add(_HOST, 443)
    old = seed_scanned(db, _HOST, 443, parse_certificate(self_signed_leaf.der))
    seen: dict = {}
    _checking_then_racing(monkeypatch, "cert_watch.services.host_ownership", db, seen)
    target = resolve_host_ownership_target(db, old, auth=AuthContext.system())
    update_host_ownership(
        db,
        target,
        HostOwnershipUpdate(owner_name="written-before-renewal"),
        auth=AuthContext.system(),
        actor="t",
        source_ip=None,
    )
    out, err = seen["proc"].communicate(timeout=30)
    assert seen["proc"].returncode == 0, err
    assert seen["blocked"] is True, "the other process renewed between check and write"
    assert out.strip().splitlines()[-1] != old  # and it did renew, afterwards


def test_cross_process_renewal_waits_for_the_assign_write(
    tmp_path, monkeypatch, reload_app, self_signed_leaf
):
    """The same for an alert-group assignment: had the renewal landed in
    between, the insert would have named a deleted id."""
    db, _old, cur, group_id = _renewed(tmp_path, self_signed_leaf)
    seen: dict = {}
    _checking_then_racing(monkeypatch, "cert_watch.routes.api.alerts", db, seen)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(f"/api/alert-groups/{group_id}/certs/{cur}")
    out, err = seen["proc"].communicate(timeout=30)
    assert seen["proc"].returncode == 0, err
    assert r.status_code == 200, r.text
    assert seen["blocked"] is True, "the other process renewed between check and write"
    renewed = out.strip().splitlines()[-1]
    # The assignment was made on the live row and then carried by the renewal.
    assert SqliteAlertGroupRepository(db).groups_for_cert_manual(renewed) == [group_id]


@pytest.mark.parametrize(
    ("module", "call"),
    [
        ("cert_watch.services.certificate_management", "delete"),
        ("cert_watch.services.resource_metadata", "tags"),
    ],
)
def test_cross_process_renewal_waits_for_the_delete_and_tags_writes(
    tmp_path, monkeypatch, reload_app, self_signed_leaf, module, call
):
    db, _old, cur, _ = _renewed(tmp_path, self_signed_leaf)
    seen: dict = {}
    _checking_then_racing(monkeypatch, module, db, seen)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        if call == "delete":
            r = client.delete(f"/api/certificates/{cur}")
        else:
            r = client.put(f"/api/certificates/{cur}/tags", json={"tags": "team-a,late"})
    out, err = seen["proc"].communicate(timeout=30)
    assert seen["proc"].returncode == 0, err
    assert r.status_code == 200, r.text
    assert seen["blocked"] is True, "the other process renewed between check and write"
    if call == "tags":
        # Written to the live row first, then carried by the renewal.
        renewed = out.strip().splitlines()[-1]
        assert SqliteCertificateRepository(db).get_tags(renewed) == "team-a,late"


def test_in_scope_caller_is_told_about_the_renewal_not_refused_by_scope(tmp_path, self_signed_leaf):
    """A scoped caller who can see the successor gets the 409 with its id --
    not the scope refusal an id without tags would otherwise get."""
    from tests.test_tag_scoped_access import _make_scoped_app, _scoped_client

    db, old, new, _ = _renewed(tmp_path, self_signed_leaf)  # the successor is team-a
    app, groups = _make_scoped_app(db, tmp_path, scope_tag="team-a")
    with _scoped_client(app, groups) as client:
        tags = client.put(f"/api/certificates/{old}/tags", json={"tags": "team-a"})
        delete = client.delete(f"/api/certificates/{old}")
    _assert_conflict(tags, old, new)
    _assert_conflict(delete, old, new)


def test_cross_process_renewal_waits_for_the_unassign_write(
    tmp_path, monkeypatch, reload_app, self_signed_leaf
):
    """Had the renewal landed between check and delete, the unassign would
    have removed nothing while the renewal carried the assignment forward."""
    db, _old, cur, group_id = _renewed(tmp_path, self_signed_leaf)
    SqliteAlertGroupRepository(db).assign_cert(group_id, cur)
    seen: dict = {}
    _checking_then_racing(monkeypatch, "cert_watch.routes.api.alerts", db, seen)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.delete(f"/api/alert-groups/{group_id}/certs/{cur}")
    out, err = seen["proc"].communicate(timeout=30)
    assert seen["proc"].returncode == 0, err
    assert r.status_code == 200, r.text
    assert seen["blocked"] is True, "the other process renewed between check and write"
    renewed = out.strip().splitlines()[-1]
    assert SqliteAlertGroupRepository(db).groups_for_cert_manual(renewed) == []


# -- round 4 -----------------------------------------------------------


def _coexisting_lineage(db: Path) -> tuple[str, str, str]:
    """A -> B -> C with all three rows still stored (the schema allows it):
    A is tagged team-old, the current C team-new."""
    from tests._helpers import seed_certificate

    init_schema(db)
    SqliteHostRepository(db).add(_HOST, 443)
    ids: list[str] = []
    for days, tags in ((30, "team-old"), (60, ""), (90, "team-new")):
        cert_id = seed_certificate(
            db,
            parse_certificate(_make_cert(_HOST, days_valid=days).der),
            hostname=_HOST,
            port=443,
            source="scanned",
            replaces_cert_id=ids[-1] if ids else None,
        )
        SqliteCertificateRepository(db).set_tags(cert_id, tags)
        ids.append(cert_id)
    return ids[0], ids[1], ids[2]


def test_a_stale_row_coexisting_with_its_successor_is_superseded(tmp_path, reload_app):
    """Round 4 (Sol): the guard returned as soon as the addressed row existed.
    A still exists, but C replaces it (through B): an admin is told about C."""
    db = tmp_path / "cert-watch.sqlite3"
    a, b, c = _coexisting_lineage(db)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        for stale in (a, b):
            _assert_conflict(
                client.put(f"/api/certificates/{stale}/tags", json={"tags": "x"}), stale, c
            )
    assert SqliteCertificateRepository(db).get_tags(a) == "team-old"


def test_old_team_cannot_act_on_a_stale_row_to_reach_the_current_certificate(tmp_path):
    """Sol's probe: a user scoped only to stale A changed host ownership,
    though they can't access current C. They now get exactly the unknown-id
    answer on every route, and nothing changes."""
    from tests.test_tag_scoped_access import _make_scoped_app, _scoped_client

    db = tmp_path / "cert-watch.sqlite3"
    a, _b, c = _coexisting_lineage(db)
    app, groups = _make_scoped_app(db, tmp_path, scope_tag="team-old")
    with _scoped_client(app, groups) as client:
        unknown = _answers(client, "00000000-0000-0000-0000-000000000000")
        stale = _answers(client, a)
    assert stale == unknown
    [host] = SqliteHostRepository(db).list_all()
    assert host.owner_name == ""
    assert SqliteCertificateRepository(db).get_tags(a) == "team-old"
    assert SqliteCertificateRepository(db).get_by_id(a) is not None
    assert SqliteCertificateRepository(db).get_by_id(c) is not None


def test_two_renewals_ago_is_refused_with_the_current_certificate(
    tmp_path, reload_app, self_signed_leaf
):
    """Round 4 (Fable): A -> B -> C by ordinary renewals, so A's and B's rows
    are gone. The page for A redirects to C; a change sent from it is refused
    with C too -- not "certificate not found" or a bare redirect Home."""
    db, a, _b, group_id = _renewed(tmp_path, self_signed_leaf, assign=True)
    c = seed_scanned(db, _HOST, 443, parse_certificate(_make_cert(_HOST, days_valid=70).der))
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        _assert_sent_to_current(
            client.post(f"/certificates/{a}/tags", data={"tags": "x"}, follow_redirects=False), c
        )
        _assert_sent_to_current(
            client.post(
                f"/certificates/{a}/owner", data={"owner_name": "x"}, follow_redirects=False
            ),
            c,
        )
        _assert_sent_to_current(client.post(f"/certificates/{a}/delete", follow_redirects=False), c)
        _assert_conflict(client.put(f"/api/certificates/{a}/tags", json={"tags": "x"}), a, c)
        _assert_conflict(client.delete(f"/api/certificates/{a}"), a, c)
        _assert_conflict(client.post(f"/api/alert-groups/{group_id}/certs/{a}"), a, c)
        _assert_conflict(client.delete(f"/api/alert-groups/{group_id}/certs/{a}"), a, c)
    assert SqliteCertificateRepository(db).get_tags(c) == "team-a"
    assert SqliteAlertGroupRepository(db).groups_for_cert_manual(c) == [group_id]


def test_form_delete_of_an_unknown_id_says_so_and_is_not_audited(tmp_path, reload_app):
    """Round 4 (Fable, pre-existing): it redirected Home silently and wrote a
    cert.delete audit row for a delete that deleted nothing."""
    from cert_watch.database.connection import _connect

    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/certificates/00000000-0000-0000-0000-000000000000/delete", follow_redirects=False
        )
    assert r.headers["location"] == "/?error=certificate+not+found"
    with _connect(db) as conn:
        audited = conn.execute("SELECT 1 FROM audit_log WHERE action = 'cert.delete'").fetchall()
    assert audited == []


def _delete_in_another_process(db: Path, sql: str, param: str) -> None:
    import subprocess
    import sys

    subprocess.run(
        [
            sys.executable,
            "-c",
            "import sqlite3, sys; c = sqlite3.connect(sys.argv[1]); "
            "c.execute(sys.argv[2], (sys.argv[3],)); c.commit()",
            str(db),
            sql,
            param,
        ],
        check=True,
    )


def test_assign_refuses_a_group_deleted_by_another_process_after_the_precheck(
    tmp_path, monkeypatch, reload_app, self_signed_leaf
):
    """Round 4 (Sol): the group was checked before the insert's transaction;
    a concurrent group delete left an orphan assignment and a 200."""
    import importlib

    alerts_routes = importlib.import_module("cert_watch.routes.api.alerts")

    db, _old, cur, group_id = _renewed(tmp_path, self_signed_leaf)
    real = alerts_routes.refuse_if_superseded

    def then_delete_group(*args, **kwargs):
        real(*args, **kwargs)
        _delete_in_another_process(db, "DELETE FROM alert_groups WHERE id = ?", group_id)

    monkeypatch.setattr(alerts_routes, "refuse_if_superseded", then_delete_group)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(f"/api/alert-groups/{group_id}/certs/{cur}")
    assert (r.status_code, r.json()) == (404, {"error": "group not found"})
    from cert_watch.database.connection import _connect

    with _connect(db) as conn:
        assert conn.execute("SELECT * FROM alert_group_certs").fetchall() == []


def test_assign_refuses_a_certificate_deleted_by_another_connection(tmp_path, self_signed_leaf):
    """Fable's surviving mutant S2: with the in-transaction existence check
    ignored, this wrote an orphan and reported success."""
    from cert_watch.database.connection import _connect

    db, _old, cur, group_id = _renewed(tmp_path, self_signed_leaf)
    _delete_in_another_process(db, "DELETE FROM certificates WHERE id = ?", cur)
    outcome = SqliteAlertGroupRepository(db).assign_cert(group_id, cur, require_existing=True)
    assert outcome == "certificate_not_found"
    with _connect(db) as conn:
        assert conn.execute("SELECT * FROM alert_group_certs").fetchall() == []


def _host_tagged_estate(tmp_path: Path, self_signed_leaf, *, port: int = 443):
    """Scope comes only from the HOST tag: the certificate itself is untagged.
    A second endpoint with the same host name on :8443 belongs to team-b."""
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    hosts = SqliteHostRepository(db)
    hosts.add(_HOST, 443, tags="team-a")
    hosts.add(_HOST, 8443, tags="team-b")
    old = seed_scanned(db, _HOST, port, parse_certificate(self_signed_leaf.der))
    new = seed_scanned(db, _HOST, port, parse_certificate(_make_cert(_HOST, days_valid=90).der))
    return db, old, new


def test_scope_from_the_host_tag_alone_reveals_the_current_certificate(tmp_path, self_signed_leaf):
    from tests.test_tag_scoped_access import _make_scoped_app, _scoped_client

    db, old, new = _host_tagged_estate(tmp_path, self_signed_leaf)
    app, groups = _make_scoped_app(db, tmp_path, scope_tag="team-a")
    with _scoped_client(app, groups) as client:
        _assert_conflict(client.put(f"/api/certificates/{old}/tags", json={"tags": "x"}), old, new)


def test_same_host_name_on_another_port_does_not_lend_its_scope(tmp_path, self_signed_leaf):
    """The :8443 successor is team-b; the team-a tag on host :443 must not
    make it visible (the join is on host name AND port)."""
    from tests.test_tag_scoped_access import _make_scoped_app, _scoped_client

    db, old, _new = _host_tagged_estate(tmp_path, self_signed_leaf, port=8443)
    app, groups = _make_scoped_app(db, tmp_path, scope_tag="team-a")
    with _scoped_client(app, groups) as client:
        unknown = _answers(client, "00000000-0000-0000-0000-000000000000")
        superseded = _answers(client, old)
    assert superseded == unknown


def test_a_renewal_whose_successor_was_deleted_is_an_ordinary_not_found(
    tmp_path, reload_app, self_signed_leaf
):
    """A was renewed to B, then an operator deleted B. The lineage from A
    dead-ends in a deleted row, so A is not "renewed to" anything current."""
    from cert_watch.database import delete_certificate_cascade

    db, a, b, _ = _renewed(tmp_path, self_signed_leaf)
    assert delete_certificate_cascade(db, b)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.put(f"/api/certificates/{a}/tags", json={"tags": "x"})
    assert (r.status_code, r.json()) == (404, {"error": "not found"})


def test_a_stale_row_outside_the_callers_scope_answers_like_an_unknown_id(tmp_path):
    """Composed with #112's authorize-before-lookup: a caller who can see the
    current certificate C, but not the stale row A they addressed, learns
    nothing about A -- not even that it was renewed to C."""
    from tests.test_tag_scoped_access import _make_scoped_app, _scoped_client

    db = tmp_path / "cert-watch.sqlite3"
    a, _b, _c = _coexisting_lineage(db)  # A is team-old, C is team-new
    app, groups = _make_scoped_app(db, tmp_path, scope_tag="team-new")
    with _scoped_client(app, groups) as client:
        unknown = _answers(client, "00000000-0000-0000-0000-000000000000")
        stale = _answers(client, a)
    assert stale == unknown
    assert SqliteCertificateRepository(db).get_tags(a) == "team-old"


# -- rounds 5-6: authorization from rows; navigation hint from anchored events

_OTHER = "other-endpoint.example.test"


def _event(db: Path, event_type: str, payload: dict) -> None:
    import json

    from cert_watch.database.connection import _connect

    with _connect(db) as conn:
        conn.execute(
            "INSERT INTO event_log (event_type, timestamp, source, payload, created_at) "
            "VALUES (?, '2026-09-01T00:00:00+00:00', 'scan', ?, '2026-09-01T00:00:00+00:00')",
            (event_type, json.dumps(payload)),
        )
        conn.commit()


def _issued(db: Path, cert_id: str, hostname: str, port) -> None:
    """The id's own issuance event -- the only thing that anchors its endpoint."""
    _event(db, "cert_added", {"cert_id": cert_id, "hostname": hostname, "port": port})


def _renewal_event(db: Path, replaced: str, cert_id: str, hostname: str, port) -> None:
    payload = {"cert_id": cert_id, "replaced_cert_id": replaced}
    if hostname is not None:
        payload.update(hostname=hostname, port=port)
    _event(db, "cert_renewed", payload)


def _cert_at(db: Path, hostname: str, port: int, tags: str = "", replaces: str | None = None):
    from tests._helpers import seed_certificate

    cert_id = seed_certificate(
        db,
        parse_certificate(_make_cert(hostname, days_valid=90).der),
        hostname=hostname,
        port=port,
        source="scanned",
        replaces_cert_id=replaces,
    )
    if tags:
        SqliteCertificateRepository(db).set_tags(cert_id, tags)
    return cert_id


def _lineage(db: Path, cert_id: str):
    from cert_watch.database.cert_lineage import row_lineage
    from cert_watch.database.connection import _connect

    return row_lineage(_connect(db), cert_id)


def _hint(db: Path, cert_id: str) -> str | None:
    from cert_watch.database.cert_lineage import navigation_hint
    from cert_watch.database.connection import _connect

    return navigation_hint(_connect(db), cert_id)


def _fresh(tmp_path: Path) -> Path:
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    return db


_GONE = "11111111-1111-4111-8111-111111111111"


def test_an_event_hop_to_another_endpoint_answers_like_an_unknown_id(tmp_path):
    """Round 5 probe: an event says gone id A (issued at renewed:443) was
    renewed to X at other-endpoint:8443 (team-new). No hint; a team-new
    caller gets exactly the unknown-id answers."""
    from tests.test_tag_scoped_access import _make_scoped_app, _scoped_client

    db = _fresh(tmp_path)
    SqliteHostRepository(db).add(_HOST, 443, tags="team-old")
    SqliteHostRepository(db).add(_OTHER, 8443, tags="team-new")
    unrelated = _cert_at(db, _OTHER, 8443, tags="team-new")
    _issued(db, _GONE, _HOST, 443)
    _renewal_event(db, _GONE, unrelated, _HOST, 443)
    assert _hint(db, _GONE) is None
    app, groups = _make_scoped_app(db, tmp_path, scope_tag="team-new")
    with _scoped_client(app, groups) as client:
        unknown = _answers(client, "00000000-0000-0000-0000-000000000000")
        forged = _answers(client, _GONE)
    assert forged == unknown


def test_a_contradictory_renewal_event_cannot_reanchor_a_deleted_id(tmp_path, reload_app):
    """Round 6 HIGH 1 (Sol): the deleted id's own cert_added puts it at
    old:443; a later cert_renewed claims it moved to other:8443. The claim
    is checked against the anchor, not trusted as one: no redirect from the
    page, and the same answer as an unknown id from the API."""
    from tests.test_tag_scoped_access import _make_scoped_app, _scoped_client

    db = _fresh(tmp_path)
    SqliteHostRepository(db).add(_HOST, 443, tags="team-old")
    SqliteHostRepository(db).add(_OTHER, 8443, tags="team-new")
    target = _cert_at(db, _OTHER, 8443, tags="team-new")
    _issued(db, _GONE, _HOST, 443)
    _renewal_event(db, _GONE, target, _OTHER, 8443)
    assert _hint(db, _GONE) is None
    app, groups = _make_scoped_app(db, tmp_path, scope_tag="team-new")
    with _scoped_client(app, groups) as client:
        unknown = _answers(client, "00000000-0000-0000-0000-000000000000")
        forged = _answers(client, _GONE)
        page = client.get(f"/certificates/{_GONE}", follow_redirects=False)
    assert forged == unknown
    assert page.headers["location"] == "/?error=certificate+not+found"


def test_contradictory_issuance_events_anchor_nothing(tmp_path):
    db = _fresh(tmp_path)
    target = _cert_at(db, _HOST, 443)
    _issued(db, _GONE, _HOST, 443)
    _event(db, "cert_renewed", {"cert_id": _GONE, "hostname": _OTHER, "port": 8443})
    _renewal_event(db, _GONE, target, _HOST, 443)
    assert _hint(db, _GONE) is None


def test_ambiguous_row_lineage_refuses_the_write_for_everyone(tmp_path, reload_app):
    """Round 6 HIGH 2 (Sol): stale A (team-old) with TWO successor rows
    (team-new). The lineage is invalid, so the write is refused -- the old
    team gets the unknown-id answer and cannot change the host owner or
    delete A; an admin gets "not found" rather than a delete."""
    from tests.test_tag_scoped_access import _make_scoped_app, _scoped_client

    db = _fresh(tmp_path)
    SqliteHostRepository(db).add(_HOST, 443)
    stale = _cert_at(db, _HOST, 443, tags="team-old")
    first = _cert_at(db, _HOST, 443, tags="team-new", replaces=stale)
    second = _cert_at(db, _HOST, 443, tags="team-new", replaces=stale)
    assert _lineage(db, stale).kind == "invalid"
    app, groups = _make_scoped_app(db, tmp_path, scope_tag="team-old")
    with _scoped_client(app, groups) as client:
        unknown = _answers(client, "00000000-0000-0000-0000-000000000000")
        refused = _answers(client, stale)
    assert refused == unknown
    [host] = SqliteHostRepository(db).list_all()
    assert host.owner_name == ""
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.delete(f"/api/certificates/{stale}")
    assert (r.status_code, r.json()) == (404, {"error": "certificate not found"})
    certs = SqliteCertificateRepository(db)
    assert all(certs.get_by_id(c) is not None for c in (stale, first, second))


def test_a_row_cycle_refuses_the_write(tmp_path, reload_app):
    """Round 6 HIGH 2 (Sol): A and B name each other; deleting A went ahead."""
    from cert_watch.database.connection import _connect

    db = _fresh(tmp_path)
    SqliteHostRepository(db).add(_HOST, 443)
    a, b = _cert_at(db, _HOST, 443), _cert_at(db, _HOST, 443)
    with _connect(db) as conn:
        conn.execute("UPDATE certificates SET replaces_cert_id = ? WHERE id = ?", (a, b))
        conn.execute("UPDATE certificates SET replaces_cert_id = ? WHERE id = ?", (b, a))
        conn.commit()
    assert _lineage(db, a).kind == "invalid"
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.delete(f"/api/certificates/{a}")
    assert r.status_code == 404
    assert SqliteCertificateRepository(db).get_by_id(a) is not None


def test_a_row_chain_that_changes_endpoint_refuses_the_write(tmp_path):
    db = _fresh(tmp_path)
    stale = _cert_at(db, _HOST, 443)
    _cert_at(db, _OTHER, 443, replaces=stale)
    assert _lineage(db, stale).kind == "invalid"


def test_events_never_authorize_or_refuse_a_write(tmp_path):
    """An event claiming the (existing) row was renewed doesn't make it
    superseded; only rows do."""
    db = _fresh(tmp_path)
    stale = _cert_at(db, _HOST, 443)
    elsewhere = _cert_at(db, _HOST, 443)
    _renewal_event(db, stale, elsewhere, _HOST, 443)
    assert _lineage(db, stale).kind == "current"
    assert _lineage(db, elsewhere).kind == "current"


def test_a_multi_hop_hint_that_changes_endpoint_resolves_nothing(tmp_path):
    db = _fresh(tmp_path)
    a, b = "a" * 8 + "-0000-4000-8000-000000000001", "b" * 8 + "-0000-4000-8000-000000000002"
    same = _cert_at(db, _HOST, 443)
    moved = _cert_at(db, _OTHER, 443)
    _issued(db, a, _HOST, 443)
    _renewal_event(db, a, b, _HOST, 443)
    _renewal_event(db, b, same, _HOST, 443)
    assert _hint(db, a) == same  # control: an anchored, consistent chain resolves
    c, d = "c" * 8 + "-0000-4000-8000-000000000003", "d" * 8 + "-0000-4000-8000-000000000004"
    _issued(db, c, _HOST, 443)
    _renewal_event(db, c, d, _HOST, 443)
    _renewal_event(db, d, moved, _OTHER, 443)
    assert _hint(db, c) is None


def test_an_ambiguous_hint_resolves_nothing(tmp_path):
    db = _fresh(tmp_path)
    first, second = _cert_at(db, _HOST, 443), _cert_at(db, _HOST, 443)
    _issued(db, _GONE, _HOST, 443)
    _renewal_event(db, _GONE, first, _HOST, 443)
    _renewal_event(db, _GONE, second, _HOST, 443)
    assert _hint(db, _GONE) is None


def test_a_hint_hop_without_an_endpoint_resolves_nothing(tmp_path):
    db = _fresh(tmp_path)
    target = _cert_at(db, _HOST, 443)
    middle = "9" * 8 + "-0000-4000-8000-000000000007"
    _issued(db, _GONE, _HOST, 443)
    _renewal_event(db, _GONE, middle, None, None)
    _renewal_event(db, middle, target, _HOST, 443)
    assert _hint(db, _GONE) is None


def test_the_renewal_event_anchors_once_the_issuance_event_has_aged_out(tmp_path):
    """Round 7 (Sol, Fable): the issuance event ages out of the default 30-day
    retention long before a 90-day certificate is renewed; the fresh renewal
    event naming the id as replaced anchors it on its own."""
    db = _fresh(tmp_path)
    target = _cert_at(db, _HOST, 443)
    _renewal_event(db, _GONE, target, _HOST, 443)
    assert _hint(db, _GONE) == target


def test_with_no_event_left_there_is_no_anchor(tmp_path):
    """A successor row alone can't anchor the id: nothing independent says
    where the id was."""
    db = _fresh(tmp_path)
    target = _cert_at(db, _HOST, 443, replaces=_GONE)
    assert target
    assert _hint(db, _GONE) is None


@pytest.mark.parametrize("successor_port", [443, 8443])
def test_contradictory_issuance_anchors_give_no_hint_in_either_order(tmp_path, successor_port):
    """Fable's probe_anchor_tie: two issuance events for the id disagree on
    the port. Whichever port the successor is on, there is no hint."""
    db = _fresh(tmp_path)
    successor = _cert_at(db, _HOST, successor_port, replaces=_GONE)
    assert successor
    for port in (443, 8443):
        _issued(db, _GONE, _HOST, port)
    assert _hint(db, _GONE) is None


@pytest.mark.parametrize("successor_port", [443, 8443])
def test_issuance_and_renewal_anchors_that_disagree_give_no_hint(tmp_path, successor_port):
    db = _fresh(tmp_path)
    successor = _cert_at(db, _HOST, successor_port, replaces=_GONE)
    _issued(db, _GONE, _HOST, 443)
    _renewal_event(db, _GONE, successor, _HOST, 8443)
    assert _hint(db, _GONE) is None


def test_pre_canonical_host_spellings_in_events_still_anchor(tmp_path):
    """Events written before 1.0.3's canonical host names spell the host
    differently (case, trailing dot); they bind to the canonical rows."""
    db = _fresh(tmp_path)
    target = _cert_at(db, _HOST, 443)
    _issued(db, _GONE, _HOST.upper() + ".", 443)
    _renewal_event(db, _GONE, target, _HOST.upper() + ".", "443")
    assert _hint(db, _GONE) == target


def test_a_hint_cycle_resolves_nothing(tmp_path):
    """gone -> X -> gone: X exists, but a loop names no current certificate."""
    db = _fresh(tmp_path)
    x = _cert_at(db, _HOST, 443)
    _issued(db, _GONE, _HOST, 443)
    _renewal_event(db, _GONE, x, _HOST, 443)
    _renewal_event(db, x, _GONE, _HOST, 443)
    assert _hint(db, _GONE) is None


def test_a_renewal_event_without_a_successor_id_resolves_nothing(tmp_path):
    db = _fresh(tmp_path)
    target = _cert_at(db, _HOST, 443)
    _issued(db, _GONE, _HOST, 443)
    _event(db, "cert_renewed", {"replaced_cert_id": _GONE, "hostname": _HOST, "port": 443})
    _renewal_event(db, _GONE, target, _HOST, 443)
    assert _hint(db, _GONE) is None


def test_an_unanchored_chain_to_an_endpointless_certificate_resolves_nothing(tmp_path):
    """No issuance event and no endpoint anywhere: nothing to bind to, even
    though every hop "agrees" (on having no endpoint)."""
    from tests._helpers import seed_certificate

    db = _fresh(tmp_path)
    uploaded = seed_certificate(
        db,
        parse_certificate(_make_cert("uploaded.example.test").der),
        hostname="",
        port=0,
        source="uploaded",
    )
    _renewal_event(db, _GONE, uploaded, None, None)
    assert _hint(db, _GONE) is None


def test_no_hint_is_given_for_an_id_whose_row_exists(tmp_path):
    """The hint is only for missing ids; an existing stale row is decided by
    row lineage alone."""
    db = _fresh(tmp_path)
    stale = _cert_at(db, _HOST, 443)
    successor = _cert_at(db, _HOST, 443, replaces=stale)
    _issued(db, stale, _HOST, 443)
    _renewal_event(db, stale, successor, _HOST, 443)
    assert _hint(db, stale) is None
    assert _lineage(db, stale).kind == "superseded"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (443, 443),
        ("443", 443),
        (443.9, None),
        (443.0, None),
        ("443.0", None),
        (True, None),
        (False, None),
        (" 443", None),
        ("-443", None),
        (0, None),
        (70000, None),
        (None, None),
    ],
)
def test_ports_are_parsed_strictly(value, expected):
    from cert_watch.database.cert_lineage import strict_port

    assert strict_port(value) == expected


def test_a_non_integral_event_port_anchors_nothing(tmp_path):
    """Round 6 LOW (Sol): 443.9 used to truncate to 443 and bind."""
    db = _fresh(tmp_path)
    target = _cert_at(db, _HOST, 443)
    _issued(db, _GONE, _HOST, 443.9)
    _renewal_event(db, _GONE, target, _HOST, 443.9)
    assert _hint(db, _GONE) is None


def test_a_malformed_event_payload_breaks_no_mutation_or_link(
    tmp_path, reload_app, self_signed_leaf
):
    """Sol's round-5 probe: one event row with payload '{' made json_extract
    raise, failing every certificate tag/delete/owner mutation (500)."""
    from cert_watch.database.connection import _connect

    db, old, new, _ = _renewed(tmp_path, self_signed_leaf)
    with _connect(db) as conn:
        conn.execute(
            "INSERT INTO event_log (event_type, timestamp, source, payload, created_at) "
            "VALUES ('cert_renewed', '2026-09-01T00:00:00+00:00', 'scan', '{', "
            "'2026-09-01T00:00:00+00:00')"
        )
        conn.commit()
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        ok = client.put(f"/api/certificates/{new}/tags", json={"tags": "team-a,more"})
        refused = client.put(f"/api/certificates/{old}/tags", json={"tags": "x"})
        link = client.get(f"/certificates/{old}", follow_redirects=False)
        # An id no row knows reaches the stale-link event lookup itself.
        unknown = client.get(
            "/certificates/00000000-0000-0000-0000-000000000000", follow_redirects=False
        )
    assert ok.status_code == 200, ok.text
    _assert_conflict(refused, old, new)
    assert link.status_code == 303
    assert (unknown.status_code, unknown.headers["location"]) == (
        303,
        "/?error=certificate+not+found",
    )


def test_unassign_refuses_a_group_deleted_by_another_process_after_the_precheck(
    tmp_path, monkeypatch, reload_app, self_signed_leaf
):
    """Mirror of the assign case (Fable round 5): the group is re-checked in
    the unassign's own transaction, so a concurrent group delete answers
    "group not found", not "not assigned"."""
    import importlib

    alerts_routes = importlib.import_module("cert_watch.routes.api.alerts")
    db, _old, cur, group_id = _renewed(tmp_path, self_signed_leaf)
    real_repo = alerts_routes.SqliteAlertGroupRepository

    class DeletesGroupFirst(real_repo):  # type: ignore[misc, valid-type]
        def unassign_cert(self, *args, **kwargs):
            _delete_in_another_process(db, "DELETE FROM alert_groups WHERE id = ?", group_id)
            return super().unassign_cert(*args, **kwargs)

    monkeypatch.setattr(alerts_routes, "SqliteAlertGroupRepository", DeletesGroupFirst)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.delete(f"/api/alert-groups/{group_id}/certs/{cur}")
    assert (r.status_code, r.json()) == (404, {"error": "group not found"})


# -- round 7: link after retention; unassign independent of events ------


def test_a_renewal_webhook_link_resolves_right_after_renewal(tmp_path, reload_app):
    """Sol's sequence: the certificate is 31 days old, so the default 30-day
    purge has already removed its issuance event when the renewal webhook
    emits its cert_watch_url. The certificate is then renewed; the link must
    open the new certificate straight away."""
    from cert_watch.database.connection import _connect
    from cert_watch.events import purge_old_events

    db = _fresh(tmp_path)
    SqliteHostRepository(db).add(_HOST, 443)
    old = seed_scanned(db, _HOST, 443, parse_certificate(_make_cert(_HOST).der))
    with _connect(db) as conn:
        conn.execute(
            "UPDATE event_log SET timestamp = datetime('now', '-31 days'), "
            "created_at = datetime('now', '-31 days')"
        )
        conn.commit()
    purge_old_events(db, 30)
    new = _renew(db)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        page = client.get(f"/certificates/{old}", follow_redirects=False)
        tags = client.put(f"/api/certificates/{old}/tags", json={"tags": "x"})
    assert page.headers["location"] == f"/certificates/{new}?superseded=1"
    _assert_conflict(tags, old, new)


@pytest.mark.parametrize("events", ["retained", "purged"])
def test_a_dangling_assignment_is_removed_whether_or_not_events_remain(
    tmp_path, reload_app, events
):
    """Round 7 (Sol): with renewal events retained the unassign of a dangling
    assignment on a missing id was refused (409, nothing removed); once the
    events were purged the same request removed it. Rows decide: it is
    removed both times, and the answer may only mention the renewal."""
    from cert_watch.database.connection import _connect

    db = _fresh(tmp_path)
    SqliteHostRepository(db).add(_HOST, 443)
    current = _cert_at(db, _HOST, 443, replaces=_GONE)
    groups = SqliteAlertGroupRepository(db)
    group_id = groups.create(name="G", recipients=["g@example.test"], match_tags=[])
    groups.assign_cert(group_id, _GONE)  # dangling: no row has this id
    if events == "retained":
        _renewal_event(db, _GONE, current, _HOST, 443)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.delete(f"/api/alert-groups/{group_id}/certs/{_GONE}")
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "unassigned"
    assert r.json().get("current_cert_id") == (current if events == "retained" else None)
    with _connect(db) as conn:
        assert conn.execute("SELECT * FROM alert_group_certs").fetchall() == []


def test_a_later_hop_recorded_at_another_endpoint_breaks_the_chain(tmp_path):
    """The head is on the anchored endpoint, but the step that reached it was
    recorded elsewhere: the chain is not trusted."""
    db = _fresh(tmp_path)
    middle = "7" * 8 + "-0000-4000-8000-000000000009"
    head = _cert_at(db, _HOST, 443)
    _issued(db, _GONE, _HOST, 443)
    _renewal_event(db, _GONE, middle, _HOST, 443)
    _renewal_event(db, middle, head, _OTHER, 443)
    assert _hint(db, _GONE) is None
