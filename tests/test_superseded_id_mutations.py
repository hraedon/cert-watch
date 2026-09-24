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
    target = resolve_host_ownership_target(db, old)
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
    target = resolve_host_ownership_target(db, old)
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
