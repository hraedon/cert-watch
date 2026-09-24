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


def test_out_of_scope_caller_learns_nothing_about_the_successor(tmp_path, self_signed_leaf):
    from cert_watch.auth.rbac import AuthContext
    from cert_watch.services.certificate_identity import (
        CertificateSupersededError,
        ensure_not_superseded,
    )

    db, old, _new, _ = _renewed(tmp_path, self_signed_leaf)  # current is team-a
    team_b = AuthContext(
        username="b",
        roles=["viewer"],
        tier="viewer",
        scope_tag="team-b",
        tag_tiers={"team-b": "operator"},
    )
    with get_write_lock(), pytest.raises(CertificateSupersededError) as info:
        ensure_not_superseded(db, old, auth=team_b)
    assert info.value.current_id is None


def test_unknown_and_current_ids_pass_through(tmp_path, self_signed_leaf):
    from cert_watch.auth.rbac import AuthContext
    from cert_watch.services.certificate_identity import ensure_not_superseded

    db, _old, new, _ = _renewed(tmp_path, self_signed_leaf)
    with get_write_lock():
        ensure_not_superseded(db, new, auth=AuthContext.system())
        ensure_not_superseded(db, "00000000-0000-0000-0000-000000000000", auth=AuthContext.system())
