"""The metadata / ownership services enforce tag scope themselves (plan 057 W6).

Route adapters no longer call ``scope_write_denied`` / ``scope_new_tags_denied``
for notes, tags or ownership: the service takes the acting AuthContext and
checks scope inside the write lock, before validating or persisting anything.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from cert_watch.audit import list_audit
from cert_watch.auth.rbac import AuthContext
from cert_watch.auth.scope import ScopeDeniedError
from cert_watch.certificate_model import Certificate
from cert_watch.database import SqliteCertificateRepository, SqliteHostRepository, init_schema
from cert_watch.services.host_ownership import (
    HostOwnershipUpdate,
    resolve_host_ownership_target,
    update_host_ownership,
)
from cert_watch.services.resource_metadata import (
    update_certificate_tags,
    update_host_notes,
    update_host_tags,
)

SCOPED_OPERATOR = AuthContext.from_tier(
    "otto", tier="viewer", scope_tag="A", tag_tiers={"A": "operator"}
)
SCOPED_VIEWER = AuthContext.from_tier("vera", tier="viewer", scope_tag="A")


@pytest.fixture
def estate(tmp_path: Path) -> dict[str, object]:
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    hosts = SqliteHostRepository(db)
    in_scope = hosts.add("a.example.test", tags="A")
    out_of_scope = hosts.add("b.example.test", tags="B")
    now = datetime.now(UTC)
    cert_b = SqliteCertificateRepository(
        db, source="scanned", hostname="b.example.test", port=443
    ).add(
        Certificate(
            subject="CN=b.example.test", issuer="CN=CA",
            not_before=now - timedelta(days=1), not_after=now + timedelta(days=30),
        )
    )
    return {"db": db, "in": in_scope, "out": out_of_scope, "cert_b": cert_b}


def _call(kind: str, db: Path, target: str, auth: AuthContext | None, value: object = "x"):
    kw = {"auth": auth, "actor": "t", "source_ip": None}
    if kind == "notes":
        return update_host_notes(db, target, value, **kw)
    if kind == "host_tags":
        return update_host_tags(db, target, value if value != "x" else "A", **kw)
    if kind == "cert_tags":
        return update_certificate_tags(db, target, value if value != "x" else "A", **kw)
    update = value if value != "x" else HostOwnershipUpdate(owner_name="Ops")
    return update_host_ownership(db, target, update, **kw)


@pytest.mark.parametrize("kind", ["notes", "host_tags", "ownership"])
def test_out_of_scope_host_is_refused_and_nothing_is_written(estate, kind):
    with pytest.raises(ScopeDeniedError, match="outside your team scope"):
        _call(kind, estate["db"], estate["out"], SCOPED_OPERATOR)
    stored = SqliteHostRepository(estate["db"]).get(estate["out"])
    assert (stored.notes, stored.tags, stored.owner_name) == ("", "B", "")
    assert list_audit(estate["db"]) == []


def test_out_of_scope_certificate_tags_are_refused(estate):
    with pytest.raises(ScopeDeniedError, match="outside your team scope"):
        _call("cert_tags", estate["db"], estate["cert_b"], SCOPED_OPERATOR)


@pytest.mark.parametrize("kind", ["notes", "host_tags", "ownership"])
def test_in_scope_host_is_written(estate, kind):
    _call(kind, estate["db"], estate["in"], SCOPED_OPERATOR)
    assert len(list_audit(estate["db"])) == 1


def test_read_only_tier_on_the_tag_is_refused(estate):
    with pytest.raises(ScopeDeniedError, match="read-only"):
        _call("notes", estate["db"], estate["in"], SCOPED_VIEWER)


@pytest.mark.parametrize("kind", ["host_tags", "cert_tags"])
def test_new_tags_outside_scope_are_refused(estate, kind):
    target = estate["in"]
    if kind == "cert_tags":  # a cert on the in-scope host
        now = datetime.now(UTC)
        target = SqliteCertificateRepository(
            estate["db"], source="scanned", hostname="a.example.test", port=443
        ).add(Certificate(
            subject="CN=a", issuer="CN=CA",
            not_before=now - timedelta(days=1), not_after=now + timedelta(days=30),
        ))
    with pytest.raises(ScopeDeniedError, match="tag 'B' is outside your team scope"):
        _call(kind, estate["db"], target, SCOPED_OPERATOR, value="A,B")


@pytest.mark.parametrize("kind", ["notes", "host_tags", "ownership"])
def test_deferred_input_is_not_evaluated_for_a_refused_caller(estate, kind):
    """A JSON adapter hands its body parser over; an out-of-scope caller is
    refused before the body is judged (the old route order: 403 before 400)."""
    def parser():
        raise AssertionError("parsed input from a caller outside the target's scope")

    with pytest.raises(ScopeDeniedError):
        _call(kind, estate["db"], estate["out"], SCOPED_OPERATOR, value=parser)


def test_no_auth_context_is_unrestricted(estate):
    _call("notes", estate["db"], estate["out"], None)
    assert SqliteHostRepository(estate["db"]).get(estate["out"]).notes == "x"


def test_ownership_through_a_certificate_is_scoped_by_its_effective_tags(estate):
    """A cert tagged A on an untagged-for-A host carries A in its effective
    tags, so ownership edited *through that certificate* is in scope."""
    db = estate["db"]
    SqliteCertificateRepository(db).set_tags(estate["cert_b"], "A")
    target = resolve_host_ownership_target(db, estate["cert_b"])
    update_host_ownership(
        db, target, HostOwnershipUpdate(owner_name="Ops"),
        auth=SCOPED_OPERATOR, actor="t", source_ip=None,
    )
    # ...but the same host by its own id is not.
    with pytest.raises(ScopeDeniedError):
        update_host_ownership(
            db, estate["out"], HostOwnershipUpdate(owner_name="Ops"),
            auth=SCOPED_OPERATOR, actor="t", source_ip=None,
        )


@pytest.mark.parametrize("kind", ["notes", "host_tags", "cert_tags", "ownership"])
def test_scope_is_checked_while_holding_the_write_lock(estate, kind, monkeypatch):
    import cert_watch.auth.scope as scope
    from cert_watch.database.connection import get_write_lock

    held: list[bool] = []
    real = scope._effective_tags

    def spy(*args, **kwargs):
        held.append(get_write_lock()._is_owned())
        return real(*args, **kwargs)

    monkeypatch.setattr(scope, "_effective_tags", spy)
    target = estate["cert_b"] if kind == "cert_tags" else estate["out"]
    with pytest.raises(ScopeDeniedError):
        _call(kind, estate["db"], target, SCOPED_OPERATOR)
    assert held == [True]
