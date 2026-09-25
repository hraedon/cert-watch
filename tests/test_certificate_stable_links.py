"""#113 item 3: certificate detail links survive rescans and renewals.

Every scan used to rewrite the leaf row under a fresh id, so a bookmarked,
shared or renewal-webhook-linked ``/certificates/<id>`` died on the next scan and
landed on ``/?error=certificate not found``.

- an unchanged rescan keeps the certificate's id;
- an id from before a renewal redirects to the endpoint's current
  certificate;
- a host id is a stable address for the endpoint: it opens the current
  certificate once one exists;
- none of this crosses tag scope.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cert_watch.certificate_model import parse_certificate
from cert_watch.database import SqliteHostRepository, init_schema
from tests._helpers import seed_scanned
from tests.conftest import _make_cert

_HOST = "leaf.example.com"
_NOT_FOUND = "/?error=certificate+not+found"


@pytest.fixture(autouse=True)
def _no_startup_scan(monkeypatch):
    """Keep the lifespan's real scheduler from scanning the registered hosts
    while a test runs (#115 review: a startup scan raced such assertions)."""
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.start", lambda self: None)
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.stop", lambda self: None)


def _db(tmp_path: Path) -> Path:
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    return db


def _leaf(der: bytes):
    return parse_certificate(der)


def test_unchanged_rescan_keeps_the_certificate_id(tmp_path, reload_app, self_signed_leaf):
    db = _db(tmp_path)
    SqliteHostRepository(db).add(_HOST, 443)
    first = seed_scanned(db, _HOST, 443, _leaf(self_signed_leaf.der))
    second = seed_scanned(db, _HOST, 443, _leaf(self_signed_leaf.der))
    assert second == first

    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get(f"/certificates/{first}", follow_redirects=False)
    assert r.status_code == 200


def test_unchanged_rescan_does_not_mark_itself_superseded(tmp_path, self_signed_leaf):
    """Keeping the id must not make the row its own successor: expiry and
    renewal rules skip any leaf that some row ``replaces``."""
    from cert_watch.database.connection import _connect

    db = _db(tmp_path)
    first = seed_scanned(db, _HOST, 443, _leaf(self_signed_leaf.der))
    seed_scanned(db, _HOST, 443, _leaf(self_signed_leaf.der))
    with _connect(db) as conn:
        row = conn.execute(
            "SELECT replaces_cert_id FROM certificates WHERE id = ?", (first,)
        ).fetchone()
    assert row["replaces_cert_id"] != first


def test_pre_renewal_link_redirects_to_current_certificate(tmp_path, reload_app, self_signed_leaf):
    db = _db(tmp_path)
    SqliteHostRepository(db).add(_HOST, 443)
    old = seed_scanned(db, _HOST, 443, _leaf(self_signed_leaf.der))
    renewed = _make_cert(_HOST, days_valid=90, san_dns=[_HOST])
    new = seed_scanned(db, _HOST, 443, _leaf(renewed.der))
    assert new != old

    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get(f"/certificates/{old}", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == f"/certificates/{new}?superseded=1"
        page = client.get(r.headers["location"])
    assert page.status_code == 200
    assert "earlier certificate" in page.text


def test_link_from_two_renewals_ago_resolves_through_the_event_log(
    tmp_path, reload_app, self_signed_leaf
):
    """The successor row of a twice-renewed id is gone too; the lifecycle
    event recorded when that id was issued still names its endpoint."""
    db = _db(tmp_path)
    SqliteHostRepository(db).add(_HOST, 443)
    oldest = seed_scanned(db, _HOST, 443, _leaf(self_signed_leaf.der))
    seed_scanned(db, _HOST, 443, _leaf(_make_cert(_HOST, days_valid=90).der))
    current = seed_scanned(db, _HOST, 443, _leaf(_make_cert(_HOST, days_valid=80).der))

    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get(f"/certificates/{oldest}", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == f"/certificates/{current}?superseded=1"


def _alert_on(db: Path, cert_id: str, port: int, fingerprint: str) -> None:
    """An expiry alert as the rule writes it: the dedupe key names host:port."""
    from cert_watch.alerting.keys import certificate_alert_key
    from cert_watch.database import Alert, SqliteAlertRepository

    SqliteAlertRepository(db).create(
        Alert(
            cert_id=cert_id,
            alert_type="expiry_warning",
            status="sent",
            message="expiring",
            threshold_days=7,
            hostname=_HOST,
            dedupe_key=certificate_alert_key(
                "expiry",
                cert_id=cert_id,
                fingerprint=fingerprint,
                hostname=_HOST,
                port=port,
                suffix=("expiry_warning", "7"),
            ),
        )
    )


def test_an_alert_alone_no_longer_resolves_a_stale_link(tmp_path, reload_app, self_signed_leaf):
    """#115 review round 6: stale links follow renewal lineage anchored on
    the id's own issuance event -- the one resolver the mutation routes also
    use. An alert records where a certificate was, not what replaced it, so
    once the events have aged out the old id is "not found" rather than
    guessed from the endpoint's current certificate."""
    from cert_watch.database.connection import _connect

    db = _db(tmp_path)
    hosts = SqliteHostRepository(db)
    hosts.add(_HOST, 443)
    hosts.add(_HOST, 8443)
    oldest_leaf = _leaf(self_signed_leaf.der)
    oldest = seed_scanned(db, _HOST, 443, oldest_leaf)
    seed_scanned(db, _HOST, 8443, _leaf(_make_cert(_HOST, days_valid=120).der))
    _alert_on(db, oldest, 443, oldest_leaf.fingerprint_sha256)
    # Renewed twice: the successor row naming the old id is gone too.
    seed_scanned(db, _HOST, 443, _leaf(_make_cert(_HOST, days_valid=90).der))
    current = seed_scanned(db, _HOST, 443, _leaf(_make_cert(_HOST, days_valid=80).der))
    with _connect(db) as conn:
        conn.execute("DELETE FROM event_log")  # retention purged them
        conn.commit()

    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get(f"/certificates/{oldest}", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == _NOT_FOUND
    assert current  # the endpoint still has a current certificate


def test_alert_fallback_never_picks_another_ports_certificate(
    tmp_path, reload_app, self_signed_leaf
):
    """#115 review finding 3. The :443 certificate that fired an alert is
    renewed, its events expire, and the current :443 certificate is deleted
    while :8443 remains. The old id must not open the :8443 certificate just
    because it is now the only leaf with that host name."""
    from cert_watch.database import delete_certificate_cascade
    from cert_watch.database.connection import _connect

    db = _db(tmp_path)
    hosts = SqliteHostRepository(db)
    hosts.add(_HOST, 443)
    hosts.add(_HOST, 8443)
    old_leaf = _leaf(self_signed_leaf.der)
    old = seed_scanned(db, _HOST, 443, old_leaf)
    _alert_on(db, old, 443, old_leaf.fingerprint_sha256)
    seed_scanned(db, _HOST, 443, _leaf(_make_cert(_HOST, days_valid=80).der))
    current_443 = seed_scanned(db, _HOST, 443, _leaf(_make_cert(_HOST, days_valid=70).der))
    seed_scanned(db, _HOST, 8443, _leaf(_make_cert(_HOST, days_valid=120).der))
    with _connect(db) as conn:
        conn.execute("DELETE FROM event_log")
        conn.commit()
    assert delete_certificate_cascade(db, current_443)

    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get(f"/certificates/{old}", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == _NOT_FOUND


def test_host_id_is_a_stable_address_for_the_endpoint(tmp_path, reload_app, self_signed_leaf):
    db = _db(tmp_path)
    host_id = SqliteHostRepository(db).add(_HOST, 443)
    cert_id = seed_scanned(db, _HOST, 443, _leaf(self_signed_leaf.der))

    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get(f"/certificates/{host_id}", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == f"/certificates/{cert_id}"


def test_unknown_id_still_reports_not_found(tmp_path, reload_app):
    _db(tmp_path)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/certificates/00000000-0000-0000-0000-000000000000", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == _NOT_FOUND


def test_stale_link_does_not_reveal_an_out_of_scope_certificate(tmp_path, self_signed_leaf):
    from tests.test_tag_scoped_access import _make_scoped_app, _scoped_client

    db = _db(tmp_path)
    SqliteHostRepository(db).add(_HOST, 443, tags="team-b")
    old = seed_scanned(db, _HOST, 443, _leaf(self_signed_leaf.der))
    seed_scanned(db, _HOST, 443, _leaf(_make_cert(_HOST, days_valid=90).der))

    app, groups = _make_scoped_app(db, tmp_path, scope_tag="team-a")
    with _scoped_client(app, groups) as client:
        r = client.get(f"/certificates/{old}", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == _NOT_FOUND


def test_stale_link_resolves_for_an_in_scope_user(tmp_path, self_signed_leaf):
    from tests.test_tag_scoped_access import _make_scoped_app, _scoped_client

    db = _db(tmp_path)
    SqliteHostRepository(db).add(_HOST, 443, tags="team-a")
    old = seed_scanned(db, _HOST, 443, _leaf(self_signed_leaf.der))
    new = seed_scanned(db, _HOST, 443, _leaf(_make_cert(_HOST, days_valid=90).der))

    app, groups = _make_scoped_app(db, tmp_path, scope_tag="team-a")
    with _scoped_client(app, groups) as client:
        r = client.get(f"/certificates/{old}?endpoint_saved=1", follow_redirects=False)
    assert r.status_code == 303
    # Query parameters (flash messages) travel with the redirect.
    assert r.headers["location"] == f"/certificates/{new}?endpoint_saved=1&superseded=1"
