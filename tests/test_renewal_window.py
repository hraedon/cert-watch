"""Tests for the ACME renewal-window alert (Plan 027)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta


def _insert_cert(db, *, cid, days_valid, hostname="h.example.com", port=443, replaces=None):
    from cert_watch.database import init_schema
    from cert_watch.database.queries import _connect, _iso

    init_schema(db)
    now = datetime.now(UTC)
    with _connect(db) as conn:
        conn.execute(
            "INSERT INTO certificates (id, subject, issuer, not_before, not_after, "
            "san_dns_names, fingerprint_sha256, raw_der, source, hostname, port, "
            "is_leaf, chain_valid, replaces_cert_id, tags, created_at, updated_at) "
            "VALUES (?,?,?,?,?,'[]',?,?,?,?,?,1,1,?,?,?,?)",
            (
                cid, f"CN={cid}", "CN=Test CA",
                _iso(now - timedelta(days=10)),
                _iso(now + timedelta(days=days_valid)),
                cid + "-fp", b"\x00", "scanned", hostname, port,
                replaces, "", _iso(now), _iso(now),
            ),
        )
        conn.commit()


def _seed(db):
    _insert_cert(db, cid="stalled", days_valid=20)  # in window, no successor -> alert
    _insert_cert(db, cid="renewed-old", days_valid=15, hostname="r.example.com")
    _insert_cert(  # successor of renewed-old -> renewal worked, no alert
        db, cid="renewed-new", days_valid=300, hostname="r.example.com",
        replaces="renewed-old",
    )
    _insert_cert(db, cid="far", days_valid=100)  # outside window
    _insert_cert(db, cid="expired", days_valid=-5)  # expired -> expiry owns it


def test_only_stalled_cert_alerts(tmp_path):
    from cert_watch.alerts import evaluate_renewal_window
    from cert_watch.database import SqliteAlertRepository

    db = str(tmp_path / "t.sqlite3")
    _seed(db)
    repo = SqliteAlertRepository(db)
    created = evaluate_renewal_window(db, repo, 30)
    assert {a.cert_id for a in created} == {"stalled"}
    assert created[0].alert_type == "renewal_stalled"


def test_idempotent(tmp_path):
    from cert_watch.alerts import evaluate_renewal_window
    from cert_watch.database import SqliteAlertRepository

    db = str(tmp_path / "t.sqlite3")
    _seed(db)
    repo = SqliteAlertRepository(db)
    assert len(evaluate_renewal_window(db, repo, 30)) == 1
    assert evaluate_renewal_window(db, repo, 30) == []  # no duplicate


def test_window_zero_disables(tmp_path):
    from cert_watch.alerts import evaluate_renewal_window
    from cert_watch.database import SqliteAlertRepository

    db = str(tmp_path / "t.sqlite3")
    _seed(db)
    repo = SqliteAlertRepository(db)
    assert evaluate_renewal_window(db, repo, 0) == []
