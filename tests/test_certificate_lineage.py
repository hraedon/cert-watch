"""The renewal record stale links follow (migration 0042, #115 review round 9).

``certificate_lineage`` is written by the scan in the same transaction as
each renewal, and backfilled on upgrade from stored rows and retained
``cert_renewed`` events. Stale links read it instead of the event log, whose
retention and Settings -> Event stream choices used to break them.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path

import pytest

from cert_watch.certificate_model import parse_certificate
from cert_watch.database import SqliteHostRepository, init_schema
from cert_watch.database.connection import _connect
from tests._helpers import seed_scanned
from tests.conftest import _make_cert

_HOST = "lineage.example.test"
_OTHER = "elsewhere.example.test"


def _lineage_rows(db: Path) -> list[tuple]:
    with _connect(db) as conn:
        return [
            tuple(r)
            for r in conn.execute(
                "SELECT old_cert_id, new_cert_id, hostname, port FROM certificate_lineage "
                "ORDER BY old_cert_id"
            )
        ]


# -- written by the scan -------------------------------------------------


def test_a_renewal_writes_one_record_and_an_unchanged_rescan_none(tmp_path, self_signed_leaf):
    db = tmp_path / "c.sqlite3"
    init_schema(db)
    SqliteHostRepository(db).add(_HOST, 443)
    leaf = parse_certificate(self_signed_leaf.der)
    first = seed_scanned(db, _HOST, 443, leaf)
    assert _lineage_rows(db) == []
    assert seed_scanned(db, _HOST, 443, leaf) == first  # unchanged rescan
    assert _lineage_rows(db) == []
    renewed = seed_scanned(db, _HOST, 443, parse_certificate(_make_cert(_HOST, days_valid=90).der))
    assert _lineage_rows(db) == [(first, renewed, _HOST, 443)]


# -- backfill on upgrade -------------------------------------------------


def _db_at(db: Path, last_applied: str) -> None:
    """A database migrated only up to *last_applied*, as that release built it."""
    import cert_watch.migrations.registry  # noqa: F401
    from cert_watch.migrations.runner import get_migrations

    conn = sqlite3.connect(str(db))
    conn.row_factory = sqlite3.Row  # as the runner's connection has
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_version "
        "(id TEXT PRIMARY KEY, description TEXT NOT NULL, applied_at TEXT NOT NULL)"
    )
    for mid, desc, fn in get_migrations():
        if mid > last_applied:
            break
        conn.execute("BEGIN IMMEDIATE")
        fn(conn)
        conn.execute(
            "INSERT INTO schema_version VALUES (?, ?, '2026-09-01T00:00:00+00:00')",
            (mid, desc),
        )
        conn.commit()
    conn.close()


def _leaf(conn, cert_id: str, host: str, port: int, replaces: str | None) -> None:
    conn.execute(
        "INSERT INTO certificates (id, subject, issuer, not_before, not_after, "
        "san_dns_names, fingerprint_sha256, raw_der, source, hostname, port, is_leaf, "
        "replaces_cert_id, created_at, updated_at) VALUES (?, 'CN=x', 'CN=ca', "
        "'2026-08-01T00:00:00+00:00', '2026-11-01T00:00:00+00:00', '[]', ?, x'00', "
        "'scanned', ?, ?, 1, ?, '2026-09-01T00:00:00+00:00', '2026-09-01T00:00:00+00:00')",
        (cert_id, cert_id + "-fp", host, port, replaces),
    )


def _renewed_event(conn, old: str, new: str, host: str, port) -> None:
    conn.execute(
        "INSERT INTO event_log (event_type, timestamp, source, payload, created_at) "
        "VALUES ('cert_renewed', '2026-09-01T00:00:00+00:00', 'scan', ?, "
        "'2026-09-01T00:00:00+00:00')",
        (json.dumps({"cert_id": new, "replaced_cert_id": old, "hostname": host, "port": port}),),
    )


@pytest.mark.parametrize(
    ("release", "last_applied", "spelling"),
    [
        # 1.0.2 stored host names as typed; 0038 canonicalizes them first.
        ("1.0.2", "0037", _HOST.upper() + "."),
        ("1.0.3", "0041", _HOST),
    ],
)
def test_upgrade_backfills_from_rows_and_retained_events(
    tmp_path, caplog, release, last_applied, spelling
):
    from cert_watch.database.cert_lineage import navigation_hint
    from cert_watch.migrations.m0042_certificate_lineage import upgrade
    from cert_watch.migrations.runner import run_pending_migrations

    db = tmp_path / f"cert-watch-{release}.sqlite3"
    _db_at(db, last_applied)
    with sqlite3.connect(str(db)) as conn:
        conn.execute(
            "INSERT INTO hosts (id, hostname, port, added_at) "
            "VALUES ('h1', ?, 443, '2026-08-01T00:00:00+00:00')",
            (spelling,),
        )
        # Z -> A -> B: A's and Z's rows are gone; B (current) names A.
        _leaf(conn, "B", spelling, 443, "A")
        _renewed_event(conn, "A", "B", spelling, 443)
        _renewed_event(conn, "Z", "A", spelling, 443)
        # An event on another endpoint than its successor row: skipped.
        _leaf(conn, "Q", _OTHER, 443, None)
        _renewed_event(conn, "P", "Q", spelling, 443)
        # An event whose chain reaches no stored certificate: skipped.
        _renewed_event(conn, "S", "R", spelling, 443)
        # A malformed payload is ignored.
        conn.execute(
            "INSERT INTO event_log (event_type, timestamp, source, payload, created_at) "
            "VALUES ('cert_renewed', '2026-09-01', 'scan', '{', '2026-09-01')"
        )
        conn.commit()

    with caplog.at_level(logging.INFO, logger="cert_watch.migrations"):
        applied = run_pending_migrations(db, backup=False)
    assert applied[-1] == "0042"
    assert _lineage_rows(db) == [("A", "B", _HOST, 443), ("Z", "A", _HOST, 443)]
    assert any(
        "recorded 1 renewal(s) from stored certificates and 1" in r.getMessage()
        for r in caplog.records
    )
    with _connect(db) as conn:
        assert navigation_hint(conn, "Z") == "B"
        assert navigation_hint(conn, "A") == "B"
        assert navigation_hint(conn, "P") is None
        assert navigation_hint(conn, "S") is None
        upgrade(conn)  # idempotent
        conn.commit()
    assert _lineage_rows(db) == [("A", "B", _HOST, 443), ("Z", "A", _HOST, 443)]
