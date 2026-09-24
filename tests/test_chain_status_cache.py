"""The chain-status cache can be missing or stale, never falsely healthy (#113).

SQL status counts read a cached chain status (``certificates.chain_status``).
Round two of the #114 review showed three ways it served a stale "healthy":
a chain certificate swapped for another at the same count, a cache write that
failed after the trust anchor was removed, and an anchor removed while the
refresh was computing. Each case must now read as not-healthy in the SQL
counts, filters and rows alike.
"""

from __future__ import annotations

import sqlite3
from collections import Counter
from pathlib import Path

import pytest

from tests.test_status_rule_everywhere import STATUS_COUNTS, _issue, _row_key, _seed

KEY = "ok.example.test:443"


def _rows(db: Path) -> dict[str, str]:
    from cert_watch.database import list_dashboard_page

    rows, _ = list_dashboard_page(db, per_page=25)
    return {_row_key(r): r["urgency"] for r in rows}


def _row_counts(db: Path) -> dict[str, int]:
    counts = Counter(u for u in _rows(db).values() if u != "gray")
    return {u: counts.get(u, 0) for u in STATUS_COUNTS}


def _healthy_filter(db: Path) -> set[str]:
    from cert_watch.database import list_dashboard_page

    rows, _ = list_dashboard_page(db, urgency="healthy", per_page=25)
    return {_row_key(r) for r in rows}


@pytest.fixture
def estate(tmp_path):
    from cert_watch.database import dashboard_urgency_stats

    db = tmp_path / "cache.sqlite3"
    _seed(db)
    assert dashboard_urgency_stats(db) == STATUS_COUNTS  # cache filled, all healthy ones healthy
    return db


def test_swapping_a_chain_certificate_at_the_same_count_is_seen(estate):
    """The basis names every chain certificate, so a swap is not the same basis."""
    from cert_watch.database import dashboard_urgency_stats
    from cert_watch.database.connection import _connect

    impostor, _ = _issue("Impostor Intermediate", 400, None, ca=True)
    with _connect(estate) as conn:
        leaf = conn.execute(
            "SELECT id FROM certificates WHERE hostname = 'ok.example.test' AND port = 443"
            " AND is_leaf = 1"
        ).fetchone()
        conn.execute(
            "UPDATE certificates SET subject = ?, issuer = ?, fingerprint_sha256 = ?,"
            " raw_der = ? WHERE parent_cert_id = ?",
            (impostor.subject, impostor.issuer, impostor.fingerprint_sha256,
             impostor.raw_der, leaf["id"]),
        )
        conn.commit()

    assert _rows(estate)[KEY] == "warning"
    assert dashboard_urgency_stats(estate) == _row_counts(estate)
    assert KEY not in _healthy_filter(estate)


def test_a_cache_that_cannot_be_written_fails_closed(estate):
    """With the anchor gone and the cache unwritable, nothing stays Healthy."""
    from cert_watch.database import dashboard_urgency_stats
    from cert_watch.database.chain_status_cache import refresh_chain_status
    from cert_watch.database.connection import _connect

    with _connect(estate) as conn:
        conn.execute(
            "CREATE TRIGGER reject_chain_cache BEFORE UPDATE OF chain_status ON certificates"
            " BEGIN SELECT RAISE(FAIL, 'cache read-only'); END"
        )
        conn.execute("DELETE FROM trust_anchors")
        conn.commit()

    assert refresh_chain_status(estate) == 0
    stats = dashboard_urgency_stats(estate)
    assert stats["healthy"] == 0
    # The rows verify live and agree: every private chain is now incomplete.
    assert stats == _row_counts(estate)
    assert _healthy_filter(estate) == set()


def test_an_anchor_removed_during_refresh_is_not_published_as_trusted(estate, monkeypatch):
    """Compare-and-set: a status computed against an anchor deleted before it
    is published must not be stored as current."""
    from cert_watch.database import chain_status_cache, dashboard_urgency_stats
    from cert_watch.database.connection import _connect

    with _connect(estate) as conn:
        conn.execute("UPDATE certificates SET chain_status_basis = NULL WHERE is_leaf = 1")
        conn.commit()

    original = chain_status_cache._compute
    fired = []

    def compute_then_delete_anchor(conn, leaf_ids, anchors, trust):
        updates = original(conn, leaf_ids, anchors, trust)
        if not fired:
            fired.append(True)
            with sqlite3.connect(estate, timeout=30) as writer:
                writer.execute("DELETE FROM trust_anchors")
                writer.commit()
        return updates

    monkeypatch.setattr(chain_status_cache, "_compute", compute_then_delete_anchor)
    during = dashboard_urgency_stats(estate)
    assert fired
    assert during["healthy"] == 0
    assert during == _row_counts(estate)


def test_basis_names_the_leaf_and_every_chain_certificate(estate):
    from cert_watch.database.connection import _connect

    with _connect(estate) as conn:
        row = conn.execute(
            "SELECT c.fingerprint_sha256 AS fp, c.chain_status_basis AS basis,"
            " (SELECT ch.fingerprint_sha256 FROM certificates ch"
            "  WHERE ch.parent_cert_id = c.id) AS chain_fp"
            " FROM certificates c WHERE c.hostname = 'ok.example.test' AND c.port = 443"
            " AND c.is_leaf = 1"
        ).fetchone()
    assert row["basis"].endswith(f":{row['fp']}:{row['chain_fp']}")
