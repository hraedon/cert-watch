"""One Browse row per endpoint, even with two scanned leaves (#151).

An old alias merge (see ``resolve_target``) can leave one endpoint holding two
scanned leaf rows. Browse renders one row per endpoint, so every count over the
inventory must count that endpoint once too: the Browse total and pager, the
grouped view, the Home cards, and the per-axis counts Home links into Browse.
The row shown is the endpoint's head leaf -- the newest by ``created_at`` then
``rowid`` -- the same head renewal reports, readiness and the renewal webhook
read.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from cert_watch.certificate_model import Certificate
from cert_watch.database import SqliteHostRepository, init_schema
from cert_watch.database.chain_status_cache import prepare_status
from cert_watch.database.connection import _connect
from cert_watch.database.dashboard_axes import dashboard_axis_stats
from cert_watch.database.dashboard_grouped import list_dashboard_grouped_page
from cert_watch.database.dashboard_page import get_dashboard_entry, list_dashboard_page
from cert_watch.database.dashboard_stats import (
    dashboard_inventory_count,
    dashboard_urgency_stats,
)
from cert_watch.status_model import AxisSettings, prepare_status_model_context
from tests._helpers import seed_scanned

NOW = datetime.now(UTC)


def _insert_leaf(
    conn, leaf_id: str, hostname: str, fingerprint: str, created_at: datetime, *, days: int
) -> None:
    conn.execute(
        """INSERT INTO certificates
           (id,subject,issuer,not_before,not_after,san_dns_names,fingerprint_sha256,
            raw_der,source,hostname,port,is_leaf,parent_cert_id,tags,created_at,updated_at)
           VALUES (?,?,'CN=Test CA',?,?,'[]',?,x'00','scanned',?,443,1,NULL,'t',?,?)""",
        (
            leaf_id,
            f"CN={leaf_id}.example.test",
            (NOW - timedelta(days=5)).isoformat(),
            (NOW + timedelta(days=days)).isoformat(),
            fingerprint.ljust(64, "0"),
            hostname,
            created_at.isoformat(),
            created_at.isoformat(),
        ),
    )


def _estate(tmp_path: Path) -> Path:
    """Three endpoints: one ordinary, one with two scanned leaves, one pending."""
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    repo = SqliteHostRepository(db)
    repo.add("plain.example.test", 443, tags="t")
    merge_id = repo.add("merge.example.test", 443, tags="t")
    repo.add("pending.example.test", 443, tags="t")
    seed_scanned(
        db,
        "plain.example.test",
        443,
        Certificate(
            subject="CN=plain.example.test",
            issuer="CN=Test CA",
            not_before=NOW - timedelta(days=5),
            not_after=NOW + timedelta(days=200),
            fingerprint_sha256="c3".ljust(64, "0"),
        ),
    )
    with _connect(db) as conn:
        # The older row expires sooner, so an "expiry" sort would list it
        # first if it leaked into the population.
        _insert_leaf(
            conn, "stale-leaf", "merge.example.test", "a1",
            NOW - timedelta(days=30), days=3,
        )
        _insert_leaf(
            conn, "head-leaf", "merge.example.test", "b2",
            NOW - timedelta(days=1), days=150,
        )
        conn.execute(
            "INSERT INTO renewal_attempts(attempt_id,host_id,is_current,source,state,"
            "opened_seq,received_at,failure_attempt_id,failure_reported_at)"
            " VALUES('dup-a',?,1,'test','verifying',1,?,?,?)",
            (merge_id, NOW.isoformat(), "dup-a", NOW.isoformat()),
        )
        conn.commit()
    return db


def test_browse_total_equals_rendered_rows(tmp_path) -> None:
    db = _estate(tmp_path)

    rows, total = list_dashboard_page(db, per_page=0)

    assert total == len(rows) == 3
    merge_rows = [r for r in rows if r.get("host") == "merge.example.test:443"]
    assert [r["id"] for r in merge_rows] == ["head-leaf"]


def test_pager_never_counts_a_row_it_cannot_show(tmp_path) -> None:
    db = _estate(tmp_path)

    _rows, total = list_dashboard_page(db, per_page=1, page=1)
    seen = []
    for page in range(1, total + 1):
        page_rows, page_total = list_dashboard_page(db, per_page=1, page=page)
        assert page_total == total
        assert len(page_rows) == 1, page
        seen.append(page_rows[0]["id"])

    assert total == 3
    assert len(set(seen)) == 3
    assert "stale-leaf" not in seen


def test_filters_and_sorts_see_only_the_head_leaf(tmp_path) -> None:
    db = _estate(tmp_path)

    # The stale row expires in 3 days (critical); the head in 150 (healthy).
    rows, total = list_dashboard_page(db, urgency="critical", per_page=0)
    assert (rows, total) == ([], 0)
    rows, total = list_dashboard_page(db, sort_by="expiry", per_page=0)
    assert total == len(rows)
    assert "stale-leaf" not in [r["id"] for r in rows]


def test_home_and_grouped_counts_match_browse_total(tmp_path) -> None:
    db = _estate(tmp_path)
    status = prepare_status(db, NOW)
    axes = prepare_status_model_context(db, certificate_status=status, settings=AxisSettings())

    _rows, browse_total = list_dashboard_page(db, per_page=0, status=status, axes=axes)
    assert dashboard_inventory_count(db) == browse_total
    assert sum(dashboard_urgency_stats(db, status=status).values()) == browse_total - 1

    groups, _ = list_dashboard_grouped_page(db, per_page=0, status=status, axes=axes)
    members = [m for g in groups for m in g.get("members", [g])]
    assert len(members) == browse_total

    for columns in (frozenset({"condition", "renewal"}), frozenset({"renewal_risks"})):
        counts = dashboard_axis_stats(
            db, status=status, axes=axes, axis_columns=columns, home=True
        )["renewal"]
        failed_rows, failed_total = list_dashboard_page(
            db, renewal="failed", per_page=0, status=status, axes=axes
        )
        assert counts["failed"] == failed_total == len(failed_rows) == 1


def test_direct_lookup_of_the_stale_leaf_still_resolves(tmp_path) -> None:
    """A detail link to the non-head row still describes that certificate."""
    db = _estate(tmp_path)

    entry = get_dashboard_entry(db, "stale-leaf")

    assert entry is not None
    assert entry["id"] == "stale-leaf"
