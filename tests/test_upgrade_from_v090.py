"""Upgrade-floor test: a real v0.9.0 database migrates cleanly to head.

v0.9.0 is the declared minimum supported upgrade source for 1.0 (see
UPGRADING.md). This guards that contract: `tests/fixtures/cw_v090_dump.sql` is
a `.dump` of an actual database built by the **v0.9.0 tag's** code (schema
stamped through migration 0023, with representative rows). The test replays it,
runs the app's real startup upgrade path (`init_schema` = ensure_base +
run_pending_migrations), and asserts the m0024–m0028 delta applies, the data
survives, and the post-0.9.0 schema changes land.

Regenerate the fixture only from a genuine v0.9.0 checkout — do not hand-edit it,
or it stops being a faithful floor.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from cert_watch.database.schema import init_schema

_FIXTURE = Path(__file__).parent / "fixtures" / "cw_v090_dump.sql"

# Tracked tables whose row counts must be identical before and after upgrade.
_DATA_TABLES = ("hosts", "certificates", "alerts", "scan_history", "roles")


@pytest.fixture
def v090_db(tmp_path: Path) -> Path:
    """Materialise an authentic v0.9.0 database from the committed SQL dump."""
    db = tmp_path / "cw_v090.sqlite3"
    sql = _FIXTURE.read_text()
    with sqlite3.connect(str(db)) as conn:
        conn.executescript(sql)
    return db


def _counts(db: Path) -> dict[str, int]:
    with sqlite3.connect(str(db)) as conn:
        return {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in _DATA_TABLES}


def test_fixture_is_the_v090_floor(v090_db: Path) -> None:
    """Guard the fixture itself: it must be stamped through 0023 and no further."""
    with sqlite3.connect(str(v090_db)) as conn:
        ids = [r[0] for r in conn.execute("SELECT id FROM schema_version ORDER BY id")]
    assert ids[-1] == "0023", f"fixture floor drifted: head is {ids[-1]}, expected 0023"
    # The post-0.9.0 schema must NOT be present yet, or the test proves nothing.
    with sqlite3.connect(str(v090_db)) as conn:
        roles_cols = {r[1] for r in conn.execute("PRAGMA table_info(roles)")}
        hosts_cols = {r[1] for r in conn.execute("PRAGMA table_info(hosts)")}
        ct = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='ct_issuer_first_seen'"
        ).fetchone()
    assert "permission_tier" not in roles_cols  # added by m0024
    assert "starttls_mode" not in hosts_cols    # added by m0027
    assert ct is not None                       # dropped by m0028


def test_v090_upgrades_to_head_without_data_loss(v090_db: Path) -> None:
    before = _counts(v090_db)
    assert before == {"hosts": 2, "certificates": 1, "alerts": 1, "scan_history": 1, "roles": 1}

    # The exact path the app runs on startup.
    init_schema(v090_db)

    # Every registered migration is now recorded, and 0024–0028 were the delta.
    import cert_watch.migrations.registry  # noqa: F401 — registers migrations
    from cert_watch.migrations.runner import get_migrations

    expected_ids = [m[0] for m in get_migrations()]
    with sqlite3.connect(str(v090_db)) as conn:
        applied = [r[0] for r in conn.execute("SELECT id FROM schema_version ORDER BY id")]
    assert applied == expected_ids
    assert [i for i in applied if i > "0023"] == ["0024", "0025", "0026", "0027", "0028"]

    # No data lost.
    assert _counts(v090_db) == before
    # A specific row is byte-for-byte intact.
    with sqlite3.connect(str(v090_db)) as conn:
        row = conn.execute(
            "SELECT hostname, owner_email, threshold_days FROM hosts WHERE id='h1'"
        ).fetchone()
    assert row == ("prod.hraedon.com", "plm@hraedon.com", 14)


def test_v090_upgrade_applies_post_floor_schema(v090_db: Path) -> None:
    init_schema(v090_db)
    with sqlite3.connect(str(v090_db)) as conn:
        roles_cols = {r[1] for r in conn.execute("PRAGMA table_info(roles)")}
        hosts_cols = {r[1] for r in conn.execute("PRAGMA table_info(hosts)")}
        ct = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='ct_issuer_first_seen'"
        ).fetchone()
    assert "permission_tier" in roles_cols   # m0024 role tiers
    assert "starttls_mode" in hosts_cols     # m0027 STARTTLS scanning
    assert ct is None                        # m0028 dropped the unused table
