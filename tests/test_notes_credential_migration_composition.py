"""The notes-first migration sequence must preserve both features' data."""

import sqlite3
from contextlib import closing

import pytest

import cert_watch.migrations.registry  # noqa: F401
from cert_watch.certificate_model import parse_certificate
from cert_watch.migrations import runner
from tests._helpers import seed_certificate
from tests.test_schema_migration_invariants import _schema_snapshot


def _tables(database):
    with closing(sqlite3.connect(database)) as conn:
        return {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def _snapshot(database):
    with closing(sqlite3.connect(database)) as conn:
        data = {}
        for table in sorted(_tables(database)):
            quoted = table.replace('"', '""')
            data[table] = sorted(conn.execute(f'SELECT * FROM "{quoted}"').fetchall(), key=repr)
    return _schema_snapshot(database), data


def _prefix(database, through, monkeypatch):
    with monkeypatch.context() as patch:
        patch.setattr(
            runner, "_MIGRATIONS", [m for m in runner.get_migrations() if m[0] <= through]
        )
        runner.run_pending_migrations(database, backup=False)


@pytest.mark.parametrize("through", ["0049", "0050"])
def test_notes_first_upgrade_preserves_certificate_and_notes(
    tmp_path, monkeypatch, self_signed_leaf, through
):
    database = tmp_path / "before.sqlite3"
    with monkeypatch.context() as patch:
        patch.setattr(
            runner, "_MIGRATIONS", [m for m in runner.get_migrations() if m[0] <= through]
        )
        runner.run_pending_migrations(database, backup=False)
        certificate_id = seed_certificate(
            database,
            parse_certificate(self_signed_leaf.der),
            cert_id="synthetic-upload",
            source="uploaded",
            tags="team-a",
        )
    notes = "Keep this uploaded certificate's renewal context."
    with closing(sqlite3.connect(database)) as conn:
        if through == "0049":
            # 0031 deliberately retains this column for unassociated legacy notes.
            conn.execute("ALTER TABLE certificates ADD COLUMN notes TEXT NOT NULL DEFAULT ''")
            conn.execute("UPDATE certificates SET notes=? WHERE id=?", (notes, certificate_id))
        else:
            conn.execute(
                "INSERT INTO uploaded_certificate_notes VALUES (?, ?)", (certificate_id, notes)
            )
        conn.commit()

    applied = runner.run_pending_migrations(database)

    assert applied == (["0050", "0051"] if through == "0049" else ["0051"])
    assert {"uploaded_certificate_notes", "application_secrets"} <= _tables(database)
    with closing(sqlite3.connect(database)) as conn:
        assert conn.execute(
            "SELECT notes FROM uploaded_certificate_notes WHERE cert_id=?", (certificate_id,)
        ).fetchone() == (notes,)
        assert conn.execute(
            "SELECT source,tags FROM certificates WHERE id=?", (certificate_id,)
        ).fetchone() == ("uploaded", "team-a")
        assert conn.execute(
            "SELECT id FROM schema_version WHERE id >= '0050' ORDER BY id"
        ).fetchall() == [("0050",), ("0051",)]
    assert runner.run_pending_migrations(database, backup=False) == []
    backups = list(tmp_path.glob("before-pre-migration-*.sqlite3"))
    assert len(backups) == 1
    assert "application_secrets" not in _tables(backups[0])


def test_fresh_schema_has_both_distinct_migrations(tmp_path):
    database = tmp_path / "fresh.sqlite3"
    applied = runner.run_pending_migrations(database, backup=False)
    assert applied[-2:] == ["0050", "0051"]
    assert len(applied) == len(set(applied))
    assert {"uploaded_certificate_notes", "application_secrets"} <= _tables(database)


def test_other_draft_0050_without_notes_is_refused_before_schema_change(tmp_path, monkeypatch):
    database = tmp_path / "other-draft.sqlite3"
    _prefix(database, "0049", monkeypatch)
    with closing(sqlite3.connect(database)) as conn:
        conn.execute(
            "INSERT INTO schema_version VALUES "
            "('0050', 'track application credential expiry metadata', '2026-10-25')"
        )
        conn.execute(
            "CREATE TABLE application_secrets (id TEXT PRIMARY KEY, application_name TEXT)"
        )
        conn.execute("INSERT INTO application_secrets VALUES ('synthetic-id', 'keep metadata')")
        conn.commit()
    before = _snapshot(database)

    with pytest.raises(ValueError, match=r"0050.*uploaded_certificate_notes"):
        runner.run_pending_migrations(database)

    assert _snapshot(database) == before
    backups = list(tmp_path.glob("other-draft-pre-migration-*.sqlite3"))
    assert len(backups) == 1
    assert _snapshot(backups[0]) == before


def test_failed_0051_rolls_back_without_erasing_0050(tmp_path, monkeypatch):
    database = tmp_path / "failure.sqlite3"
    _prefix(database, "0050", monkeypatch)
    migrations = runner.get_migrations()
    real = migrations[-1]
    assert real[0] == "0051"

    def fail_after_schema(conn):
        real[2](conn)
        raise RuntimeError("synthetic migration failure")

    before = _snapshot(database)
    with monkeypatch.context() as patch:
        patch.setattr(
            runner, "_MIGRATIONS", [*migrations[:-1], (real[0], real[1], fail_after_schema)]
        )
        with pytest.raises(RuntimeError, match="synthetic migration failure"):
            runner.run_pending_migrations(database, backup=False)
    assert _snapshot(database) == before
    assert runner.run_pending_migrations(database, backup=False) == ["0051"]
