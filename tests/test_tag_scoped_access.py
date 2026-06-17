"""Tests for WI-051 (tag-scoped cert/host access) and WI-053 (effective tags)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from cert_watch.auth.rbac import AuthContext
from cert_watch.database import (
    Role,
    SqliteRoleRepository,
    init_schema,
)
from cert_watch.database.connection import _connect


@pytest.fixture
def db(tmp_path: Path) -> Path:
    path = tmp_path / "scoped.sqlite3"
    init_schema(path)
    return path


def _insert_host(conn, hostname, port=443, tags=""):
    conn.execute(
        "INSERT INTO hosts (id, hostname, port, tags, added_at) VALUES (?, ?, ?, ?, ?)",
        (f"h-{hostname}", hostname, port, tags, datetime.now(UTC).isoformat()),
    )


def _insert_cert(conn, cert_id, hostname, port=443, tags=""):
    now = datetime.now(UTC)
    conn.execute(
        """
        INSERT INTO certificates
        (id, subject, issuer, not_before, not_after, san_dns_names,
         fingerprint_sha256, raw_der, source, hostname, port, is_leaf,
         parent_cert_id, chain_valid, replaces_cert_id, notes, tags,
         created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            cert_id, hostname, f"issuer-{hostname}",
            now.isoformat(), (now + timedelta(days=30)).isoformat(),
            "[]", f"fp-{cert_id}", b"der", "scanned", hostname,
            port, 1, None, 1, None, "", tags,
            now.isoformat(), now.isoformat(),
        ),
    )


class TestEffectiveTags:
    def test_dashboard_row_effective_tags_merge_host_and_cert(self, db: Path):
        from cert_watch.database.dashboard import list_dashboard_page

        with _connect(db) as conn:
            _insert_host(conn, "host.example.com", tags="host-tag")
            _insert_cert(conn, "c1", "host.example.com", tags="cert-tag")
        rows, total = list_dashboard_page(db)
        assert total == 1
        row = rows[0]
        tags = {t.strip() for t in row["tags"].split(",") if t.strip()}
        assert tags == {"host-tag", "cert-tag"}


class TestDashboardScopeFiltering:
    def test_scoped_user_sees_only_tagged_entries(self, db: Path):
        from cert_watch.database.dashboard import list_dashboard_page

        with _connect(db) as conn:
            _insert_host(conn, "host-a.example.com", tags="team-a")
            _insert_host(conn, "host-b.example.com", tags="team-b")
            _insert_cert(conn, "ca1", "host-a.example.com")
            _insert_cert(conn, "cb1", "host-b.example.com")

        rows, total = list_dashboard_page(db, scope_tags=("team-a",))
        assert total == 1
        assert rows[0]["host"].startswith("host-a")

    def test_scoped_user_matching_cert_tag(self, db: Path):
        from cert_watch.database.dashboard import list_dashboard_page

        with _connect(db) as conn:
            _insert_host(conn, "host-a.example.com")
            _insert_cert(conn, "ca1", "host-a.example.com", tags="team-a")
            _insert_host(conn, "host-c.example.com")
            _insert_cert(conn, "cc1", "host-c.example.com")

        rows, total = list_dashboard_page(db, scope_tags=("team-a",))
        assert total == 1
        assert rows[0]["id"] == "ca1"

    def test_admin_empty_scope_sees_all(self, db: Path):
        from cert_watch.database.dashboard import list_dashboard_page

        with _connect(db) as conn:
            _insert_host(conn, "host-a.example.com", tags="team-a")
            _insert_host(conn, "host-b.example.com", tags="team-b")
            _insert_cert(conn, "ca1", "host-a.example.com")
            _insert_cert(conn, "cb1", "host-b.example.com")

        rows, total = list_dashboard_page(db, scope_tags=())
        assert total == 2

    def test_scoped_user_non_ascii_casefold_parity(self, db: Path):
        """WI-066: a non-ASCII case-variant scope tag matches with the same
        parity as the Python casefold engine (SQLite LIKE is ASCII-CI only, so
        without cw_casefold the scope filter undercounts vs tags_match)."""
        from cert_watch.database.dashboard import list_dashboard_page
        from cert_watch.tags import tags_match

        with _connect(db) as conn:
            _insert_host(conn, "de.example.com", tags="STRASSE")
            _insert_cert(conn, "c1", "de.example.com")

        # Engine matches via casefold (ß -> ss); the SQL scope filter must agree.
        assert tags_match(["STRASSE"], ["Straße"]) is True
        rows, total = list_dashboard_page(db, scope_tags=("Straße",))
        assert total == 1
        assert rows[0]["id"] == "c1"


class TestHostAutoTagging:
    def test_tags_with_scope_merges_scope_tag(self):
        from cert_watch.routes._scoped import tags_with_scope

        class FakeAuth:
            scope_tag = "ops-team"

        class FakeRequest:
            state = type("S", (), {"auth_context": FakeAuth()})()

        result = tags_with_scope(FakeRequest(), "prod")
        assert "ops-team" in result
        assert "prod" in result

    def test_tags_without_scope_returns_input(self):
        from cert_watch.routes._scoped import tags_with_scope

        class FakeRequest:
            state = type("S", (), {"auth_context": None})()

        assert tags_with_scope(FakeRequest(), "prod") == "prod"


class TestRoleScopeTag:
    def test_role_round_trip_scope_tag(self, db: Path):
        repo = SqliteRoleRepository(db)
        role_id = repo.add(Role(name="ops", permission_tier="operator", scope_tag="ops-team"))
        role = repo.get(role_id)
        assert role.scope_tag == "ops-team"

    def test_auth_context_carries_scope_tag(self):
        ctx = AuthContext.from_tier(
            "alice", tier="operator", scope_tag="team-a", email="alice@example.com"
        )
        assert ctx.scope_tag == "team-a"
        assert ctx.may_write()

    def test_admin_context_empty_scope_tag(self):
        ctx = AuthContext.from_tier("root", tier="admin")
        assert ctx.scope_tag == ""
        assert ctx.is_admin
