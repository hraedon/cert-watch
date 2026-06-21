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


def _insert_cert(conn, cert_id, hostname, port=443, tags="", source="scanned"):
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
            "[]", f"fp-{cert_id}", b"der", source, hostname,
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

    def test_grouped_dashboard_non_ascii_casefold_parity(self, db: Path):
        """WI-066: the grouped dashboard's Python-side filter
        (_entry_matches_scope_tag) uses casefold() not lower(), so uploaded
        entries with non-ASCII tags match scope tags the same way scanned
        entries do via SQL cw_casefold."""
        from cert_watch.database.dashboard import list_dashboard_grouped_page
        from cert_watch.tags import tags_match

        with _connect(db) as conn:
            _insert_host(conn, "de.example.com", tags="STRASSE")
            _insert_cert(conn, "c1", "de.example.com", source="uploaded")

        assert tags_match(["STRASSE"], ["Straße"]) is True
        rows, total = list_dashboard_grouped_page(
            db, scope_tags=("Straße",), per_page=0
        )
        assert total == 1


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


def _insert_alert(
    conn,
    alert_id,
    cert_id,
    alert_type="expiry_warning",
    status="pending",
    message="test",
    threshold_days=7,
):
    conn.execute(
        """
        INSERT INTO alerts
        (id, cert_id, alert_type, status, message, threshold_days, extra_recipients,
         created_at, sent_at, error_message, hostname, subject)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            alert_id,
            cert_id,
            alert_type,
            status,
            message,
            threshold_days,
            "[]",
            datetime.now(UTC).isoformat(),
            None,
            None,
            "",
            "",
        ),
    )


# ── WI-078: bulk operations honour tag scope ────────────────────────────────
#
# Two layers of coverage:
#   1. Repository methods (list_scoped / list_pending_scoped / mark_all_read) —
#      the SQL is owned here, so it is unit-tested directly.
#   2. The three routes (scan-all, flush, mark-all-read) — driven end-to-end
#      through a TestClient with a real tag-scoped operator session, proving the
#      route actually wires the scope into the repository (the bug was a missing
#      wire, so only a route test can guard against a regression).


def _seed_two_teams(db: Path) -> None:
    """Seed host-a/cert-a/alert-a tagged team-a and host-b/... tagged team-b."""
    with _connect(db) as conn:
        _insert_host(conn, "host-a.example.com", tags="team-a")
        _insert_host(conn, "host-b.example.com", tags="team-b")
        _insert_cert(conn, "cert-a", "host-a.example.com", tags="team-a")
        _insert_cert(conn, "cert-b", "host-b.example.com", tags="team-b")
        _insert_alert(conn, "alert-a", "cert-a", status="pending")
        _insert_alert(conn, "alert-b", "cert-b", status="pending")
        conn.commit()


class TestScopedRepoMethods:
    """WI-078: the repository methods the routes delegate to."""

    def test_host_list_scoped_filters_by_tag(self, db: Path):
        from cert_watch.database import SqliteHostRepository

        _seed_two_teams(db)
        hosts = SqliteHostRepository(db).list_scoped(("team-a",))
        assert [h.hostname for h in hosts] == ["host-a.example.com"]

    def test_host_list_scoped_empty_scope_returns_all(self, db: Path):
        from cert_watch.database import SqliteHostRepository

        _seed_two_teams(db)
        hosts = SqliteHostRepository(db).list_scoped(())
        assert {h.hostname for h in hosts} == {
            "host-a.example.com",
            "host-b.example.com",
        }

    def test_alert_list_pending_scoped_filters_by_tag(self, db: Path):
        from cert_watch.database import SqliteAlertRepository

        _seed_two_teams(db)
        pending = SqliteAlertRepository(db).list_pending_scoped(("team-a",))
        assert [a.id for a in pending] == ["alert-a"]

    def test_alert_list_pending_scoped_empty_returns_all(self, db: Path):
        from cert_watch.database import SqliteAlertRepository

        _seed_two_teams(db)
        pending = SqliteAlertRepository(db).list_pending_scoped(())
        assert {a.id for a in pending} == {"alert-a", "alert-b"}

    def test_alert_mark_all_read_scoped(self, db: Path):
        from cert_watch.database import SqliteAlertRepository

        _seed_two_teams(db)
        updated = SqliteAlertRepository(db).mark_all_read(("team-a",))
        assert updated == 1
        with _connect(db) as conn:
            reads = dict(conn.execute("SELECT id, read FROM alerts").fetchall())
        assert reads["alert-a"] == 1
        assert reads["alert-b"] == 0

    def test_alert_mark_all_read_no_scope_marks_all(self, db: Path):
        from cert_watch.database import SqliteAlertRepository

        _seed_two_teams(db)
        updated = SqliteAlertRepository(db).mark_all_read(())
        assert updated == 2
        with _connect(db) as conn:
            reads = dict(conn.execute("SELECT id, read FROM alerts").fetchall())
        assert reads == {"alert-a": 1, "alert-b": 1}

    def test_disjoint_scope_touches_nothing(self, db: Path):
        """A scope that matches no data must select/mutate zero rows across all
        three repo methods (boundary the reviewers flagged as untested)."""
        from cert_watch.database import SqliteAlertRepository, SqliteHostRepository

        _seed_two_teams(db)
        assert SqliteHostRepository(db).list_scoped(("team-c",)) == []
        assert SqliteAlertRepository(db).list_pending_scoped(("team-c",)) == []
        assert SqliteAlertRepository(db).mark_all_read(("team-c",)) == 0
        with _connect(db) as conn:
            reads = dict(conn.execute("SELECT id, read FROM alerts").fetchall())
        assert reads == {"alert-a": 0, "alert-b": 0}

    def test_multi_tag_scope_is_union_not_intersection(self, db: Path):
        """A user scoped to BOTH teams sees the union — guards against the
        OR-vs-AND ambiguity the reviewers raised about the tag filter."""
        from cert_watch.database import SqliteAlertRepository, SqliteHostRepository

        _seed_two_teams(db)
        hosts = SqliteHostRepository(db).list_scoped(("team-a", "team-b"))
        assert {h.hostname for h in hosts} == {
            "host-a.example.com",
            "host-b.example.com",
        }
        pending = SqliteAlertRepository(db).list_pending_scoped(("team-a", "team-b"))
        assert {a.id for a in pending} == {"alert-a", "alert-b"}
        assert SqliteAlertRepository(db).mark_all_read(("team-a", "team-b")) == 2

    def test_flush_and_mark_read_select_the_same_scope(self, db: Path):
        """Regression for the is_leaf asymmetry: the SET of alerts a scoped user
        can flush (list_pending_scoped) must be exactly the set they can clear
        (mark_all_read) — asserted by identity, not just cardinality. (The two
        methods filter orthogonal columns — status vs read — so this only holds
        because every seeded alert is both pending and unread.)"""
        from cert_watch.database import SqliteAlertRepository

        _seed_two_teams(db)
        repo = SqliteAlertRepository(db)
        flushable = {a.id for a in repo.list_pending_scoped(("team-a",))}
        repo.mark_all_read(("team-a",))
        with _connect(db) as conn:
            cleared = {
                r["id"]
                for r in conn.execute("SELECT id FROM alerts WHERE read = 1").fetchall()
            }
        assert cleared == flushable == {"alert-a"}


    def test_effective_tags_union_matches_host_or_cert_tag(self, db: Path):
        """The scope filter matches on cert ∪ host tags: an alert is in scope
        when EITHER its cert or its host carries a scope tag, even when the two
        disagree. Guards the OR (not AND) semantics across the two tag columns,
        which the same-tag seed in _seed_two_teams never exercises."""
        from cert_watch.database import SqliteAlertRepository, SqliteHostRepository

        with _connect(db) as conn:
            # host tagged team-a, but its cert tagged team-b (tags disagree).
            _insert_host(conn, "split.example.com", tags="team-a")
            _insert_cert(conn, "cert-split", "split.example.com", tags="team-b")
            _insert_alert(conn, "alert-split", "cert-split", status="pending")
            conn.commit()

        host_repo = SqliteHostRepository(db)
        alert_repo = SqliteAlertRepository(db)
        # The host tag pulls it into team-a's scope...
        assert [h.hostname for h in host_repo.list_scoped(("team-a",))] == [
            "split.example.com"
        ]
        assert [a.id for a in alert_repo.list_pending_scoped(("team-a",))] == [
            "alert-split"
        ]
        # ...and the cert tag independently pulls the alert into team-b's scope.
        assert [a.id for a in alert_repo.list_pending_scoped(("team-b",))] == [
            "alert-split"
        ]


class TestScopeTagsFromAuthContract:
    """The fail-open contract the routes rely on: no auth context → unscoped."""

    def test_none_auth_context_is_unscoped(self):
        from cert_watch.routes._scoped import scope_tags_from_auth

        # Auth disabled (no provider) → request.state.auth_context is None →
        # bulk routes must behave as unscoped (see everything), matching the
        # existing scope_write_denied contract.
        assert scope_tags_from_auth(None) == ()


def _make_scoped_app(db: Path, tmp_path: Path, *, scope_tag: str):
    """Build an app + session groups for a *writer* scoped to *scope_tag*.

    Per the tier/scope decoupling (WI-061), write capability comes from an
    UNSCOPED global role while the tag scope comes from a separate SCOPED role.
    An empty *scope_tag* yields an unscoped operator (full visibility). Returns
    ``(app, groups)`` — the groups travel in the session token.
    """
    from cert_watch.app import create_app
    from cert_watch.config import Settings

    role_repo = SqliteRoleRepository(db)
    # Unscoped operator → grants write, no tag restriction.
    role_repo.add(Role(name="global-op", permission_tier="operator", scope_tag=""))
    role_map = {"global-op": {"groups": ["op-grp"]}}
    groups = ["op-grp"]
    if scope_tag:
        # Scoped role → contributes the tag scope (but not the tier).
        role_repo.add(
            Role(name="team-role", permission_tier="viewer", scope_tag=scope_tag)
        )
        role_map["team-role"] = {"groups": ["team-grp"]}
        groups.append("team-grp")
    s = Settings(db_path=db, data_dir=tmp_path, role_map=role_map)

    class _Provider:
        provider_name = "mock"

    return create_app(auth_provider=_Provider(), settings=s), groups


def _scoped_client(app, groups):
    from fastapi.testclient import TestClient

    from cert_watch.auth import SESSION_COOKIE, create_session

    token = create_session("alice", groups=groups)
    client = TestClient(app)
    client.cookies.set(SESSION_COOKIE, token)
    return client


class TestScanAllHostsRoute:
    """WI-078: POST /hosts/all/scan only scans the caller's in-scope hosts."""

    def _run(self, db, tmp_path, monkeypatch, scope_tag):
        monkeypatch.setenv("CERT_WATCH_CSRF_DISABLED", "1")
        _seed_two_teams(db)

        scanned: list[str] = []

        async def _fake_scan(hostname, port, **kwargs):
            from cert_watch.scan import ScanError

            scanned.append(hostname)
            return ScanError(hostname=hostname, port=port, error_message="stub")

        monkeypatch.setattr(
            "cert_watch.routes.hosts.scan_host_async", _fake_scan
        )
        app, groups = _make_scoped_app(db, tmp_path, scope_tag=scope_tag)
        with _scoped_client(app, groups) as client:
            r = client.post("/hosts/all/scan", follow_redirects=False)
        assert r.status_code == 303
        return scanned

    def test_scoped_operator_scans_only_team_hosts(self, db, tmp_path, monkeypatch):
        scanned = self._run(db, tmp_path, monkeypatch, scope_tag="team-a")
        assert scanned == ["host-a.example.com"]

    def test_unscoped_operator_scans_all_hosts(self, db, tmp_path, monkeypatch):
        scanned = self._run(db, tmp_path, monkeypatch, scope_tag="")
        assert set(scanned) == {"host-a.example.com", "host-b.example.com"}


class TestMarkAllAlertsReadRoute:
    """WI-078: POST /alerts/mark-all-read only clears the caller's alerts."""

    def _run(self, db, tmp_path, monkeypatch, scope_tag):
        monkeypatch.setenv("CERT_WATCH_CSRF_DISABLED", "1")
        _seed_two_teams(db)
        app, groups = _make_scoped_app(db, tmp_path, scope_tag=scope_tag)
        with _scoped_client(app, groups) as client:
            r = client.post("/alerts/mark-all-read", follow_redirects=False)
        assert r.status_code == 303
        with _connect(db) as conn:
            return dict(conn.execute("SELECT id, read FROM alerts").fetchall())

    def test_scoped_operator_clears_only_team_alerts(self, db, tmp_path, monkeypatch):
        reads = self._run(db, tmp_path, monkeypatch, scope_tag="team-a")
        assert reads == {"alert-a": 1, "alert-b": 0}

    def test_unscoped_operator_clears_all_alerts(self, db, tmp_path, monkeypatch):
        reads = self._run(db, tmp_path, monkeypatch, scope_tag="")
        assert reads == {"alert-a": 1, "alert-b": 1}


class TestFlushAlertQueueRoute:
    """WI-078: POST /alerts/flush only sends the caller's in-scope alerts."""

    def _run(self, db, tmp_path, monkeypatch, scope_tag):
        monkeypatch.setenv("CERT_WATCH_CSRF_DISABLED", "1")
        _seed_two_teams(db)

        seen: list[str] = []

        def _fake_process(alert_repo, alert_config, webhook_config):
            seen.extend(a.id for a in alert_repo.list_pending())
            return {"sent": len(seen), "failed": 0}

        monkeypatch.setattr("cert_watch.alerts.process_pending", _fake_process)
        app, groups = _make_scoped_app(db, tmp_path, scope_tag=scope_tag)
        with _scoped_client(app, groups) as client:
            r = client.post("/alerts/flush", follow_redirects=False)
        assert r.status_code == 303
        return seen

    def test_scoped_operator_flushes_only_team_alerts(self, db, tmp_path, monkeypatch):
        seen = self._run(db, tmp_path, monkeypatch, scope_tag="team-a")
        assert seen == ["alert-a"]

    def test_unscoped_operator_flushes_all_alerts(self, db, tmp_path, monkeypatch):
        seen = self._run(db, tmp_path, monkeypatch, scope_tag="")
        assert set(seen) == {"alert-a", "alert-b"}


class TestScopedFlushFullContract:
    """WI-078: drive the REAL process_pending through ScopedAlertRepository with
    only the SMTP transport stubbed, proving the whole wrapper contract
    (scoped list_pending + mark_sent on in-scope IDs) — not just list_pending.
    The route test stubs process_pending entirely, so it can't cover this."""

    def test_real_process_pending_sends_and_marks_only_in_scope(
        self, db: Path, monkeypatch
    ):
        from cert_watch import alerts as alerts_mod
        from cert_watch.database import ScopedAlertRepository

        _seed_two_teams(db)

        sent_ids: list[str] = []

        def _fake_send(alert, config):
            sent_ids.append(alert.id)
            return True

        # Stub delivery at the transport boundary; process_pending itself is real.
        monkeypatch.setattr(alerts_mod, "send_alert", _fake_send)

        repo = ScopedAlertRepository(db, ("team-a",))
        result = alerts_mod.process_pending(repo, config=object(), webhook_config=None)

        assert sent_ids == ["alert-a"]
        assert result == {"sent": 1, "failed": 0}
        # mark_sent went through the wrapper → only the in-scope alert flipped.
        with _connect(db) as conn:
            statuses = dict(conn.execute("SELECT id, status FROM alerts").fetchall())
        assert statuses["alert-a"] == "sent"
        assert statuses["alert-b"] == "pending"
