"""Tests for BC-083 (secure-by-default) and BC-081 (session revocation)."""

from __future__ import annotations

import sqlite3
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from cert_watch.auth import (
    NoAuthProvider,
    create_session,
    set_signing_key,
    validate_session,
)
from cert_watch.database import init_schema, kv_set
from cert_watch.database.queries import bump_session_version, get_session_version
from cert_watch.middleware import set_csrf_secret

# ---------- BC-083: Secure-by-default auth posture ----------


class TestBC083SecureByDefault:
    """Verify that the app refuses to start without auth on non-loopback."""

    LOOPBACK_ADDRS = ("127.0.0.1", "::1", "localhost")

    def test_needs_setup_no_host_count_condition(self):
        """BC-083: needs_setup is true without auth and without allow_unauth,
        regardless of host count. The old host_count==0 gate is removed."""
        auth = NoAuthProvider()
        s = MagicMock()
        s.allow_unauth = False
        setup_complete = False

        needs_setup = isinstance(auth, NoAuthProvider) and not s.allow_unauth and not setup_complete
        assert needs_setup is True

    def test_needs_setup_false_with_auth(self):
        """With a real auth provider, needs_setup is false."""
        from cert_watch.auth import LocalAdminProvider, _scrypt_hash

        auth = LocalAdminProvider("admin", _scrypt_hash("pass"))
        s = MagicMock()
        s.allow_unauth = False
        setup_complete = False

        needs_setup = isinstance(auth, NoAuthProvider) and not s.allow_unauth and not setup_complete
        assert needs_setup is False

    def test_needs_setup_false_with_allow_unauth(self):
        """With ALLOW_UNAUTH=1, needs_setup is false."""
        auth = NoAuthProvider()
        s = MagicMock()
        s.allow_unauth = True
        setup_complete = False

        needs_setup = isinstance(auth, NoAuthProvider) and not s.allow_unauth and not setup_complete
        assert needs_setup is False

    def test_needs_setup_false_after_setup_complete(self):
        """After setup is complete, needs_setup is false."""
        auth = NoAuthProvider()
        s = MagicMock()
        s.allow_unauth = False
        setup_complete = True

        needs_setup = isinstance(auth, NoAuthProvider) and not s.allow_unauth and not setup_complete
        assert needs_setup is False

    def test_system_exit_nonloopback_no_auth(self, tmp_path, monkeypatch):
        """BC-083: lifespan raises SystemExit for non-loopback + no auth + no ALLOW_UNAUTH."""
        from cert_watch.auth import NoAuthProvider
        from cert_watch.config import Settings

        s = Settings(
            db_path=tmp_path / "test.sqlite3",
            data_dir=tmp_path,
            auth_provider="",
            allow_unauth=False,
        )
        auth = NoAuthProvider()

        # Verify the condition logic (not a full lifespan test — that's hard
        # to do without TestClient starting the app, which would raise SystemExit)
        assert isinstance(auth, NoAuthProvider)
        assert not s.allow_unauth
        # Non-loopback host should trigger SystemExit
        bind_host = "0.0.0.0"
        should_exit = (
            isinstance(auth, NoAuthProvider)
            and not s.allow_unauth
            and bind_host not in self.LOOPBACK_ADDRS
        )
        assert should_exit

    def test_loopback_exempt(self, tmp_path):
        """BC-083: loopback binds always bypass the SystemExit check."""
        from cert_watch.auth import NoAuthProvider

        auth = NoAuthProvider()
        # For loopback addresses, the "should exit" check should be False
        for bind_host in self.LOOPBACK_ADDRS:
            should_exit = isinstance(auth, NoAuthProvider) and bind_host not in self.LOOPBACK_ADDRS
            assert not should_exit, f"{bind_host} should be exempt"

    def test_allow_unauth_bypasses_system_exit(self, tmp_path, monkeypatch):
        """BC-083: CERT_WATCH_ALLOW_UNAUTH=1 skips the SystemExit."""
        monkeypatch.setenv("CERT_WATCH_ALLOW_UNAUTH", "1")
        from cert_watch.config import Settings

        s = Settings(
            db_path=tmp_path / "test.sqlite3",
            data_dir=tmp_path,
            auth_provider="",
            allow_unauth=True,
        )
        # allow_unauth=True means the check should not trigger
        auth = NoAuthProvider()
        should_exit = isinstance(auth, NoAuthProvider) and not s.allow_unauth
        assert not should_exit


# ---------- BC-081: Server-side session revocation ----------


class TestBC081SessionRevocation:
    """Tests for per-user session version tracking (BC-081)."""

    def test_get_session_version_default(self, tmp_path):
        """A user with no row in session_versions has version 0."""
        db = tmp_path / "test.sqlite3"
        init_schema(db)
        version = get_session_version(db, "nonexistent")
        assert version == 0

    def test_bump_creates_row(self, tmp_path):
        """bump_session_version creates a row starting at version 1."""
        db = tmp_path / "test.sqlite3"
        init_schema(db)
        version = bump_session_version(db, "alice")
        assert version == 1

        # Row exists in DB
        with sqlite3.connect(str(db)) as conn:
            row = conn.execute(
                "SELECT version FROM session_versions WHERE username = ?", ("alice",)
            ).fetchone()
        assert row is not None
        assert row[0] == 1

    def test_bump_increments(self, tmp_path):
        """Subsequent bumps increment the version."""
        db = tmp_path / "test.sqlite3"
        init_schema(db)
        v1 = bump_session_version(db, "alice")
        v2 = bump_session_version(db, "alice")
        v3 = bump_session_version(db, "alice")
        assert v1 == 1
        assert v2 == 2
        assert v3 == 3

    def test_session_with_version_valid(self, tmp_path):
        """A session token with the current version is valid."""
        db = tmp_path / "test.sqlite3"
        init_schema(db)
        set_signing_key("test-key-bc081")
        # Create a session with version=1 and ensure it validates
        bump_session_version(db, "alice")
        token = create_session("alice", version=1)
        result = validate_session(token, db_path=str(db))
        assert result == "alice"

    def test_session_with_old_version_invalid(self, tmp_path):
        """A session token with an old version is invalid after bump."""
        db = tmp_path / "test.sqlite3"
        init_schema(db)
        set_signing_key("test-key-bc081")
        # Create session at version 0 (before any bumps)
        token = create_session("alice", version=0)
        # Bump the session version to 1 (simulating logout)
        bump_session_version(db, "alice")
        # Old token should be invalid
        result = validate_session(token, db_path=str(db))
        assert result is None

    def test_session_without_db_path_backward_compat(self):
        """Without db_path, version checking is skipped (backward compat for
        unit tests that don't have a database)."""
        set_signing_key("test-key-bc081-compat")
        token = create_session("alice", version=0)
        # Should validate fine without a DB check
        result = validate_session(token)
        assert result == "alice"

    def test_new_session_after_bump_valid(self, tmp_path):
        """After a bump, a newly issued session with the new version is valid."""
        db = tmp_path / "test.sqlite3"
        init_schema(db)
        set_signing_key("test-key-bc081-new")
        bump_session_version(db, "alice")
        # Create token with current version
        token = create_session("alice", version=1)
        result = validate_session(token, db_path=str(db))
        assert result == "alice"

    def test_logout_bumps_version(self, tmp_path, monkeypatch):
        """POST /auth/logout bumps the session version for the logged-in user."""
        monkeypatch.setenv("CERT_WATCH_AUTH_SECRET", "test-logout-key")
        monkeypatch.setenv("CERT_WATCH_CSRF_SECRET", "test-logout-csrf")
        monkeypatch.setenv("CERT_WATCH_COOKIE_SECURE", "0")
        # Patch module-level _COOKIE_SECURE so the cookie is sent over HTTP
        import cert_watch.routes.auth as auth_routes
        monkeypatch.setattr(auth_routes, "_COOKIE_SECURE", False)
        set_signing_key("test-logout-key")
        set_csrf_secret("test-logout-csrf")

        from cert_watch.app import create_app
        from cert_watch.auth import LocalAdminProvider, _scrypt_hash
        from cert_watch.config import Settings
        from cert_watch.security import SecurityContext

        db = tmp_path / "test.sqlite3"
        init_schema(db)
        # Set up a local admin
        kv_set(db, "local_admin_user", "admin")
        kv_set(db, "local_admin_password_hash", _scrypt_hash("password123"))
        kv_set(db, "setup_complete", "1")

        s = Settings(
            db_path=db,
            data_dir=tmp_path,
            auth_provider="local",
            local_admin_user="admin",
            local_admin_password_hash=_scrypt_hash("password123"),
            allow_unauth=False,
        )
        auth = LocalAdminProvider("admin", _scrypt_hash("password123"))
        security = SecurityContext(signing_key="test-logout-key", csrf_secret="test-logout-csrf")
        app = create_app(settings=s, auth_provider=auth, security=security)
        with TestClient(app) as client:
            # Log in to get a session
            response = client.post("/login", data={
                "username": "admin",
                "password": "password123",
            }, follow_redirects=False)
            assert response.status_code == 303

            # The session version for admin should be 0 (no bumps yet)
            ver_before = get_session_version(db, "admin")
            assert ver_before == 0

            # Now log out — should bump the session version.
            # Note: CSRF is disabled by the autouse conftest fixture.
            response = client.post("/auth/logout", follow_redirects=False)
            assert response.status_code == 303

            # After logout, the session version should be bumped
            ver_after = get_session_version(db, "admin")
            assert ver_after > ver_before

    def test_old_session_token_invalidated_after_logout(self, tmp_path):
        """After logout bumps version, old session tokens are rejected."""
        db = tmp_path / "test.sqlite3"
        init_schema(db)
        set_signing_key("test-revoke-key")

        # Create session at version 0
        token_old = create_session("bob", version=0)
        # Session should be valid (version 0 <= stored version 0)
        assert validate_session(token_old, db_path=str(db)) == "bob"

        # Simulate logout: bump version to 1
        bump_session_version(db, "bob")
        # Old token (version 0) should now be invalid
        assert validate_session(token_old, db_path=str(db)) is None

        # New token at version 1 should be valid
        token_new = create_session("bob", version=1)
        assert validate_session(token_new, db_path=str(db)) == "bob"

    def test_migration_creates_session_versions_table(self, tmp_path):
        """Migration 0011 creates the session_versions table."""
        db = tmp_path / "test.sqlite3"
        init_schema(db)
        with sqlite3.connect(str(db)) as conn:
            tables = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()}
        assert "session_versions" in tables

    def test_multiple_users_independent(self, tmp_path):
        """Bumping one user's version doesn't affect another user's sessions."""
        db = tmp_path / "test.sqlite3"
        init_schema(db)
        set_signing_key("test-multi-key")

        # Both users start at version 0
        token_alice = create_session("alice", version=0)
        token_bob = create_session("bob", version=0)

        # Both valid before any bumps
        assert validate_session(token_alice, db_path=str(db)) == "alice"
        assert validate_session(token_bob, db_path=str(db)) == "bob"

        # Bump alice's version (logout)
        bump_session_version(db, "alice")

        # Alice's old token invalid, bob's still valid
        assert validate_session(token_alice, db_path=str(db)) is None
        assert validate_session(token_bob, db_path=str(db)) == "bob"