"""Focused tests for cert_watch.auth.session signing helpers and revocation."""

from __future__ import annotations

import hashlib
import hmac
import sqlite3
import threading
import time

import pytest
from fastapi.testclient import TestClient

from cert_watch.auth import (
    create_session,
    decode_session,
    set_signing_key,
    validate_session,
)
from cert_watch.auth.session import _parse_ts, _sign_state, _verify_state
from cert_watch.database import (
    bump_session_version,
    get_session_version,
    init_schema,
    kv_set,
)
from cert_watch.middleware import set_csrf_secret
from cert_watch.security import SecurityContext


@pytest.fixture
def security():
    return SecurityContext(signing_key="a" * 64, csrf_secret="b" * 64)


def test_sign_and_verify_state_roundtrip(security):
    signed = _sign_state("raw-state", security=security, nonce="nonce0")
    assert _verify_state(signed, security=security) == ("raw-state", "nonce0", None)


def test_sign_state_with_pkce_code_verifier(security):
    signed = _sign_state(
        "raw-state", security=security, nonce="nonce0", code_verifier="verifier123"
    )
    assert _verify_state(signed, security=security) == ("raw-state", "nonce0", "verifier123")


def test_verify_state_rejects_legacy_and_tampered(security):
    assert _verify_state("legacy:sig", security=security) is None
    assert _verify_state("raw-state:nonce0:" + "0" * 64, security=security) is None
    assert _verify_state("", security=security) is None


def test_parse_ts_invalid_returns_zero():
    assert _parse_ts(["a", "b", "c", "not-a-number"], start=3) == 0
    assert _parse_ts(["a", "b"], start=3) == 0
    assert _parse_ts(["a", "b", "c", "0"], start=3) == 0
    assert _parse_ts(["a", "b", "c", "999"], start=3) == 999


# ── Session revocation (BC-081) ─────────────────────────────────────────────


class TestSessionRevocation:
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

            # The session version for admin should be >=1 after login (BC-029 D)
            ver_before = get_session_version(db, "admin")
            assert ver_before >= 1

            # Now log out — should bump the session version.
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


# ── Session token shapes (WI-088) ───────────────────────────────────────────


def test_validate_session_3_part_rejected():
    """Old-format 3-part tokens (username:ts:nonce) are rejected (WI-088)."""
    set_signing_key("test-key-3part")
    payload = "bob:1234567890:abcdef12"
    sig = "fake"
    old_token = f"{payload}:{sig}"
    assert validate_session(old_token) is None


def test_validate_session_4_part_with_version():
    """New-format tokens (username:version:ts:nonce) validate correctly."""
    set_signing_key("test-key-4part")
    token = create_session("alice", version=2)
    assert validate_session(token) == "alice"


def test_validate_session_5_part_malformed():
    """Extra colons in payload shouldn't crash validation."""
    set_signing_key("test-key-5part")
    # Manually create a 5-part payload (username:extra:version:ts:nonce)
    # The signature check will fail, but parsing should not crash
    token = "alice:extra:2:1234567890:abcdef12:fake_sig"
    assert validate_session(token) is None


def test_validate_session_6_part_with_groups_and_roles():
    """BC-145: tokens carrying groups/roles encode and decode correctly."""
    set_signing_key("test-key-6part")
    token = create_session(
        "alice", version=2, groups=["g-ops", "g-admin"], roles=["operator"]
    )
    info = decode_session(token)
    assert info is not None
    assert info.username == "alice"
    assert info.version == 2
    assert info.groups == ["g-ops", "g-admin"]
    assert info.roles == ["operator"]
    assert validate_session(token) == "alice"


def test_validate_session_3_part_rejected_even_when_signed():
    """A genuine 3-part signed token (old format) is rejected (WI-088)."""
    set_signing_key("test-key-old")
    payload = f"bob:{int(time.time())}:nonce1234"
    sig = hmac.new(b"test-key-old", payload.encode(), hashlib.sha256).hexdigest()[:64]
    token = f"{payload}:{sig}"
    assert validate_session(token) is None


def test_validate_session_4_part_rejects_32char_sig():
    """4-part tokens with legacy 32-char signatures are rejected (WI-088)."""
    set_signing_key("test-key-32char")
    payload = f"bob:0:{int(time.time())}:nonce1234"
    sig = hmac.new(b"test-key-32char", payload.encode(), hashlib.sha256).hexdigest()[:32]
    token = f"{payload}:{sig}"
    assert validate_session(token) is None


# ── Concurrent bump race (BC-124) ───────────────────────────────────────────


def test_bump_session_version_concurrent_race(tmp_path):
    """Concurrent bumps from multiple threads must not lose updates.

    Uses INSERT … ON CONFLICT … DO UPDATE … RETURNING so every caller
    sees a distinct, monotonically increasing version.
    """
    db = tmp_path / "race.sqlite3"
    init_schema(db)

    versions = []
    errors = []

    def bump():
        try:
            v = bump_session_version(db, "alice")
            versions.append(v)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=bump) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    assert len(versions) == 10
    # All versions should be unique and monotonically assigned
    assert sorted(versions) == list(range(1, 11))
    # Final stored version should be the max
    final = get_session_version(db, "alice")
    assert final == 10
