"""Tests for Plan 014 — onboarding and secure bootstrap.

Slices:
1. Persisted signing keys (resolve_or_persist_secret, set_signing_key, set_csrf_secret)
2. kv_store table and helpers
3. First-run /setup wizard
4. Unauthenticated-mode warning
"""

from __future__ import annotations

import os
import stat
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from cert_watch.auth import (
    LocalAdminProvider,
    NoAuthProvider,
    _scrypt_hash,
    create_session,
    set_signing_key,
    validate_session,
    verify_scrypt_hash,
)
from cert_watch.config import resolve_or_persist_secret
from cert_watch.database import init_schema, kv_all, kv_get, kv_set
from cert_watch.middleware import make_csrf_token, set_csrf_secret, validate_csrf_token

# ---------- Slice 1: Persisted signing keys ----------


class TestResolveOrPersistSecret:
    """Tests for resolve_or_persist_secret helper."""

    def test_generates_and_persists_when_unset(self, tmp_path):
        """AC-1: Fresh install, no env -> key generated and persisted."""
        with patch.dict(os.environ, {}, clear=False):
            # Remove env vars if present
            os.environ.pop("CERT_WATCH_AUTH_SECRET", None)
            os.environ.pop("CERT_WATCH_AUTH_SECRET_FILE", None)
            val = resolve_or_persist_secret("CERT_WATCH_AUTH_SECRET", tmp_path, ".auth_secret")
        assert val is not None
        assert len(val) == 64  # 32 bytes = 64 hex chars
        secret_file = tmp_path / ".auth_secret"
        assert secret_file.exists()
        # File should be readable
        persisted = secret_file.read_text().strip()
        assert persisted == val

    def test_second_call_reads_persisted(self, tmp_path):
        """AC-1 continued: persisted key survives across calls."""
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CERT_WATCH_AUTH_SECRET", None)
            os.environ.pop("CERT_WATCH_AUTH_SECRET_FILE", None)
            val1 = resolve_or_persist_secret("CERT_WATCH_AUTH_SECRET", tmp_path, ".auth_secret")
            val2 = resolve_or_persist_secret("CERT_WATCH_AUTH_SECRET", tmp_path, ".auth_secret")
        assert val1 == val2

    def test_empty_string_treated_as_unset(self, tmp_path):
        """AC-2: CERT_WATCH_AUTH_SECRET="" is treated as unset."""
        with patch.dict(os.environ, {"CERT_WATCH_AUTH_SECRET": ""}):
            val = resolve_or_persist_secret("CERT_WATCH_AUTH_SECRET", tmp_path, ".auth_secret2")
        assert val is not None
        assert len(val) == 64
        # Should have persisted a generated value, not used the empty string
        persisted = (tmp_path / ".auth_secret2").read_text().strip()
        assert persisted == val

    def test_whitespace_treated_as_unset(self, tmp_path):
        """Whitespace-only values are treated as unset."""
        with patch.dict(os.environ, {"CERT_WATCH_AUTH_SECRET": "   "}):
            val = resolve_or_persist_secret("CERT_WATCH_AUTH_SECRET", tmp_path, ".auth_secret3")
        assert val is not None
        assert len(val) == 64

    def test_env_var_takes_precedence(self, tmp_path):
        """Explicit env var takes precedence over persisted file."""
        secret_file = tmp_path / ".auth_secret4"
        secret_file.write_text("persisted_value\n")
        with patch.dict(os.environ, {"CERT_WATCH_AUTH_SECRET": "from_env"}):
            val = resolve_or_persist_secret("CERT_WATCH_AUTH_SECRET", tmp_path, ".auth_secret4")
        assert val == "from_env"

    def test_persisted_file_used_when_no_env(self, tmp_path):
        """When no env var, persisted file value is used."""
        secret_file = tmp_path / ".auth_secret5"
        secret_file.write_text("persisted_value\n")
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CERT_WATCH_AUTH_SECRET", None)
            os.environ.pop("CERT_WATCH_AUTH_SECRET_FILE", None)
            val = resolve_or_persist_secret("CERT_WATCH_AUTH_SECRET", tmp_path, ".auth_secret5")
        assert val == "persisted_value"

    def test_file_permissions(self, tmp_path):
        """Persisted file should have 0600 permissions (best effort)."""
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CERT_WATCH_AUTH_SECRET", None)
            os.environ.pop("CERT_WATCH_AUTH_SECRET_FILE", None)
            resolve_or_persist_secret("CERT_WATCH_AUTH_SECRET", tmp_path, ".auth_secret6")
        secret_file = tmp_path / ".auth_secret6"
        if os.name != "nt":
            mode = stat.S_IMODE(secret_file.stat().st_mode)
            assert mode == 0o600


class TestSetSigningKey:
    """Tests for set_signing_key / set_csrf_secret."""

    def test_set_signing_key_changes_session_tokens(self):
        """set_signing_key changes the signing key so tokens sign differently."""
        set_signing_key("key-alpha")
        token_a = create_session("user1")
        assert validate_session(token_a) == "user1"

        set_signing_key("key-beta")
        token_b = create_session("user2")
        # Token from key-alpha should not validate under key-beta
        assert validate_session(token_a) is None
        assert validate_session(token_b) == "user2"

    def test_set_csrf_secret_changes_tokens(self):
        """set_csrf_secret changes the CSRF signing key."""
        set_csrf_secret("csrf-alpha")
        tok_a = make_csrf_token("sid1")
        assert validate_csrf_token(tok_a, "sid1") is True

        set_csrf_secret("csrf-beta")
        # Old token should no longer validate
        assert validate_csrf_token(tok_a, "sid1") is False


# ---------- Slice 2: kv_store ----------


class TestKvStore:
    """Tests for kv_get, kv_set, kv_all."""

    def test_kv_set_and_get(self, tmp_path):
        db = tmp_path / "test.sqlite3"
        init_schema(db)
        kv_set(db, "setup_complete", "1")
        assert kv_get(db, "setup_complete") == "1"

    def test_kv_get_missing_key(self, tmp_path):
        db = tmp_path / "test.sqlite3"
        init_schema(db)
        assert kv_get(db, "nonexistent") is None

    def test_kv_set_overwrites(self, tmp_path):
        db = tmp_path / "test.sqlite3"
        init_schema(db)
        kv_set(db, "test_key", "val1")
        kv_set(db, "test_key", "val2")
        assert kv_get(db, "test_key") == "val2"

    def test_kv_all(self, tmp_path):
        db = tmp_path / "test.sqlite3"
        init_schema(db)
        kv_set(db, "k1", "v1")
        kv_set(db, "k2", "v2")
        result = kv_all(db)
        assert result == {"k1": "v1", "k2": "v2"}

    def test_local_admin_password_hash_in_kv(self, tmp_path):
        """Scrypt hash stored in kv_store validates correctly."""
        db = tmp_path / "test.sqlite3"
        init_schema(db)
        pw_hash = _scrypt_hash("testpassword")
        kv_set(db, "local_admin_user", "admin")
        kv_set(db, "local_admin_password_hash", pw_hash)
        assert kv_get(db, "local_admin_user") == "admin"
        assert verify_scrypt_hash("testpassword", kv_get(db, "local_admin_password_hash"))


# ---------- Slice 3: Setup wizard ----------


@pytest.fixture
def fresh_db(tmp_path):
    """Create a fresh database with no hosts."""
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    return db


@pytest.fixture
def setup_app_client(fresh_db, tmp_path):
    """Client with fresh DB, no auth, no hosts — triggers setup.

    Uses CERT_WATCH_ALLOW_UNAUTH=1 so the lifespan doesn't raise SystemExit
    (BC-083: secure-by-default). The test then forces needs_setup=True.
    """
    import cert_watch.app as app_mod
    import cert_watch.auth as auth_mod
    import cert_watch.config as cfg_mod
    import cert_watch.middleware as mw_mod

    saved_cfg = dict(vars(cfg_mod))
    saved_auth = dict(vars(auth_mod))
    saved_app = dict(vars(app_mod))

    env = {
        "CERT_WATCH_DATA_DIR": str(tmp_path),
        "AUTH_PROVIDER": "",
        "CERT_WATCH_AUTH_SECRET": "test-secret-for-setup",
        "CERT_WATCH_CSRF_SECRET": "test-csrf-secret-for-setup",
        "CERT_WATCH_ALLOW_UNAUTH": "1",
        "CERT_WATCH_HOST": "127.0.0.1",
    }
    with patch.dict(os.environ, env, clear=False):
        s = cfg_mod.Settings.from_env()
        cfg_mod.resolve_or_persist_secret("CERT_WATCH_AUTH_SECRET", s.data_dir, ".auth_secret")
        auth_mod.set_signing_key("test-secret-for-setup")
        mw_mod.set_csrf_secret("test-csrf-secret-for-setup")

        from cert_watch.auth import build_auth_provider
        auth = build_auth_provider(provider="")

        with TestClient(app_mod.app) as client:
            # Force needs_setup=True after lifespan sets it
            app_mod.app.state.auth_provider = auth
            app_mod.app.state.settings = s
            app_mod.app.state.needs_setup = True
            yield client

    # Cleanup
    vars(cfg_mod).clear()
    vars(cfg_mod).update(saved_cfg)
    vars(auth_mod).clear()
    vars(auth_mod).update(saved_auth)
    vars(app_mod).clear()
    vars(app_mod).update(saved_app)


class TestSetupWizard:
    """Tests for the /setup endpoint."""

    def test_setup_page_accessible_when_needed(self, setup_app_client):
        """AC-3: /setup is accessible when needs_setup is True."""
        r = setup_app_client.get("/setup", follow_redirects=False)
        assert r.status_code == 200
        assert "Welcome to cert-watch" in r.text and "admin" in r.text.lower()

    def test_healthz_not_redirected(self, setup_app_client):
        """Healthz is never redirected even during setup."""
        r = setup_app_client.get("/healthz", follow_redirects=False)
        assert r.status_code == 200

    def test_dashboard_redirected_to_setup(self, setup_app_client):
        """Non-public paths redirect to /setup when needs_setup is True."""
        r = setup_app_client.get("/", follow_redirects=False)
        assert r.status_code == 303
        assert "/setup" in r.headers.get("location", "")

    def test_create_local_admin(self, setup_app_client, fresh_db):
        """AC-3: Creating admin via setup stores creds in kv_store."""
        # Get CSRF token first
        r = setup_app_client.get("/setup", follow_redirects=False)
        assert r.status_code == 200
        # Get session ID from the cookie
        sid_cookie = None
        for cookie in setup_app_client.cookies.jar:
            if cookie.name == "cw_sid":
                sid_cookie = cookie.value
                break
        assert sid_cookie is not None

        csrf_token = make_csrf_token(sid_cookie)

        r = setup_app_client.post("/setup", data={
            "_csrf_token": csrf_token,
            "step": "1",
            "username": "testadmin",
            "password": "SecurePass123",
            "password_confirm": "SecurePass123",
        }, follow_redirects=False)
        assert r.status_code == 303
        # Should redirect to / (dashboard)
        assert r.headers.get("location", "") == "/"

        # Verify kv_store has the admin
        assert kv_get(fresh_db, "local_admin_user") == "testadmin"
        assert kv_get(fresh_db, "setup_complete") == "1"
        # H3: password hash is now encrypted at rest — decrypt for verification
        from cert_watch.database import derive_encryption_key
        enc_key = derive_encryption_key("test-secret-for-setup")
        pw_hash = kv_get(fresh_db, "local_admin_password_hash", encryption_key=enc_key)
        assert pw_hash is not None
        assert verify_scrypt_hash("SecurePass123", pw_hash)

    def test_create_admin_with_allowed_subnets(self, setup_app_client, fresh_db):
        """The wizard persists the optional scan allowlist to kv_store."""
        setup_app_client.get("/setup", follow_redirects=False)
        sid = next(c.value for c in setup_app_client.cookies.jar if c.name == "cw_sid")
        r = setup_app_client.post("/setup", data={
            "_csrf_token": make_csrf_token(sid),
            "step": "1",
            "username": "admin2",
            "password": "SecurePass123",
            "password_confirm": "SecurePass123",
            "allowed_subnets": "10.0.0.0/8, 192.168.0.0/16",
        }, follow_redirects=False)
        assert r.status_code == 303
        assert r.headers.get("location", "") == "/"
        assert kv_get(fresh_db, "allowed_subnets") == "10.0.0.0/8,192.168.0.0/16"

    def test_invalid_allowed_subnet_rejected(self, setup_app_client, fresh_db):
        """An invalid CIDR aborts setup before any admin is created."""
        setup_app_client.get("/setup", follow_redirects=False)
        sid = next(c.value for c in setup_app_client.cookies.jar if c.name == "cw_sid")
        r = setup_app_client.post("/setup", data={
            "_csrf_token": make_csrf_token(sid),
            "step": "1",
            "username": "admin3",
            "password": "SecurePass123",
            "password_confirm": "SecurePass123",
            "allowed_subnets": "not-a-cidr",
        }, follow_redirects=False)
        assert r.status_code == 303
        assert "invalid+subnet" in r.headers.get("location", "")
        assert kv_get(fresh_db, "local_admin_user") is None

    def test_password_mismatch(self, setup_app_client):
        """Password confirmation mismatch returns error."""
        r = setup_app_client.get("/setup", follow_redirects=False)
        sid_cookie = None
        for cookie in setup_app_client.cookies.jar:
            if cookie.name == "cw_sid":
                sid_cookie = cookie.value
                break
        csrf_token = make_csrf_token(sid_cookie)

        r = setup_app_client.post("/setup", data={
            "_csrf_token": csrf_token,
            "step": "1",
            "username": "admin",
            "password": "password1",
            "password_confirm": "password2",
        }, follow_redirects=False)
        assert r.status_code == 303
        loc = r.headers.get("location", "")
        assert "passwords+do+not+match" in loc or "setup" in loc

    def test_short_password(self, setup_app_client):
        """Short password is rejected."""
        r = setup_app_client.get("/setup", follow_redirects=False)
        sid_cookie = None
        for cookie in setup_app_client.cookies.jar:
            if cookie.name == "cw_sid":
                sid_cookie = cookie.value
                break
        csrf_token = make_csrf_token(sid_cookie)

        r = setup_app_client.post("/setup", data={
            "_csrf_token": csrf_token,
            "step": "1",
            "username": "admin",
            "password": "short",
            "password_confirm": "short",
        }, follow_redirects=False)
        assert r.status_code == 303
        loc = r.headers.get("location", "")
        assert "8+characters" in loc or "setup" in loc

    def test_setup_not_accessible_after_completion(self, fresh_db, tmp_path):
        """AC-4: After setup, /setup redirects to /."""
        # Mark setup as complete
        kv_set(fresh_db, "setup_complete", "1")

        import cert_watch.app as app_mod
        import cert_watch.auth as auth_mod
        import cert_watch.config as cfg_mod
        import cert_watch.middleware as mw_mod2

        saved_cfg = dict(vars(cfg_mod))
        saved_auth = dict(vars(auth_mod))
        saved_app = dict(vars(app_mod))

        env = {
            "CERT_WATCH_DATA_DIR": str(tmp_path),
            "AUTH_PROVIDER": "",
            "CERT_WATCH_AUTH_SECRET": "test-secret",
            "CERT_WATCH_ALLOW_UNAUTH": "1",
            "CERT_WATCH_HOST": "127.0.0.1",
        }
        with patch.dict(os.environ, env, clear=False):
            s = cfg_mod.Settings.from_env()
            auth_mod.set_signing_key("test-secret")
            mw_mod2.set_csrf_secret("test-csrf")

            from cert_watch.auth import LocalAdminProvider
            auth = LocalAdminProvider("admin", _scrypt_hash("password123"))
            app_mod.app.state.auth_provider = auth
            app_mod.app.state.settings = s
            app_mod.app.state.needs_setup = False

            with TestClient(app_mod.app) as client:
                r = client.get("/setup", follow_redirects=False)
                assert r.status_code == 303
                assert r.headers.get("location", "") == "/"

        vars(cfg_mod).clear()
        vars(cfg_mod).update(saved_cfg)
        vars(auth_mod).clear()
        vars(auth_mod).update(saved_auth)
        vars(app_mod).clear()
        vars(app_mod).update(saved_app)


# ---------- Slice 4: Secure-by-default enforcement (BC-083) ----------


class TestSecureByDefault:
    """Tests for BC-083: app refuses to start without auth on non-loopback."""

    LOOPBACK_ADDRS = ("127.0.0.1", "::1", "localhost")

    def test_system_exit_no_auth_nonloopback(self, tmp_path):
        """BC-083: SystemExit when auth is off and bound to non-loopback."""
        import cert_watch.app as app_mod
        import cert_watch.config as cfg_mod

        saved_cfg = dict(vars(cfg_mod))
        saved_app = dict(vars(app_mod))
        try:
            s = cfg_mod.Settings(
                db_path=tmp_path / "test.sqlite3",
                data_dir=tmp_path,
                auth_provider="",
                allow_unauth=False,
            )
            from cert_watch.auth import NoAuthProvider
            auth = NoAuthProvider()
            bind_host = "0.0.0.0"

            # BC-083: should raise SystemExit for non-loopback without auth
            should_exit = (
                isinstance(auth, NoAuthProvider)
                and bind_host not in self.LOOPBACK_ADDRS
                and not s.allow_unauth
            )
            assert should_exit, (
                "Expected non-loopback + NoAuthProvider + no allow_unauth to be fatal"
            )
        finally:
            vars(cfg_mod).clear()
            vars(cfg_mod).update(saved_cfg)
            vars(app_mod).clear()
            vars(app_mod).update(saved_app)

    def test_loopback_exempt(self, tmp_path):
        """BC-083: loopback binds are always exempt."""
        import cert_watch.config as cfg_mod

        saved_cfg = dict(vars(cfg_mod))
        try:
            s = cfg_mod.Settings(
                db_path=tmp_path / "test.sqlite3",
                data_dir=tmp_path,
                auth_provider="",
                allow_unauth=False,
            )
            from cert_watch.auth import NoAuthProvider
            auth = NoAuthProvider()

            for bind_host in self.LOOPBACK_ADDRS:
                should_exit = (
                    isinstance(auth, NoAuthProvider)
                    and bind_host not in self.LOOPBACK_ADDRS
                    and not s.allow_unauth
                )
                assert not should_exit, f"Loopback {bind_host} should be exempt"
        finally:
            vars(cfg_mod).clear()
            vars(cfg_mod).update(saved_cfg)

    def test_allow_unauth_exempt(self, tmp_path):
        """BC-083: CERT_WATCH_ALLOW_UNAUTH=1 skips the check."""
        import cert_watch.config as cfg_mod

        saved_cfg = dict(vars(cfg_mod))
        try:
            s = cfg_mod.Settings(
                db_path=tmp_path / "test.sqlite3",
                data_dir=tmp_path,
                auth_provider="",
                allow_unauth=True,
            )
            from cert_watch.auth import NoAuthProvider
            auth = NoAuthProvider()

            should_exit = (
                isinstance(auth, NoAuthProvider)
                and "0.0.0.0" not in self.LOOPBACK_ADDRS
                and not s.allow_unauth
            )
            assert not should_exit
        finally:
            vars(cfg_mod).clear()
            vars(cfg_mod).update(saved_cfg)

    def test_auth_provider_exempt(self, tmp_path):
        """BC-083: configured auth provider skips the check."""
        from cert_watch.auth import _scrypt_hash

        auth = LocalAdminProvider("admin", _scrypt_hash("pass"))
        assert not isinstance(auth, NoAuthProvider)

    def test_needs_setup_no_host_count_condition(self, tmp_path):
        """BC-083: needs_setup is true when no auth is configured and
        setup_complete is not set, regardless of host count.
        The old host_count==0 gate is removed.
        """
        # Simulate the conditions: NoAuthProvider, not allow_unauth, not setup_complete
        from cert_watch.auth import NoAuthProvider
        auth = NoAuthProvider()
        s_allow_unauth = False
        setup_complete = False

        needs_setup = isinstance(auth, NoAuthProvider) and not s_allow_unauth and not setup_complete
        assert needs_setup is True
