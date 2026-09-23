"""CERT_WATCH_ADMINS does not restrict admin under the no-role-map path.

Found while building the W6 authorization matrix
(tests/test_authz_characterization.py). README documents ``CERT_WATCH_ADMINS``
as "Usernames allowed to reach /settings" and ``_admin_allowed`` calls the list
"an explicit allowlist only". But with no role map, ``build_auth_context``
gives every directory user ``AuthContext.full_access`` -- ``is_admin`` is True
-- and ``_admin_allowed`` consults the list only when ``is_admin`` is False.
So every directory user is admin: a user who is *not* in
``CERT_WATCH_WRITE_USERS`` (read-only for data) can still mint a write-scoped
API key and write with it, and can change auth settings, roles and users.

Left failing (strict xfail) rather than fixed inside the W6 refactor, which
must not change an authorization decision; the fix is an owner decision about
what "no role map = full access" means once CERT_WATCH_ADMINS is set.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient


def _app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from cert_watch.app import create_app
    from cert_watch.auth import _scrypt_hash
    from cert_watch.config import Settings
    from cert_watch.database import init_schema, kv_set

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    kv_set(db, "setup_complete", "1")
    kv_set(db, "local_admin_user", "admin")
    kv_set(db, "local_admin_password_hash", _scrypt_hash("testpassword", n=2**4, r=1, p=1))
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CERT_WATCH_COOKIE_SECURE", "0")
    monkeypatch.delenv("CERT_WATCH_ROLE_MAP", raising=False)
    monkeypatch.setenv("CERT_WATCH_WRITE_USERS", "will")
    monkeypatch.setenv("CERT_WATCH_ADMINS", "alan")
    return create_app(settings=Settings.from_env())


def _login(client: TestClient, username: str) -> None:
    from cert_watch.auth import SESSION_COOKIE, create_session

    client.cookies.set(SESSION_COOKIE, create_session(username, client.app.state.security))


@pytest.mark.xfail(
    strict=True,
    reason="CERT_WATCH_ADMINS is ignored without a role map (full_access is_admin)",
)
def test_read_only_legacy_user_cannot_mint_a_write_api_key(tmp_path, monkeypatch):
    with TestClient(_app(tmp_path, monkeypatch)) as client:
        _login(client, "rita")  # neither a writer nor a listed admin
        r = client.post("/api/api-keys", json={"name": "k", "scope": "write"})
    assert r.status_code == 403


@pytest.mark.xfail(
    strict=True,
    reason="CERT_WATCH_ADMINS is ignored without a role map (full_access is_admin)",
)
def test_unlisted_legacy_user_cannot_reach_settings(tmp_path, monkeypatch):
    with TestClient(_app(tmp_path, monkeypatch)) as client:
        _login(client, "will")  # a writer, but not in CERT_WATCH_ADMINS
        r = client.get("/settings/roles", follow_redirects=False)
    assert r.status_code == 303
    assert "admin" in r.headers["location"]
