"""The legacy no-role-map lists are enforced as documented (plan 057 W6).

Found while building the W6 authorization matrix: with no role map every
directory user got ``AuthContext.full_access``, so ``CERT_WATCH_ADMINS`` (README:
"Usernames allowed to reach /settings") restricted nothing, and a user outside
``CERT_WATCH_WRITE_USERS`` could mint an API key -- including a write-scoped one
-- and write with it. Now, with no role map:

- ``CERT_WATCH_ADMINS`` set: admin requires membership;
- ``CERT_WATCH_WRITE_USERS`` set: writes require membership (listed admins
  always write);
- neither set: every authenticated user is full access (unchanged).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient


def _app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, writers: str, admins: str):
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
    for var, value in (("CERT_WATCH_WRITE_USERS", writers), ("CERT_WATCH_ADMINS", admins)):
        if value:
            monkeypatch.setenv(var, value)
        else:
            monkeypatch.delenv(var, raising=False)
    return create_app(settings=Settings.from_env())


def _login(client: TestClient, username: str) -> None:
    from cert_watch.auth import SESSION_COOKIE, create_session

    client.cookies.set(SESSION_COOKIE, create_session(username, client.app.state.security))


def _api_keys(tmp_path: Path) -> list:
    from cert_watch.database.api_keys import SqliteApiKeyRepository

    return SqliteApiKeyRepository(tmp_path / "cert-watch.sqlite3").list_keys()


@pytest.mark.parametrize("user", ["rita", "will"])  # a reader; a writer who is not an admin
@pytest.mark.parametrize("scope", ["read", "write", "admin"])
def test_unlisted_legacy_user_cannot_mint_any_api_key(tmp_path, monkeypatch, user, scope):
    with TestClient(_app(tmp_path, monkeypatch, writers="will", admins="alan")) as client:
        _login(client, user)
        r = client.post("/api/api-keys", json={"name": "k", "scope": scope})
        assert r.status_code == 403
        assert r.json()["detail"] == "admin required"
        r = client.post(
            "/settings/api-keys", data={"name": "k", "scope": scope}, follow_redirects=False,
        )
        assert r.status_code == 303
        assert r.headers["location"] == "/settings?error=admin%20required"
    assert _api_keys(tmp_path) == []


_SETTINGS_REFUSED = "/?error=Settings%20are%20available%20to%20administrators%20only."


def test_unlisted_legacy_user_cannot_reach_settings(tmp_path, monkeypatch):
    with TestClient(_app(tmp_path, monkeypatch, writers="will", admins="alan")) as client:
        _login(client, "will")  # a writer, but not in CERT_WATCH_ADMINS
        r = client.get("/settings/roles", follow_redirects=False)
    assert r.status_code == 303
    # A settings *page* refusal must leave /settings: bouncing back to it
    # (which is admin-only too) looped forever (#113 item 2).
    assert r.headers["location"] == _SETTINGS_REFUSED


@pytest.mark.parametrize(
    "path", ["/settings", "/settings?error=admin%20required", "/settings/tags"]
)
def test_non_admin_settings_visit_ends_on_home_with_message(tmp_path, monkeypatch, path):
    """#113 item 2: a viewer opening /settings got an endless 303 loop."""
    with TestClient(_app(tmp_path, monkeypatch, writers="will", admins="alan")) as client:
        _login(client, "rita")  # a reader
        r = client.get(path, follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == _SETTINGS_REFUSED
        final = client.get(r.headers["location"], follow_redirects=False)
    assert final.status_code == 200
    assert "Settings are available to administrators only." in final.text


def test_non_admin_settings_post_bounce_does_not_loop(tmp_path, monkeypatch):
    """A refused settings form still bounces to /settings (the authz matrix
    pins that), and following it ends on Home instead of looping."""
    with TestClient(_app(tmp_path, monkeypatch, writers="will", admins="alan")) as client:
        _login(client, "will")
        r = client.post("/settings/api-keys", data={"name": "k"}, follow_redirects=True)
    assert r.status_code == 200
    assert r.url.path == "/"
    assert "Settings are available to administrators only." in r.text


def test_listed_admin_reaches_settings_and_mints_a_key(tmp_path, monkeypatch):
    with TestClient(_app(tmp_path, monkeypatch, writers="will", admins="alan")) as client:
        _login(client, "alan")
        assert client.get("/settings/roles", follow_redirects=False).status_code == 200
        r = client.post("/api/api-keys", json={"name": "k", "scope": "read"})
    assert r.status_code == 201
    assert len(_api_keys(tmp_path)) == 1


def test_write_users_half_holds_reader_cannot_write(tmp_path, monkeypatch):
    from cert_watch.database import SqliteHostRepository, init_schema

    init_schema(tmp_path / "cert-watch.sqlite3")
    host_id = SqliteHostRepository(tmp_path / "cert-watch.sqlite3").add("h.example.com")
    with TestClient(_app(tmp_path, monkeypatch, writers="will", admins="alan")) as client:
        _login(client, "rita")
        r = client.patch(f"/api/hosts/{host_id}/notes", json={"notes": "x"})
        assert r.status_code == 403
        _login(client, "alan")  # listed admins always write
        assert client.patch(f"/api/hosts/{host_id}/notes", json={"notes": "x"}).status_code == 200


def test_no_lists_and_no_role_map_is_still_full_access(tmp_path, monkeypatch):
    with TestClient(_app(tmp_path, monkeypatch, writers="", admins="")) as client:
        _login(client, "anyone")
        assert client.get("/settings/roles", follow_redirects=False).status_code == 200
        r = client.post("/api/api-keys", json={"name": "k", "scope": "write"})
    assert r.status_code == 201


# ---------- admin implies write: CERT_WATCH_WRITE_USERS set, CERT_WATCH_ADMINS not ----------


@pytest.mark.parametrize("scope", ["read", "write", "admin"])
def test_non_writer_cannot_administer_when_only_write_users_is_set(tmp_path, monkeypatch, scope):
    """A user who cannot write data can never administer or mint keys."""
    with TestClient(_app(tmp_path, monkeypatch, writers="will", admins="")) as client:
        _login(client, "rita")
        r = client.post("/api/api-keys", json={"name": "k", "scope": scope})
        assert r.status_code == 403
        assert r.json()["detail"] == "admin required"
        r = client.post(
            "/settings/api-keys", data={"name": "k", "scope": scope}, follow_redirects=False,
        )
        assert r.headers["location"] == "/settings?error=admin%20required"
        r = client.get("/settings/roles", follow_redirects=False)
        assert r.headers["location"] == _SETTINGS_REFUSED
    assert _api_keys(tmp_path) == []


def test_writer_administers_when_only_write_users_is_set(tmp_path, monkeypatch):
    with TestClient(_app(tmp_path, monkeypatch, writers="will", admins="")) as client:
        _login(client, "will")
        assert client.get("/settings/roles", follow_redirects=False).status_code == 200
        r = client.post("/api/api-keys", json={"name": "k", "scope": "read"})
    assert r.status_code == 201
