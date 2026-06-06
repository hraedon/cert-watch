"""Tests for API-key auth (Plan 039 / BC-104).

Covers the repository (create/verify/revoke/list, hashing, scope validation)
and the middleware dependencies (require_auth / require_write / require_admin)
authenticating via an ``Authorization: Bearer cwk_…`` token.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import Request
from fastapi.exceptions import HTTPException

from cert_watch.database import init_schema
from cert_watch.database.api_keys import SqliteApiKeyRepository, hash_token
from cert_watch.middleware import (
    authenticate_api_key,
    require_admin,
    require_auth,
    require_write,
)

# ── repository ───────────────────────────────────────────────────────────


@pytest.fixture
def repo(tmp_path):
    db = tmp_path / "keys.sqlite3"
    init_schema(db)
    return SqliteApiKeyRepository(db)


def test_create_returns_prefixed_token_and_stores_only_hash(repo):
    entry, raw = repo.create_key("ci", "write")
    assert raw.startswith("cwk_")
    assert entry.scope == "write"
    assert entry.name == "ci"
    # Only the hash is persisted; the raw token never appears in the row.
    with repo_conn(repo) as conn:
        row = conn.execute("SELECT key_hash FROM api_keys WHERE id = ?", (entry.id,)).fetchone()
    assert row["key_hash"] == hash_token(raw)
    assert row["key_hash"] != raw


def test_verify_valid_token(repo):
    _, raw = repo.create_key("ci", "read")
    auth = repo.verify_key(raw)
    assert auth is not None
    assert auth.scope == "read"
    assert auth.name == "ci"


def test_verify_unknown_token_returns_none(repo):
    repo.create_key("ci", "read")
    assert repo.verify_key("cwk_does-not-exist") is None
    assert repo.verify_key("") is None


def test_verify_updates_last_used(repo):
    entry, raw = repo.create_key("ci", "read")
    assert repo.list_keys()[0].last_used_at is None
    repo.verify_key(raw)
    refreshed = next(k for k in repo.list_keys() if k.id == entry.id)
    assert refreshed.last_used_at is not None


def test_revoke_then_verify_fails(repo):
    entry, raw = repo.create_key("ci", "admin")
    assert repo.revoke_key(entry.id) is True
    assert repo.verify_key(raw) is None
    # Revoking again is a no-op (already revoked).
    assert repo.revoke_key(entry.id) is False


def test_list_excludes_revoked_by_default(repo):
    e1, _ = repo.create_key("live", "read")
    e2, _ = repo.create_key("dead", "read")
    repo.revoke_key(e2.id)
    ids = {k.id for k in repo.list_keys()}
    assert e1.id in ids and e2.id not in ids
    ids_all = {k.id for k in repo.list_keys(include_revoked=True)}
    assert e2.id in ids_all


@pytest.mark.parametrize("name,scope", [("", "read"), ("ok", "superuser")])
def test_create_rejects_bad_input(repo, name, scope):
    with pytest.raises(ValueError):
        repo.create_key(name, scope)


def repo_conn(repo):
    from cert_watch.database.connection import _connect

    return _connect(repo.db_path)


# ── dependency integration ────────────────────────────────────────────────


class _Provider:
    """A non-NoAuth provider so the auth path is exercised."""


def _make_request(db_path, *, bearer=None, role_map=None) -> Request:
    headers = []
    if bearer is not None:
        headers.append((b"authorization", f"Bearer {bearer}".encode()))
    settings = SimpleNamespace(
        db_path=str(db_path),
        role_map=role_map or {},
        write_users=[],
        admin_users=[],
    )
    app = SimpleNamespace(
        state=SimpleNamespace(auth_provider=_Provider(), settings=settings, security=None)
    )
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/test",
        "headers": headers,
        "app": app,
        "client": ("127.0.0.1", 12345),
        "query_string": b"",
        "state": {},
    }
    return Request(scope)


@pytest.fixture
def seeded(tmp_path):
    db = tmp_path / "deps.sqlite3"
    init_schema(db)
    return db, SqliteApiKeyRepository(db)


@pytest.mark.anyio
async def test_require_auth_accepts_api_key(seeded):
    db, repo = seeded
    _, raw = repo.create_key("svc", "read")
    request = _make_request(db, bearer=raw)
    assert await require_auth(request) == "svc"
    assert request.state.api_key_auth is True


@pytest.mark.anyio
async def test_require_auth_rejects_bad_api_key(seeded):
    db, _ = seeded
    request = _make_request(db, bearer="cwk_bogus")
    with pytest.raises(HTTPException) as exc:
        await require_auth(request)
    assert exc.value.status_code == 401


@pytest.mark.anyio
async def test_authenticate_api_key_ignores_non_cwk_bearer(seeded):
    db, _ = seeded
    request = _make_request(db, bearer="some-other-token")
    assert authenticate_api_key(request, db) is None


@pytest.mark.anyio
async def test_require_write_allows_write_scope_without_csrf(seeded):
    db, repo = seeded
    _, raw = repo.create_key("svc", "write")
    request = _make_request(db, bearer=raw)
    # No CSRF token on the request — must still succeed for the bearer path.
    assert await require_write(request) == "svc"


@pytest.mark.anyio
async def test_require_write_denies_read_scope(seeded):
    db, repo = seeded
    _, raw = repo.create_key("svc", "read")
    request = _make_request(db, bearer=raw)
    with pytest.raises(HTTPException) as exc:
        await require_write(request)
    assert exc.value.status_code == 403


@pytest.mark.anyio
async def test_require_admin_requires_admin_scope(seeded):
    db, repo = seeded
    _, write_raw = repo.create_key("svc", "write")
    _, admin_raw = repo.create_key("root", "admin")

    write_req = _make_request(db, bearer=write_raw)
    with pytest.raises(HTTPException) as exc:
        await require_admin(write_req)
    assert exc.value.status_code == 403

    admin_req = _make_request(db, bearer=admin_raw)
    assert await require_admin(admin_req) == "root"


# ── HTTP end-to-end (routing + middleware mounted) ─────────────────────────


def test_bearer_auth_http_end_to_end(reload_app):
    """A bearer token authenticates /api/* with no session cookie (Plan 039)."""
    from fastapi.testclient import TestClient

    from cert_watch.auth.local_admin import _scrypt_hash
    from cert_watch.config import Settings

    app_mod = reload_app(
        CERT_WATCH_LOCAL_ADMIN_USER="admin",
        CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH=_scrypt_hash("pw-for-tests-1"),
    )
    db = Settings.from_env().db_path
    init_schema(db)
    repo = SqliteApiKeyRepository(db)
    _, read_raw = repo.create_key("reader", "read")
    _, write_raw = repo.create_key("writer", "write")
    revoked_entry, revoked_raw = repo.create_key("dead", "write")
    repo.revoke_key(revoked_entry.id)

    with TestClient(app_mod.app) as client:
        # Valid read key, no cookie → 200.
        ok = client.get("/api/hosts", headers={"Authorization": f"Bearer {read_raw}"})
        assert ok.status_code == 200

        # Unknown / revoked tokens → 401.
        assert client.get(
            "/api/hosts", headers={"Authorization": "Bearer cwk_nope"}
        ).status_code == 401
        assert client.get(
            "/api/hosts", headers={"Authorization": f"Bearer {revoked_raw}"}
        ).status_code == 401

        # Read scope cannot reach a write route → 403; write scope can (404 here
        # only because the host doesn't exist, i.e. it passed the auth gate).
        denied = client.patch(
            "/api/hosts/nope/owner",
            headers={"Authorization": f"Bearer {read_raw}"},
            json={"owner_name": "x"},
        )
        assert denied.status_code == 403
        allowed = client.patch(
            "/api/hosts/nope/owner",
            headers={"Authorization": f"Bearer {write_raw}"},
            json={"owner_name": "x"},
        )
        assert allowed.status_code != 403


def test_api_keys_management_routes(reload_app):
    """The /api/api-keys CRUD routes: admin-gated, create/list/revoke."""
    from fastapi.testclient import TestClient

    from cert_watch.auth.local_admin import _scrypt_hash
    from cert_watch.config import Settings

    app_mod = reload_app(
        CERT_WATCH_LOCAL_ADMIN_USER="admin",
        CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH=_scrypt_hash("pw-for-tests-1"),
    )
    db = Settings.from_env().db_path
    init_schema(db)
    repo = SqliteApiKeyRepository(db)
    _, admin_raw = repo.create_key("bootstrap-admin", "admin")
    _, read_raw = repo.create_key("reader", "read")
    admin_hdr = {"Authorization": f"Bearer {admin_raw}"}

    with TestClient(app_mod.app) as client:
        # A non-admin (read) key cannot manage keys.
        read_hdr = {"Authorization": f"Bearer {read_raw}"}
        assert client.get("/api/api-keys", headers=read_hdr).status_code == 403

        # Admin creates a key and gets the raw token exactly once.
        created = client.post(
            "/api/api-keys", headers=admin_hdr, json={"name": "deploy", "scope": "write"}
        )
        assert created.status_code == 201
        body = created.json()
        assert body["token"].startswith("cwk_")
        assert body["scope"] == "write"
        new_id = body["id"]

        # Bad scope is rejected.
        assert client.post(
            "/api/api-keys", headers=admin_hdr, json={"name": "x", "scope": "root"}
        ).status_code == 400

        # List shows the key, never a token/hash.
        listed = client.get("/api/api-keys", headers=admin_hdr).json()["api_keys"]
        assert any(k["id"] == new_id for k in listed)
        assert all("token" not in k and "key_hash" not in k for k in listed)

        # Revoke it; revoking again 404s.
        assert client.delete(f"/api/api-keys/{new_id}", headers=admin_hdr).status_code == 200
        assert client.delete(f"/api/api-keys/{new_id}", headers=admin_hdr).status_code == 404
