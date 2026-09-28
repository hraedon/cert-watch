"""Tests for API-key auth (Plan 039 / BC-104).

Covers the repository (create/verify/revoke/list, hashing, scope validation)
and the middleware dependencies (require_auth / write_guard / require_admin)
authenticating via an ``Authorization: Bearer cwk_…`` token.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from fastapi import Request
from fastapi.exceptions import HTTPException

from cert_watch.audit import audit_actor_display, list_audit, record_audit, resolve_actor
from cert_watch.auth.guards import (
    admin_write_guard,
    renewal_report_binding,
    renewal_report_guard,
    renewal_report_read_guard,
    require_admin,
    require_auth,
    write_guard,
)
from cert_watch.auth.rbac import AuthContext
from cert_watch.auth.request_context import authenticate_api_key, resolve_session_user
from cert_watch.database import init_schema
from cert_watch.database.api_keys import SqliteApiKeyRepository, hash_token
from cert_watch.security import SecurityContext

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


def test_renewal_report_key_uses_downgrade_safe_hash_prefix(repo):
    entry, raw = repo.create_key("renewal-hook", "renewal-report", binding="all")
    with repo_conn(repo) as conn:
        stored = conn.execute(
            "SELECT key_hash FROM api_keys WHERE id = ?", (entry.id,)
        ).fetchone()["key_hash"]

    assert stored.startswith("rr-hmac:")

    # Simulate the complete 1.1.x verifier candidate set: current/legacy HMAC
    # plus the pre-HMAC SHA-256 form. It has no rr-hmac candidate.
    old_candidates = [
        hash_token(raw),
        hash_token(raw, pepper=b"cert-watch-default-pepper"),
        hashlib.sha256(raw.encode()).hexdigest(),
    ]
    assert stored not in old_candidates
    with repo_conn(repo) as conn:
        placeholders = ",".join("?" for _ in old_candidates)
        assert conn.execute(
            f"SELECT id FROM api_keys WHERE key_hash IN ({placeholders})",
            old_candidates,
        ).fetchone() is None


def test_renewal_report_creation_requires_explicit_nonempty_binding(repo):
    for binding, tags in ((None, None), ("", ""), ("tags", " , ")):
        with pytest.raises(ValueError):
            repo.create_key(
                "renewal-hook", "renewal-report", binding=binding, bound_tags=tags
            )

    all_entry, _ = repo.create_key("all", "renewal-report", binding="all")
    tags_entry, _ = repo.create_key(
        "tags", "renewal-report", binding="tags", bound_tags=" Prod,edge,prod "
    )
    assert (all_entry.binding, all_entry.bound_tags) == ("all", ())
    assert (tags_entry.binding, tags_entry.bound_tags) == ("tags", ("Prod", "edge"))


@pytest.mark.parametrize(
    "bound_tags, message",
    [
        ("\u200b", "visible characters"),
        (" \u200b\t", "visible characters"),
        ("x" * 65, "at most 64 characters"),
        (",".join(f"tag-{index}" for index in range(21)), "at most 20 tags"),
    ],
)
def test_renewal_report_binding_rejects_invisible_or_oversized_tags(
    repo, bound_tags, message,
):
    with pytest.raises(ValueError, match=message):
        repo.create_key(
            "renewal-hook", "renewal-report",
            binding="tags", bound_tags=bound_tags,
        )


def test_renewal_report_binding_accepts_tag_limits(repo):
    tags = [f"tag-{index}" for index in range(19)] + ["x" * 64]
    entry, _ = repo.create_key(
        "renewal-hook", "renewal-report",
        binding="tags", bound_tags=",".join(tags),
    )
    assert entry.bound_tags == tuple(tags)


@pytest.mark.parametrize("scope", ["read", "write", "admin"])
def test_existing_scopes_are_all_bound_and_refuse_tags(repo, scope):
    entry, _ = repo.create_key(scope, scope)
    assert (entry.binding, entry.bound_tags) == ("all", ())
    with pytest.raises(ValueError):
        repo.create_key(scope, scope, binding="tags", bound_tags="prod")
    with pytest.raises(ValueError):
        repo.create_key(scope, scope, binding="all", bound_tags="prod")


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


def test_verify_legacy_sha256_upgrades_hash_and_valid_timestamp(repo):
    raw = "cwk_legacy-sha256-token"
    legacy_hash = hashlib.sha256(raw.encode()).hexdigest()
    created = datetime.now(UTC).isoformat()
    with repo_conn(repo) as conn:
        conn.execute(
            "INSERT INTO api_keys"
            " (id, key_hash, name, scope, binding, created_at, revoked)"
            " VALUES (?, ?, ?, ?, 'all', ?, 0)",
            ("legacy-sha", legacy_hash, "legacy", "read", created),
        )
        conn.commit()

    auth = repo.verify_key(raw)

    assert auth is not None
    with repo_conn(repo) as conn:
        row = conn.execute(
            "SELECT key_hash, last_used_at FROM api_keys WHERE id = ?",
            ("legacy-sha",),
        ).fetchone()
    assert row["key_hash"] == hash_token(raw)
    last_used = datetime.fromisoformat(row["last_used_at"])
    assert last_used.tzinfo == UTC


def test_security_context_pepper_is_used_for_new_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("CERT_WATCH_AUTH_SECRET", "old-environment-pepper")
    db = tmp_path / "security-context.sqlite3"
    init_schema(db)
    security = SecurityContext(
        signing_key="persisted-auth-secret",
        csrf_secret="persisted-csrf-secret",
    )
    secure_repo = SqliteApiKeyRepository(db, security=security)

    entry, raw = secure_repo.create_key("secure", "read")

    with repo_conn(secure_repo) as conn:
        row = conn.execute("SELECT key_hash FROM api_keys WHERE id = ?", (entry.id,)).fetchone()
    expected = hash_token(raw, pepper=security.signing_key.encode())
    assert row["key_hash"] == expected
    assert row["key_hash"] != hash_token(raw)


def test_legacy_pepper_caches_env_settings_resolution(monkeypatch):
    from cert_watch.config import Settings

    monkeypatch.setenv("CERT_WATCH_AUTH_SECRET", "cache-test-environment-pepper")
    original = Settings.from_env.__func__
    calls = 0

    def counted(cls):
        nonlocal calls
        calls += 1
        return original(cls)

    monkeypatch.setattr(Settings, "from_env", classmethod(counted))

    first = hash_token("cwk_first")
    second = hash_token("cwk_second")

    assert first != second
    assert calls == 1


@pytest.mark.parametrize(
    ("legacy_pepper", "environment_pepper"),
    [
        (b"cert-watch-default-pepper", "unrelated-current-environment"),
        (b"old-environment-pepper", "old-environment-pepper"),
    ],
)
def test_prior_hmac_peppers_authenticate_and_upgrade(
    tmp_path, monkeypatch, legacy_pepper, environment_pepper
):
    monkeypatch.setenv("CERT_WATCH_AUTH_SECRET", environment_pepper)
    db = tmp_path / "legacy-hmac.sqlite3"
    init_schema(db)
    raw = "cwk_legacy-hmac-token"
    created = datetime.now(UTC).isoformat()
    with repo_conn(SimpleNamespace(db_path=db)) as conn:
        conn.execute(
            "INSERT INTO api_keys"
            " (id, key_hash, name, scope, binding, created_at, revoked)"
            " VALUES (?, ?, ?, ?, 'all', ?, 0)",
            (
                "legacy-hmac",
                hash_token(raw, pepper=legacy_pepper),
                "legacy",
                "write",
                created,
            ),
        )
        conn.commit()
    security = SecurityContext(
        signing_key="persisted-auth-secret",
        csrf_secret="persisted-csrf-secret",
    )
    secure_repo = SqliteApiKeyRepository(db, security=security)

    auth = secure_repo.verify_key(raw)

    assert auth is not None
    assert auth.scope == "write"
    with repo_conn(secure_repo) as conn:
        row = conn.execute(
            "SELECT key_hash, last_used_at FROM api_keys WHERE id = ?",
            ("legacy-hmac",),
        ).fetchone()
    assert row["key_hash"] == hash_token(raw, pepper=security.signing_key.encode())
    assert datetime.fromisoformat(row["last_used_at"]).tzinfo == UTC


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


def _make_request(
    db_path, *, bearer=None, role_map=None, security=None,
    method="POST", path="/api/test", raw_path=None, cookie=None,
) -> Request:
    headers = []
    if bearer is not None:
        headers.append((b"authorization", f"Bearer {bearer}".encode()))
    if cookie is not None:
        headers.append((b"cookie", cookie.encode()))
    settings = SimpleNamespace(
        db_path=str(db_path),
        role_map=role_map or {},
        write_users=[],
        admin_users=[],
    )
    app = SimpleNamespace(
        state=SimpleNamespace(
            auth_provider=_Provider(), settings=settings, security=security
        )
    )
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "raw_path": raw_path if raw_path is not None else path.encode(),
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
async def test_authenticate_api_key_uses_request_security_context(seeded):
    db, _ = seeded
    security = SecurityContext(
        signing_key="persisted-auth-secret",
        csrf_secret="persisted-csrf-secret",
    )
    _, raw = SqliteApiKeyRepository(db, security=security).create_key("svc", "read")
    request = _make_request(db, bearer=raw, security=security)

    assert authenticate_api_key(request, db) is not None


def test_api_key_audit_identity_is_stable_and_not_impersonable(seeded):
    db, repo = seeded
    first, first_raw = repo.create_key("shared-name", "write")
    second, second_raw = repo.create_key("shared-name", "write")

    for raw in (first_raw, second_raw):
        request = _make_request(db, bearer=raw)
        assert authenticate_api_key(request, db) is not None
        record_audit(
            db,
            actor=resolve_actor(request),
            action="host.edit",
            target_type="host",
            target_id="host-1",
        )
    record_audit(
        db,
        actor="shared-name",
        action="host.edit",
        target_type="host",
        target_id="host-1",
    )

    rows = list_audit(db)
    assert {row["actor"] for row in rows} == {
        "shared-name",
        f"api_key:{first.id}",
        f"api_key:{second.id}",
    }
    key_rows = [row for row in rows if row["actor"].startswith("api_key:")]
    assert all(
        json.loads(row["detail"])["api_key_name"] == "shared-name"
        for row in key_rows
    )
    assert {audit_actor_display(row) for row in key_rows} == {
        f"shared-name (API key {first.id[:8]})",
        f"shared-name (API key {second.id[:8]})",
    }


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
    assert await write_guard(request) == "svc"


@pytest.mark.anyio
async def test_require_write_denies_read_scope(seeded):
    db, repo = seeded
    _, raw = repo.create_key("svc", "read")
    request = _make_request(db, bearer=raw)
    with pytest.raises(HTTPException) as exc:
        await write_guard(request)
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


@pytest.mark.anyio
async def test_renewal_report_principal_and_guard(seeded):
    db, repo = seeded
    entry, raw = repo.create_key(
        "renewal-hook", "renewal-report", binding="tags", bound_tags="Prod,edge"
    )
    request = _make_request(db, bearer=raw, path="/api/renewal-reports")
    request.scope.pop("raw_path")  # Hand-built ASGI scopes may omit raw_path.

    assert await renewal_report_guard(request) == "renewal-hook"
    context = request.state.auth_context
    assert context.principal_id == entry.id
    assert context.principal_kind == "renewal-report"
    assert context.permissions == frozenset()
    assert context.may_write() is False
    assert context.is_admin is False
    assert renewal_report_binding(context) == ("Prod", "edge")

    _, all_raw = repo.create_key(
        "all-renewals", "renewal-report", binding="all"
    )
    all_request = _make_request(
        db, bearer=all_raw, path="/api/renewal-reports"
    )
    assert await renewal_report_guard(all_request) == "all-renewals"
    assert renewal_report_binding(all_request.state.auth_context) == "all"


@pytest.mark.parametrize(
    "scope,binding,path",
    [
        ("renewal-report", "all", "/api/renewal-reports"),
        ("read", None, "/api/certificates"),
    ],
)
def test_api_key_authentication_refuses_a_key_revoked_before_usage_recording(
    seeded, monkeypatch, scope, binding, path,
):
    db, repo = seeded
    _, raw = repo.create_key("racing-key", scope, binding=binding)
    original_verify = SqliteApiKeyRepository.verify_key

    def verify_with_revoke_race(self, token, **kwargs):
        if kwargs.get("record_use", True):
            return None
        return original_verify(self, token, **kwargs)

    monkeypatch.setattr(
        SqliteApiKeyRepository, "verify_key", verify_with_revoke_race
    )
    request = _make_request(db, bearer=raw, method="GET", path=path)

    assert authenticate_api_key(request, db) is None
    assert not hasattr(request.state, "auth_context")


def test_resolve_session_user_preserves_report_key_state(seeded):
    db, repo = seeded
    _, raw = repo.create_key(
        "renewal-hook", "renewal-report", binding="all"
    )

    allowed = _make_request(db, bearer=raw, path="/api/renewal-reports")
    assert authenticate_api_key(allowed, db) is not None
    assert resolve_session_user(allowed) == ("renewal-hook", None, True)

    forbidden = _make_request(db, bearer=raw, path="/api/health")
    assert resolve_session_user(forbidden) == (
        None, "forbidden for this key", True
    )
    # A second guard resolution takes the already-classified fast path.
    assert resolve_session_user(forbidden) == (
        None, "forbidden for this key", True
    )


@pytest.mark.anyio
@pytest.mark.parametrize("scope", ["read", "write", "admin"])
async def test_renewal_report_guard_refuses_other_key_scopes(seeded, scope):
    db, repo = seeded
    _, raw = repo.create_key(scope, scope)
    request = _make_request(db, bearer=raw, path="/api/renewal-reports")
    with pytest.raises(HTTPException) as exc:
        await renewal_report_guard(request)
    assert exc.value.status_code == 403


@pytest.mark.anyio
async def test_renewal_report_guard_refuses_plain_session(seeded):
    from cert_watch.auth import SESSION_COOKIE, create_session

    db, _ = seeded
    security = SecurityContext(
        signing_key="session-signing-key",
        csrf_secret="session-csrf-key",
    )
    token = create_session("human-admin", security, version=0)
    request = _make_request(
        db,
        security=security,
        path="/api/renewal-reports",
        cookie=f"{SESSION_COOKIE}={token}",
    )
    with pytest.raises(HTTPException) as exc:
        await renewal_report_guard(request)
    assert exc.value.status_code == 403


@pytest.mark.anyio
async def test_renewal_report_read_guard_refuses_missing_and_ordinary_key(seeded):
    db, repo = seeded
    missing = _make_request(db, method="GET", path="/api/renewal-reports")
    with pytest.raises(HTTPException) as unauthenticated:
        await renewal_report_read_guard(missing)
    assert unauthenticated.value.status_code == 401

    _, raw = repo.create_key("reader", "read")
    ordinary = _make_request(
        db, bearer=raw, method="GET", path="/api/renewal-reports"
    )
    with pytest.raises(HTTPException) as forbidden:
        await renewal_report_read_guard(ordinary)
    assert forbidden.value.status_code == 403


def test_renewal_report_binding_rejects_wrong_or_corrupt_context():
    with pytest.raises(ValueError, match="principal required"):
        renewal_report_binding(AuthContext.system())
    corrupt = AuthContext.renewal_report_key(
        "broken", principal_id="broken", binding="tags", bound_tags=()
    )
    with pytest.raises(ValueError, match="invalid renewal-report binding"):
        renewal_report_binding(corrupt)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "guard", [require_auth, write_guard, require_admin, admin_write_guard]
)
async def test_ordinary_guards_refuse_renewal_report_principal(seeded, guard):
    """Defense in depth if the middleware route allowlist is ever widened."""
    db, repo = seeded
    _, raw = repo.create_key(
        "renewal-hook", "renewal-report", binding="tags", bound_tags="prod"
    )
    request = _make_request(db, bearer=raw, path="/api/renewal-reports")

    with pytest.raises(HTTPException) as exc:
        await guard(request)

    assert exc.value.status_code == 403
    assert exc.value.detail == "forbidden for this key"


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


def test_renewal_report_key_route_allowlist_is_uniform(reload_app):
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
    _, raw = repo.create_key("renewal-hook", "renewal-report", binding="all")
    headers = {"Authorization": f"Bearer {raw}"}
    with TestClient(app_mod.app) as client:
        refusals = [
            client.get(path, headers=headers, follow_redirects=False)
            for path in (
                "/", "/metrics", "/api/health", "/healthz",
                "/static/css/cw.css", "/does-not-exist",
                "/api/renewal-reports/",
                "/api/renewal%2Dreports", "/api/renewal-reports/%2E",
            )
        ]
        head = client.head("/api/renewal-reports", headers=headers)
        refusals.append(client.put("/api/renewal-reports", headers=headers))
        for method in (client.get, client.post):
            response = method("/api/renewal-reports", headers=headers)
            assert response.status_code == 422

    assert {(r.status_code, r.content) for r in refusals} == {
        (403, b'{"error":"forbidden for this key"}')
    }
    assert {tuple(sorted(r.headers.items())) for r in refusals} == {
        tuple(sorted(refusals[0].headers.items()))
    }
    assert refusals[0].headers["x-content-type-options"] == "nosniff"
    assert "x-ratelimit-limit" not in refusals[0].headers
    assert head.status_code == 403  # HTTP HEAD omits the JSON body by definition.


def test_renewal_report_allowlist_rejects_raw_dot_segment(seeded):
    db, repo = seeded
    entry, raw = repo.create_key("renewal-hook", "renewal-report", binding="all")
    request = _make_request(
        db,
        bearer=raw,
        method="GET",
        path="/api/renewal-reports",
        raw_path=b"/api/renewal-reports/.",
    )

    assert authenticate_api_key(request, db, renewal_report_only=True) is None
    assert request.state.api_key_forbidden is True
    refreshed = next(key for key in repo.list_keys() if key.id == entry.id)
    assert refreshed.last_used_at is None


@pytest.mark.parametrize(
    "authorization_headers",
    [
        lambda raw: [("authorization", f"Bearer  {raw}")],
        lambda raw: [("authorization", f"Bearer\t{raw}")],
        lambda raw: [("authorization", f"Bearer {raw} ")],
        lambda raw: [("authorization", f"bearer {raw}")],
        lambda raw: [("authorization", f"Bearer {raw.upper()}")],
        lambda raw: [
            ("authorization", "Basic YWRtaW46cHc="),
            ("authorization", f"Bearer {raw}"),
        ],
        lambda raw: [("authorization", raw)],
        lambda raw: [("authorization", f" Bearer {raw}")],
    ],
    ids=[
        "two-spaces", "tab", "trailing-space", "lowercase-scheme",
        "uppercase-token-prefix", "duplicate-one-cwk", "no-scheme", "leading-space",
    ],
)
@pytest.mark.parametrize("auth_enabled", [True, False], ids=["auth-on", "auth-off"])
def test_malformed_authorization_is_rejected_everywhere(
    reload_app, authorization_headers, auth_enabled,
):
    from fastapi.testclient import TestClient

    from cert_watch.auth.local_admin import _scrypt_hash
    from cert_watch.config import Settings

    app_mod = reload_app(
        **(
            {
                "CERT_WATCH_LOCAL_ADMIN_USER": "admin",
                "CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH": _scrypt_hash(
                    "pw-for-tests-1"
                ),
            }
            if auth_enabled
            else {}
        )
    )
    db = Settings.from_env().db_path
    init_schema(db)
    _, raw = SqliteApiKeyRepository(db).create_key(
        "renewal-hook", "renewal-report", binding="all"
    )
    headers = authorization_headers(raw)

    with TestClient(app_mod.app) as client:
        responses = [
            client.get(path, headers=headers, follow_redirects=False)
            for path in (
                "/", "/api/hosts", "/api/renewal-reports",
                "/healthz", "/readyz", "/static/css/cw.css", "/login",
            )
        ]

    assert {(response.status_code, response.content) for response in responses} == {
        (401, b'{"error":"malformed authorization"}')
    }


@pytest.mark.parametrize("auth_enabled", [True, False], ids=["auth-on", "auth-off"])
@pytest.mark.parametrize(
    "authorization_headers",
    [
        [("authorization", "Basic YWRtaW46cHc=")],
        [("authorization", "bearer idp-access-token")],
        [
            ("authorization", "Basic YWRtaW46cHc="),
            ("authorization", "bearer idp-access-token"),
        ],
        # Review R3-1: "cwk_" inside a token is not a cert-watch key.
        [("authorization", "Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4cwk_eSJ9.c2ln")],
        [("authorization", "bearer idp-token-CWk_suffix")],
    ],
    ids=[
        "basic",
        "lowercase-idp-bearer",
        "duplicate-non-cwk",
        "jwt-containing-cwk",
        "token-containing-cwk-any-case",
    ],
)
def test_non_cwk_authorization_preserves_origin_behavior(
    reload_app, auth_enabled, authorization_headers,
):
    """Non-cwk credentials are invisible to the report-key precheck."""
    from fastapi.testclient import TestClient

    from cert_watch.auth.local_admin import _scrypt_hash

    env = (
        {
            "CERT_WATCH_LOCAL_ADMIN_USER": "admin",
            "CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH": _scrypt_hash("pw-for-tests-1"),
        }
        if auth_enabled
        else {}
    )
    app_mod = reload_app(**env)
    paths = ("/healthz", "/readyz", "/login", "/", "/api/hosts")

    with TestClient(app_mod.app) as client:
        baseline = {
            path: client.get(path, follow_redirects=False) for path in paths
        }
        actual = {
            path: client.get(
                path,
                headers=authorization_headers,
                follow_redirects=False,
            )
            for path in paths
        }

    assert {
        path: (response.status_code, response.headers.get("location"))
        for path, response in actual.items()
    } == {
        path: (response.status_code, response.headers.get("location"))
        for path, response in baseline.items()
    }


def test_public_path_does_not_consume_existing_key_scopes(reload_app):
    """The report-key precheck leaves read/write/admin behavior unchanged."""
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
    entry, raw = repo.create_key("reader", "read")

    with TestClient(app_mod.app) as client:
        response = client.get(
            "/healthz", headers={"Authorization": f"Bearer {raw}"}
        )

    assert response.status_code == 200
    refreshed = next(key for key in repo.list_keys() if key.id == entry.id)
    assert refreshed.last_used_at is None


def test_renewal_report_allowlist_applies_when_auth_is_disabled(reload_app):
    from fastapi.testclient import TestClient

    from cert_watch.config import Settings

    app_mod = reload_app()
    db = Settings.from_env().db_path
    repo = SqliteApiKeyRepository(db)
    _, raw = repo.create_key("renewal-hook", "renewal-report", binding="all")

    with TestClient(app_mod.app) as client:
        refused = client.get("/", headers={"Authorization": f"Bearer {raw}"})
        admitted = client.post(
            "/api/renewal-reports",
            headers={"Authorization": f"Bearer {raw}"},
        )

    assert refused.status_code == 403
    assert refused.content == b'{"error":"forbidden for this key"}'
    # The real route's validation response proves the key passed the pre-router
    # allowlist and renewal-report guard even though browser auth is disabled.
    assert admitted.status_code == 422


def test_refused_renewal_report_key_has_no_usage_side_effects(reload_app):
    from fastapi.testclient import TestClient

    from cert_watch.auth.local_admin import _scrypt_hash
    from cert_watch.config import Settings

    app_mod = reload_app(
        CERT_WATCH_LOCAL_ADMIN_USER="admin",
        CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH=_scrypt_hash("pw-for-tests-1"),
    )
    db = Settings.from_env().db_path
    repo = SqliteApiKeyRepository(db)
    entry, raw = repo.create_key("renewal-hook", "renewal-report", binding="all")
    with repo_conn(repo) as conn:
        before_hash = conn.execute(
            "SELECT key_hash FROM api_keys WHERE id = ?", (entry.id,)
        ).fetchone()["key_hash"]

    with TestClient(app_mod.app) as client:
        response = client.get(
            "/api/certificates", headers={"Authorization": f"Bearer {raw}"}
        )

    assert response.status_code == 403
    refreshed = next(key for key in repo.list_keys() if key.id == entry.id)
    assert refreshed.last_used_at is None
    with repo_conn(repo) as conn:
        after_hash = conn.execute(
            "SELECT key_hash FROM api_keys WHERE id = ?", (entry.id,)
        ).fetchone()["key_hash"]
    assert after_hash == before_hash


def test_report_hash_family_cannot_authenticate_a_regular_scope(reload_app):
    from fastapi.testclient import TestClient

    from cert_watch.auth.local_admin import _scrypt_hash
    from cert_watch.config import Settings

    app_mod = reload_app(
        CERT_WATCH_LOCAL_ADMIN_USER="admin",
        CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH=_scrypt_hash("pw-for-tests-1"),
    )
    db = Settings.from_env().db_path
    repo = SqliteApiKeyRepository(db)
    entry, raw = repo.create_key(
        "renewal-hook", "renewal-report", binding="all"
    )
    with repo_conn(repo) as conn:
        conn.execute("UPDATE api_keys SET scope = 'read' WHERE id = ?", (entry.id,))
        conn.commit()

    with TestClient(app_mod.app) as client:
        response = client.get(
            "/api/certificates", headers={"Authorization": f"Bearer {raw}"}
        )

    assert response.status_code == 401


@pytest.mark.parametrize(
    "scope,binding,bound_tags,hash_prefix",
    [
        ("renewal-report", "all", "", "hmac:"),
        ("renewal-report", "all", "prod", "rr-hmac:"),
        ("read", "tags", "prod", "hmac:"),
        ("write", "tags", "prod", "hmac:"),
        ("admin", "tags", "prod", "hmac:"),
    ],
)
def test_verify_rejects_cross_family_or_binding_corruption(
    repo, scope, binding, bound_tags, hash_prefix,
):
    create_scope = "renewal-report" if scope == "renewal-report" else scope
    entry, raw = repo.create_key(
        "key", create_scope,
        binding="all" if create_scope == "renewal-report" else None,
    )
    with repo_conn(repo) as conn:
        conn.execute("PRAGMA ignore_check_constraints = ON")
        conn.execute(
            "UPDATE api_keys SET scope = ?, binding = ?, bound_tags = ?, "
            "key_hash = ? || substr(key_hash, instr(key_hash, ':') + 1) "
            "WHERE id = ?",
            (scope, binding, bound_tags, hash_prefix, entry.id),
        )
        conn.commit()

    assert repo.verify_key(raw) is None


@pytest.mark.parametrize(
    "corruption",
    ["empty-tags", "unknown-binding", "too-many-tags", "invisible-tag"],
)
def test_corrupt_renewal_report_binding_is_unauthenticated(reload_app, corruption):
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
    entry, raw = repo.create_key(
        "renewal-hook", "renewal-report", binding="tags", bound_tags="prod"
    )
    with repo_conn(repo) as conn:
        if corruption == "unknown-binding":
            conn.execute("PRAGMA ignore_check_constraints = ON")
            conn.execute(
                "UPDATE api_keys SET binding = 'future' WHERE id = ?", (entry.id,)
            )
        elif corruption == "empty-tags":
            conn.execute(
                "UPDATE api_keys SET bound_tags = '' WHERE id = ?", (entry.id,)
            )
        elif corruption == "too-many-tags":
            conn.execute(
                "UPDATE api_keys SET bound_tags = ? WHERE id = ?",
                (",".join(f"tag-{index}" for index in range(21)), entry.id),
            )
        else:
            conn.execute(
                "UPDATE api_keys SET bound_tags = ? WHERE id = ?",
                ("prod,\u200b", entry.id),
            )
        conn.commit()

    with TestClient(app_mod.app) as client:
        response = client.get(
            "/api/renewal-reports",
            headers={"Authorization": f"Bearer {raw}"},
        )
    assert response.status_code == 401
    assert response.json() == {"error": "unauthenticated"}


def test_revoked_renewal_report_key_is_unauthenticated(reload_app):
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
    entry, raw = repo.create_key("renewal-hook", "renewal-report", binding="all")
    assert repo.revoke_key(entry.id)

    with TestClient(app_mod.app) as client:
        response = client.get(
            "/api/renewal-reports",
            headers={"Authorization": f"Bearer {raw}"},
        )
    assert response.status_code == 401


def test_unknown_scope_is_unauthenticated_on_api_and_html_routes(
    reload_app, caplog,
):
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
    entry, raw = repo.create_key("corrupt-scope", "read")
    legacy_hash = hashlib.sha256(raw.encode()).hexdigest()
    with repo_conn(repo) as conn:
        conn.execute(
            "UPDATE api_keys SET scope = 'bogus', key_hash = ? WHERE id = ?",
            (legacy_hash, entry.id),
        )
        conn.commit()

    headers = {"Authorization": f"Bearer {raw}"}
    with (
        caplog.at_level("WARNING", logger="cert_watch.auth.request_context"),
        TestClient(app_mod.app) as client,
    ):
        assert client.get("/api/hosts", headers=headers).status_code == 401
        assert client.get(
            "/", headers=headers, follow_redirects=False
        ).status_code == 401

    assert any(entry.id in record.message for record in caplog.records)
    assert all(raw not in record.message for record in caplog.records)
    with repo_conn(repo) as conn:
        row = conn.execute(
            "SELECT key_hash, last_used_at FROM api_keys WHERE id = ?", (entry.id,)
        ).fetchone()
    assert row["key_hash"] == legacy_hash
    assert row["last_used_at"] is None


def test_non_cert_watch_bearer_on_html_page_uses_login_flow(reload_app):
    from fastapi.testclient import TestClient

    from cert_watch.auth.local_admin import _scrypt_hash

    app_mod = reload_app(
        CERT_WATCH_LOCAL_ADMIN_USER="admin",
        CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH=_scrypt_hash("pw-for-tests-1"),
    )
    with TestClient(app_mod.app) as client:
        response = client.get(
            "/",
            headers={"Authorization": "Bearer proxy-issued-token"},
            follow_redirects=False,
        )
        rejected_key = client.get(
            "/",
            headers={"Authorization": "Bearer cwk_not-a-real-key"},
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert rejected_key.status_code == 401
    assert rejected_key.json() == {"error": "unauthenticated"}


def test_api_keys_management_routes(reload_app):
    """API-key CRUD requires an admin browser session, never another API key."""
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
        from cert_watch.auth import SESSION_COOKIE, create_session
        from cert_watch.auth.rbac import BREAK_GLASS_CLAIM

        # No API key, including an admin-scoped key, can manage keys.
        read_hdr = {"Authorization": f"Bearer {read_raw}"}
        assert client.get("/api/api-keys", headers=read_hdr).status_code == 403
        assert client.get("/api/api-keys", headers=admin_hdr).status_code == 403
        assert client.post(
            "/api/api-keys", headers=admin_hdr, json={"name": "x", "scope": "read"}
        ).status_code == 403

        token = create_session(
            "admin", client.app.state.security, version=0, roles=[BREAK_GLASS_CLAIM]
        )
        client.cookies.set(SESSION_COOKIE, token)

        # The admin browser session creates a key and gets the raw token once.
        created = client.post(
            "/api/api-keys", json={"name": "deploy", "scope": "write"}
        )
        assert created.status_code == 201
        body = created.json()
        assert body["token"].startswith("cwk_")
        assert body["scope"] == "write"
        assert body["binding"] == "all"
        assert body["bound_tags"] == []
        new_id = body["id"]

        # Bad scope is rejected.
        assert client.post(
            "/api/api-keys", json={"name": "x", "scope": "root"}
        ).status_code == 400

        # Renewal-report bindings are explicit and use the shared tag parser.
        assert client.post(
            "/api/api-keys", json={"name": "rr", "scope": "renewal-report"}
        ).status_code == 400
        assert client.post(
            "/api/api-keys",
            json={
                "name": "rr", "scope": "renewal-report",
                "binding": "tags", "bound_tags": [],
            },
        ).status_code == 400
        assert client.post(
            "/api/api-keys",
            json={
                "name": "bad-read", "scope": "read",
                "binding": "tags", "bound_tags": ["prod"],
            },
        ).status_code == 400
        comma_tag = client.post(
            "/api/api-keys",
            json={
                "name": "bad-comma", "scope": "renewal-report",
                "binding": "tags", "bound_tags": ["prod,edge"],
            },
        )
        assert comma_tag.status_code == 400
        assert comma_tag.json() == {
            "error": "bound_tags list elements cannot contain commas"
        }
        report_key = client.post(
            "/api/api-keys",
            json={
                "name": "rr", "scope": "renewal-report",
                "binding": "tags", "bound_tags": [" Prod ", "edge", "prod"],
            },
        )
        assert report_key.status_code == 201
        assert report_key.json()["binding"] == "tags"
        assert report_key.json()["bound_tags"] == ["Prod", "edge"]

        # List shows the key, never a token/hash.
        listed = client.get("/api/api-keys").json()["api_keys"]
        assert any(k["id"] == new_id for k in listed)
        assert all("token" not in k and "key_hash" not in k for k in listed)

        # Revoke it; revoking again 404s.
        assert client.delete(f"/api/api-keys/{new_id}").status_code == 200
        assert client.delete(f"/api/api-keys/{new_id}").status_code == 404
