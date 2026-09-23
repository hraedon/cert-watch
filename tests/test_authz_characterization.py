"""Authorization characterization matrix for every mutating route (plan 057 W6).

Pins the *outcome class* of every mutating route (POST/PUT/PATCH/DELETE) in
the app for a matrix of principals, each twice: once carrying a valid CSRF
token and once carrying none. The recorded outcome is the class
(``allowed`` / ``401`` / ``403`` / ``redirect-login`` / ``denied-redirect`` /
``csrf-reject``) plus the exact status, redirect target, or error detail, so
any change to an authorization decision -- including a changed bounce target
or message -- shows up as a diff against ``fixtures/authz_matrix.json``.

The route list is read from ``app.routes``, so a new mutating route fails this
test until the golden file is regenerated deliberately::

    CW_REGEN_AUTHZ_MATRIX=1 .venv/bin/pytest tests/test_authz_characterization.py

A regenerated golden file is a reviewable authorization change: read the diff.

Every principal gets a fresh database and app, and the routes run in a fixed
order with destructive routes (deletes, revokes, logout, password change)
last, so the matrix is deterministic. Scanning is stubbed out; nothing here
touches the network.
"""

from __future__ import annotations

import inspect
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi import UploadFile
from fastapi.testclient import TestClient

GOLDEN = Path(__file__).parent / "fixtures" / "authz_matrix.json"

_ROLE_MAP = {
    "admin": {"roles": ["admin"]},
    "ops": {"roles": ["ops"]},
    "ops-a": {"roles": ["ops-a"]},
    "view": {"roles": ["view"]},
}


@dataclass(frozen=True)
class Principal:
    name: str
    env: str  # "rbac" (role map), "legacy" (no role map), "noauth"
    kind: str  # "anon" | "session" | "api_key" | "local_user" | "none"
    username: str = ""
    roles: tuple[str, ...] = ()
    key_scope: str = ""


PRINCIPALS = [
    Principal("anonymous", "rbac", "anon"),
    Principal("viewer", "rbac", "session", "vera", ("view",)),
    Principal("operator-scoped-A", "rbac", "session", "otto", ("ops-a",)),
    Principal("operator", "rbac", "session", "olga", ("ops",)),
    Principal("admin", "rbac", "session", "ada", ("admin",)),
    Principal("break-glass", "rbac", "session", "admin", ("cw:break-glass",)),
    Principal("local-viewer", "rbac", "local_user", "lou"),
    Principal("api-key-read", "rbac", "api_key", key_scope="read"),
    Principal("api-key-write", "rbac", "api_key", key_scope="write"),
    Principal("api-key-admin", "rbac", "api_key", key_scope="admin"),
    # No role map: the legacy CERT_WATCH_WRITE_USERS / CERT_WATCH_ADMINS lists.
    Principal("legacy-reader", "legacy", "session", "rita"),
    Principal("legacy-writer", "legacy", "session", "will"),
    Principal("legacy-admin-listed", "legacy", "session", "alan"),
    Principal("auth-disabled", "noauth", "none"),
]


@dataclass
class Seeded:
    ids: dict[str, str] = field(default_factory=dict)
    api_keys: dict[str, str] = field(default_factory=dict)


def _hash(pw: str) -> str:
    from cert_watch.auth import _scrypt_hash

    return _scrypt_hash(pw, n=2**4, r=1, p=1)


def _cert(cn: str, fp: str):
    from datetime import UTC, datetime, timedelta

    from cert_watch.certificate_model import Certificate

    now = datetime.now(UTC)
    return Certificate(
        subject=f"CN={cn}",
        issuer="CN=Test CA",
        not_before=now - timedelta(days=5),
        not_after=now + timedelta(days=60),
        san_dns_names=[cn],
        fingerprint_sha256=fp * 64,
    )


def _seed(db: Path, principal: Principal) -> Seeded:
    from cert_watch.database import (
        Role,
        SqliteHostRepository,
        SqliteRoleRepository,
        SqliteTrustAnchorRepository,
        SqliteUserRepository,
        User,
        init_schema,
        kv_set,
    )
    from cert_watch.database.api_keys import SqliteApiKeyRepository
    from cert_watch.database.repo import Alert, SqliteAlertGroupRepository, SqliteAlertRepository
    from tests._helpers import seed_scanned

    init_schema(db)
    kv_set(db, "setup_complete", "1")
    if principal.env != "noauth":
        kv_set(db, "local_admin_user", "admin")
        kv_set(db, "local_admin_password_hash", _hash("testpassword"))
    seeded = Seeded()
    ids = seeded.ids
    roles = SqliteRoleRepository(db)
    roles.add(Role(name="ops", permission_tier="operator"))
    roles.add(Role(name="ops-a", permission_tier="operator", scope_tag="A"))
    view_role = roles.add(Role(name="view", permission_tier="viewer"))
    ids["role"] = roles.add(Role(name="target-role", permission_tier="viewer"))
    users = SqliteUserRepository(db)
    users.add(User(username="lou", email="", password_hash=_hash("pw12345678"), role_id=view_role))
    ids["user"] = users.add(
        User(username="target-user", email="", password_hash=_hash("pw12345678"), role_id=None)
    )

    hosts = SqliteHostRepository(db)
    ids["host_a"] = hosts.add("a.example.com", 443, tags="A")
    ids["host_b"] = hosts.add("b.example.com", 443, tags="B")
    ids["cert_a"] = seed_scanned(db, "a.example.com", 443, _cert("a.example.com", "a"))
    ids["cert_b"] = seed_scanned(db, "b.example.com", 443, _cert("b.example.com", "b"))
    ids["alert"] = SqliteAlertRepository(db).create(
        Alert(cert_id=ids["cert_a"], alert_type="expiry_warning", status="pending", message="m")
    )
    ids["group"] = SqliteAlertGroupRepository(db).create("g", ["ops@example.com"], ["A"])
    ids["anchor"] = SqliteTrustAnchorRepository(db).add(_cert("Anchor CA", "c"))

    keys = SqliteApiKeyRepository(db)
    entry, _ = keys.create_key("target-key", "read")
    ids["key"] = entry.id
    for scope in ("read", "write", "admin"):
        _, raw = keys.create_key(f"key-{scope}", scope)
        seeded.api_keys[scope] = raw
    return seeded


# ---------- route enumeration ----------


def _walk(routes: list[Any]) -> list[Any]:
    out: list[Any] = []
    for r in routes:
        if hasattr(r, "effective_candidates"):  # FastAPI >= 0.140 included router
            out.extend(_walk(r.effective_candidates()))
        else:
            out.append(r)
    return out


def mutating_routes(app: Any) -> list[tuple[str, str, Any]]:
    """``(method, path, route)`` for every mutating method on every route."""
    result = []
    for r in _walk(app.routes):
        methods = getattr(r, "methods", None) or set()
        for m in sorted(set(methods) - {"GET", "HEAD", "OPTIONS"}):
            result.append((m, r.path, r))
    return result


# Session-ending routes run last: a password change, then logout (which
# revokes the session every later request would need).
_DESTRUCTIVE_LAST = ("/settings/change-password", "/auth/logout")


def _order_key(item: tuple[str, str, Any]) -> tuple[int, str, str]:
    method, path, _ = item
    if path in _DESTRUCTIVE_LAST:
        rank = 2 + _DESTRUCTIVE_LAST.index(path)
    elif method == "DELETE" or path.endswith(("/delete", "/revoke")):
        rank = 1
    else:
        rank = 0
    return (rank, path, method)


_PARAM_TARGETS = {
    "host_id": ("host_a", "host_b"),
    "cert_id": ("cert_a", "cert_b"),
    "alert_id": ("alert",),
    "group_id": ("group",),
    "anchor_id": ("anchor",),
    "key_id": ("key",),
    "role_id": ("role",),
    "user_id": ("user",),
}


def _expansions(path: str) -> list[dict[str, str]]:
    names = re.findall(r"{(\w+)}", path)
    combos: list[dict[str, str]] = [{}]
    for name in names:
        combos = [{**c, name: t} for c in combos for t in _PARAM_TARGETS[name]]
    return combos


def _body_for(route: Any, path: str) -> dict[str, Any]:
    """Minimal well-formed request body: required form fields filled so body
    validation passes and the outcome reflects the guards, not a 422."""
    data: dict[str, str] = {"_probe": "1"}
    files: dict[str, Any] = {}
    dependant = getattr(route, "dependant", None)
    params = list(getattr(dependant, "body_params", []) or [])
    for p in params:
        ann = getattr(p.field_info, "annotation", None) or getattr(p, "type_", None)
        name = p.alias or p.name
        if ann is UploadFile or (inspect.isclass(ann) and issubclass(ann, UploadFile)):
            files[name] = ("probe.pem", b"not a certificate", "application/x-pem-file")
        elif ann is int or "int" in str(ann):
            data[name] = "1"
        elif ann is bool or "bool" in str(ann):
            data[name] = "false"
        else:
            data[name] = "probe"
    if path.startswith("/api/") and not params:
        return {"json": {}}
    out: dict[str, Any] = {"data": data}
    if files:
        out["files"] = files
    return out


# ---------- outcome classification ----------

_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_DENIALS = (
    "read-only user",
    "admin required",
    "unauthenticated",
    "team scope",
    "tags is read-only",
    "outside your",
)


def _normalize(text: str, seeded: Seeded) -> str:
    for label, value in seeded.ids.items():
        text = text.replace(value, "{" + label + "}")
    return _UUID.sub("{uuid}", text)


def _classify(resp: Any, seeded: Seeded) -> str:
    status = resp.status_code
    if 300 <= status < 400:
        loc = _normalize(resp.headers.get("location", ""), seeded)
        parts = urlsplit(loc)
        err = " ".join(parse_qs(parts.query).get("error", []))
        if parts.path == "/login" and not parts.query:
            cls = "redirect-login"
        elif "csrf" in err.lower():
            cls = "csrf-reject"
        elif any(d in err for d in _DENIALS):
            cls = "denied-redirect"
        else:
            cls = "allowed"
        return f"{cls} {status} {loc}"
    detail = ""
    ctype = resp.headers.get("content-type", "")
    if "json" in ctype:
        try:
            body = resp.json()
        except ValueError:
            body = {}
        if isinstance(body, dict):
            raw = body.get("detail", body.get("error", ""))
            detail = raw if isinstance(raw, str) else ""
    if status == 401:
        return f"401 {detail}"
    if status == 403:
        cls = "csrf-reject" if "csrf" in detail.lower() else "403"
        return f"{cls} {status} {detail}"
    if status == 200 and "html" in ctype and "CSRF token" in resp.text:
        return f"csrf-reject {status} html"
    if status >= 400:
        return f"allowed {status} {_normalize(detail, seeded)}"
    return f"allowed {status}"


# ---------- driving the matrix ----------


def _build_app(principal: Principal, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from cert_watch.app import create_app
    from cert_watch.config import Settings

    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CERT_WATCH_COOKIE_SECURE", "0")
    for var in ("CERT_WATCH_ROLE_MAP", "CERT_WATCH_WRITE_USERS", "CERT_WATCH_ADMINS"):
        monkeypatch.delenv(var, raising=False)
    if principal.env == "rbac":
        monkeypatch.setenv("CERT_WATCH_ROLE_MAP", json.dumps(_ROLE_MAP))
    elif principal.env == "legacy":
        monkeypatch.setenv("CERT_WATCH_WRITE_USERS", "will")
        monkeypatch.setenv("CERT_WATCH_ADMINS", "alan")
    else:
        monkeypatch.setenv("AUTH_PROVIDER", "none")
        monkeypatch.setenv("CERT_WATCH_ALLOW_UNAUTH", "1")
    return create_app(settings=Settings.from_env())


def _authenticate(client: TestClient, principal: Principal, seeded: Seeded) -> dict[str, str]:
    from cert_watch.auth import SESSION_COOKIE, create_session
    from cert_watch.auth.rbac import LOCAL_USER_CLAIM

    security = client.app.state.security
    client.cookies.set("cw_sid", "matrix-sid")
    if principal.kind == "session":
        token = create_session(principal.username, security, version=0, roles=list(principal.roles))
        client.cookies.set(SESSION_COOKIE, token)
    elif principal.kind == "local_user":
        token = create_session(principal.username, security, version=0, roles=[LOCAL_USER_CLAIM])
        client.cookies.set(SESSION_COOKIE, token)
    elif principal.kind == "api_key":
        return {"Authorization": f"Bearer {seeded.api_keys[principal.key_scope]}"}
    return {}


def _csrf_header(client: TestClient) -> dict[str, str]:
    from cert_watch.auth import SESSION_COOKIE
    from cert_watch.middleware import make_csrf_token

    sid = client.cookies.get(SESSION_COOKIE) or client.cookies.get("cw_sid") or ""
    return {"x-csrf-token": make_csrf_token(sid, client.app.state.security)}


def run_matrix_for(
    principal: Principal, with_csrf: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> dict[str, str]:
    import cert_watch.routes.hosts as hosts_routes
    from cert_watch import middleware as ratelimit

    async def _no_scan(*_a: Any, **_k: Any) -> tuple[str, str]:
        return "scan_error", "scanning disabled in the authz matrix"

    monkeypatch.setattr(hosts_routes, "_scan_and_store", _no_scan)
    ratelimit._clear_rate_caches()
    db = tmp_path / "cert-watch.sqlite3"
    seeded = _seed(db, principal)
    app = _build_app(principal, tmp_path, monkeypatch)
    outcomes: dict[str, str] = {}
    with TestClient(app) as client:
        headers = _authenticate(client, principal, seeded)
        if with_csrf and principal.kind != "api_key":
            headers = {**headers, **_csrf_header(client)}
        for method, path, route in sorted(mutating_routes(app), key=_order_key):
            for combo in _expansions(path):
                url = path
                for name, label in combo.items():
                    url = url.replace("{" + name + "}", seeded.ids[label])
                key = f"{method} {path}" + (
                    " [" + ",".join(combo.values()) + "]" if combo else ""
                )
                resp = client.request(
                    method, url, headers=headers, follow_redirects=False,
                    **_body_for(route, path),
                )
                outcomes[key] = _classify(resp, seeded)
    return outcomes


_CASES = [(p, c) for p in PRINCIPALS for c in (True, False)]


def _case_id(p: Principal, with_csrf: bool) -> str:
    return f"{p.name}/{'csrf' if with_csrf else 'no-csrf'}"


@pytest.fixture
def csrf_enforced(monkeypatch):
    from cert_watch import middleware as csrf

    monkeypatch.setattr(csrf, "_CSRF_BYPASS", False)


@pytest.mark.parametrize(
    ("principal", "with_csrf"), _CASES, ids=[_case_id(p, c) for p, c in _CASES]
)
def test_authz_matrix_matches_golden(
    principal: Principal, with_csrf: bool, tmp_path, monkeypatch, csrf_enforced
):
    actual = run_matrix_for(principal, with_csrf, tmp_path, monkeypatch)
    case = _case_id(principal, with_csrf)
    if os.environ.get("CW_REGEN_AUTHZ_MATRIX") == "1":
        golden = json.loads(GOLDEN.read_text()) if GOLDEN.exists() else {}
        golden[case] = actual
        GOLDEN.write_text(json.dumps(golden, indent=1, sort_keys=True) + "\n")
        return
    expected = json.loads(GOLDEN.read_text())[case]
    diff = {
        k: (expected.get(k), actual.get(k))
        for k in sorted(set(expected) | set(actual))
        if expected.get(k) != actual.get(k)
    }
    assert not diff, f"authorization outcomes changed for {case}:\n" + "\n".join(
        f"  {k}: expected {e!r}, got {a!r}" for k, (e, a) in diff.items()
    )
