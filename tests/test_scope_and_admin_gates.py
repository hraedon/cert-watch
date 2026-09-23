"""Tag-scope and admin-gate regressions (plan 057 W1).

- #65: trust-anchor upload/delete are fleet-wide trust decisions and must be
  admin-gated, not merely write-gated.
- #69: scope-tag matching is case-insensitive everywhere, including the
  ``routes/_scoped.py`` gates; pending hosts survive the scoped pivot
  drill-down.
- /scan-history is scope-filtered: a tag-scoped user sees only in-scope hosts.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from cert_watch.auth import SESSION_COOKIE, _scrypt_hash, create_session
from cert_watch.auth.rbac import AuthContext
from cert_watch.database import (
    Role,
    SqliteHostRepository,
    SqliteRoleRepository,
    SqliteTrustAnchorRepository,
    init_schema,
    kv_set,
)

_ROLE_MAP = {
    "admin": {"roles": ["admin"]},
    "payments-ops": {"roles": ["payments-ops"]},
    "payments-view": {"roles": ["payments-view"]},
}


def _seed(tmp_path: Path) -> Path:
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    kv_set(db, "local_admin_user", "admin")
    kv_set(db, "local_admin_password_hash", _scrypt_hash("testpassword", n=2**4, r=1, p=1))
    kv_set(db, "setup_complete", "1")
    roles = SqliteRoleRepository(db)
    roles.add(Role(name="payments-ops", permission_tier="operator", scope_tag="Payments"))
    roles.add(Role(name="payments-view", permission_tier="viewer", scope_tag="Payments"))
    return db


@pytest.fixture
def app_env(reload_app, tmp_path, monkeypatch):
    import cert_watch.routes.auth as auth_routes
    import cert_watch.security.csrf as csrf_mod

    monkeypatch.setenv("CERT_WATCH_COOKIE_SECURE", "0")
    monkeypatch.setenv("CERT_WATCH_ROLE_MAP", json.dumps(_ROLE_MAP))
    monkeypatch.setattr(csrf_mod, "_COOKIE_SECURE", False)
    monkeypatch.setattr(auth_routes, "_COOKIE_SECURE", False)
    db = _seed(tmp_path)
    return SimpleNamespace(app=reload_app().app, db=db)


def _login_as(client: TestClient, username: str, role: str) -> None:
    token = create_session(username, client.app.state.security, version=0, roles=[role])
    client.cookies.set(SESSION_COOKIE, token)


# ---------- #65: trust anchors are admin-only ----------


def test_scoped_writer_cannot_add_trust_anchor(app_env, chain_pem_file):
    with TestClient(app_env.app) as client, open(chain_pem_file, "rb") as f:
        _login_as(client, "payer", "payments-ops")
        r = client.post(
            "/trust-anchors",
            files={"file": ("bundle.pem", f, "application/x-pem-file")},
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "error" in r.headers["location"]
    assert SqliteTrustAnchorRepository(app_env.db).list_entries() == []


def test_admin_can_add_trust_anchor(app_env, chain_pem_file):
    with TestClient(app_env.app) as client, open(chain_pem_file, "rb") as f:
        _login_as(client, "admin", "admin")
        r = client.post(
            "/trust-anchors",
            files={"file": ("bundle.pem", f, "application/x-pem-file")},
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert r.headers["location"] == "/settings/trust-anchors?saved=1"
    assert len(SqliteTrustAnchorRepository(app_env.db).list_entries()) == 1


def _stored_anchor(db: Path, chain_pem_file: Path) -> str:
    from cert_watch.upload import upload_certificate

    entry = upload_certificate(chain_pem_file)
    return SqliteTrustAnchorRepository(db).add(entry.chain[-1])


def test_scoped_writer_cannot_delete_trust_anchor(app_env, chain_pem_file):
    anchor_id = _stored_anchor(app_env.db, chain_pem_file)
    with TestClient(app_env.app) as client:
        _login_as(client, "payer", "payments-ops")
        r = client.post(f"/trust-anchors/{anchor_id}/delete", follow_redirects=False)
    assert r.status_code == 303
    assert "error" in r.headers["location"]
    assert len(SqliteTrustAnchorRepository(app_env.db).list_entries()) == 1


def test_admin_can_delete_trust_anchor(app_env, chain_pem_file):
    anchor_id = _stored_anchor(app_env.db, chain_pem_file)
    with TestClient(app_env.app) as client:
        _login_as(client, "admin", "admin")
        r = client.post(f"/trust-anchors/{anchor_id}/delete", follow_redirects=False)
    assert r.headers["location"] == "/settings/trust-anchors?saved=1"
    assert SqliteTrustAnchorRepository(app_env.db).list_entries() == []


def test_trust_anchor_add_enforces_csrf_for_admin(app_env, chain_pem_file, csrf_strict):
    with TestClient(app_env.app) as client, open(chain_pem_file, "rb") as f:
        _login_as(client, "admin", "admin")
        r = client.post(
            "/trust-anchors",
            files={"file": ("bundle.pem", f, "application/x-pem-file")},
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "error" in r.headers["location"]
    assert SqliteTrustAnchorRepository(app_env.db).list_entries() == []


# ---------- #69: scope checks are case-insensitive ----------


def _scoped_request(scope_tag: str, tag_tiers: dict[str, str] | None = None):
    ctx = AuthContext.from_tier(
        "payer", tier="viewer", scope_tag=scope_tag, tag_tiers=tag_tiers or {},
    )
    return SimpleNamespace(state=SimpleNamespace(auth_context=ctx))


class TestScopeGatesCasefold:
    @pytest.fixture
    def host_id(self, db):
        return SqliteHostRepository(db).add("pay.example.com", 443, tags="payments")

    def test_read_gate_matches_case_insensitively(self, db, host_id):
        from cert_watch.routes._scoped import scope_read_denied

        req = _scoped_request("Payments")
        assert scope_read_denied(req, db, host_id=host_id) is None

    def test_write_gate_matches_case_insensitively(self, db, host_id):
        from cert_watch.routes._scoped import scope_write_denied

        req = _scoped_request("Payments", {"Payments": "operator"})
        assert scope_write_denied(req, db, host_id=host_id) is None

    def test_write_gate_still_denies_out_of_scope(self, db):
        from cert_watch.routes._scoped import scope_write_denied

        other = SqliteHostRepository(db).add("hr.example.com", 443, tags="hr")
        req = _scoped_request("Payments", {"Payments": "operator"})
        assert scope_write_denied(req, db, host_id=other) is not None

    def test_enforce_scope_tag_case_insensitive(self):
        from cert_watch.routes._scoped import enforce_scope_tag

        req = _scoped_request("Payments")
        assert enforce_scope_tag(req, "payments") is None
        assert enforce_scope_tag(req, "hr") is not None

    def test_new_tags_case_insensitive(self):
        from cert_watch.routes._scoped import scope_new_tags_denied

        req = _scoped_request("Payments")
        assert scope_new_tags_denied(req, "PAYMENTS") is None
        assert scope_new_tags_denied(req, "payments,hr") is not None


def test_may_write_tags_case_insensitive():
    ctx = AuthContext.from_tier(
        "payer", tier="viewer", scope_tag="Payments", tag_tiers={"Payments": "operator"},
    )
    assert ctx.may_write_tags({"payments"}) is True
    assert ctx.may_write_tags({"hr"}) is False


# ---------- #69: pending hosts survive the scoped pivot drill-down ----------


def test_scoped_issuer_pivot_drilldown_includes_pending_host(db):
    from cert_watch.database import get_pivot_group_entries

    SqliteHostRepository(db).add("never-scanned.example.com", 443, tags="payments")
    admin = get_pivot_group_entries(db, "issuer", "Unknown")
    scoped = get_pivot_group_entries(db, "issuer", "Unknown", scope_tags=("payments",))
    assert len(admin) == 1
    assert [e["host"] for e in scoped] == ["never-scanned.example.com:443"]


def test_scoped_owner_pivot_drilldown_includes_pending_host(db):
    """Also covers the owner/renewal-method loader, whose ``h.``-prefixed host
    filter ran against an un-aliased ``hosts`` table and raised."""
    from cert_watch.database import get_pivot_group_entries

    SqliteHostRepository(db).add(
        "never-scanned.example.com", 443, tags="payments", owner_name="alice",
    )
    admin = get_pivot_group_entries(db, "owner", "alice")
    scoped = get_pivot_group_entries(db, "owner", "alice", scope_tags=("payments",))
    assert [e["host"] for e in admin] == ["never-scanned.example.com:443"]
    assert [e["host"] for e in scoped] == ["never-scanned.example.com:443"]
    assert get_pivot_group_entries(db, "owner", "alice", scope_tags=("hr",)) == []


# ---------- /scan-history is scope-filtered ----------


def _seed_scan_history(db: Path) -> None:
    from cert_watch.scheduler import ScanHistory, record_scan_history

    hosts = SqliteHostRepository(db)
    hosts.add("pay.example.com", 443, tags="payments")
    hosts.add("secret-hr.example.com", 443, tags="hr")
    now = datetime.now(UTC) - timedelta(minutes=1)
    for host, err in (("pay.example.com", "pay-timeout"), ("secret-hr.example.com", "hr-refused")):
        record_scan_history(
            db,
            ScanHistory(
                hostname=host, port=443, status="failure", scanned_at=now, error_message=err,
            ),
        )


def test_scan_history_hides_out_of_scope_hosts(app_env):
    _seed_scan_history(app_env.db)
    with TestClient(app_env.app) as client:
        _login_as(client, "viewer", "payments-view")
        r = client.get("/scan-history")
    assert r.status_code == 200
    assert "pay.example.com" in r.text
    assert "secret-hr.example.com" not in r.text
    assert "hr-refused" not in r.text


def test_scan_history_admin_sees_all_hosts(app_env):
    _seed_scan_history(app_env.db)
    with TestClient(app_env.app) as client:
        _login_as(client, "admin", "admin")
        r = client.get("/scan-history")
    assert r.status_code == 200
    assert "pay.example.com" in r.text
    assert "secret-hr.example.com" in r.text


def test_list_scan_batches_scope_filter_casefolds(db):
    from cert_watch.database import list_scan_batches

    _seed_scan_history(db)
    batches, total = list_scan_batches(db, scope_tags=("PAYMENTS",))
    assert total == 1
    assert [h["hostname"] for h in batches[0]["hosts"]] == ["pay.example.com"]
    all_batches, _ = list_scan_batches(db)
    assert len(all_batches[0]["hosts"]) == 2


# ---------- #69 end to end: mixed-case scope, scanned + pending hosts ----------


def _seed_mixed_fleet(db: Path) -> str:
    """Three scanned hosts and one never-scanned host, all tagged ``payments``
    and owned by alice, plus one out-of-scope ``hr`` host. The role scope in
    ``_seed`` is ``Payments`` (different case), which is the issue's scenario.
    Returns the pending host's id."""
    from cert_watch.certificate_model import Certificate
    from cert_watch.database import replace_scanned

    hosts = SqliteHostRepository(db)
    now = datetime.now(UTC)
    for name, tags in (
        ("pay-a.example.com", "payments"),
        ("pay-b.example.com", "payments"),
        ("pay-c.example.com", "payments"),
        ("hr.example.com", "hr"),
    ):
        host_id = hosts.add(name, 443, tags=tags)
        hosts.update_owner(host_id, owner_name="alice")
        cert = Certificate(
            subject=f"CN={name}",
            issuer="O=DigiCert,CN=SHA2",
            not_before=now - timedelta(days=1),
            not_after=now + timedelta(days=60),
            san_dns_names=[name],
            fingerprint_sha256=name,
        )
        replace_scanned(db, name, 443, cert, [], True)
    pending = hosts.add("pay-pending.example.com", 443, tags="payments")
    hosts.update_owner(pending, owner_name="alice")
    return pending


@pytest.mark.parametrize("pivot", ["issuer", "owner", "renewal_method"])
def test_scoped_pivot_drilldown_count_matches_pivot_count(app_env, pivot):
    """#69: for a scoped user the drill-down returns every host the pivot
    table counts, including the pending one, with scope and tag in
    different case."""
    from cert_watch.database import list_fleet_pivot

    _seed_mixed_fleet(app_env.db)
    groups = list_fleet_pivot(app_env.db, pivot, scope_tags=("Payments",))
    assert sum(g["count"] for g in groups) == 4
    with TestClient(app_env.app) as client:
        _login_as(client, "viewer", "payments-view")
        for group in groups:
            r = client.get(f"/api/pivot/{pivot}/{group['key']}")
            assert r.status_code == 200
            hosts = [e["host"] for e in r.json()["entries"]]
            assert len(hosts) == group["count"], (group["key"], hosts)
            assert "hr.example.com:443" not in hosts
    if pivot == "owner":
        assert "pay-pending.example.com:443" in hosts


def test_scoped_user_opens_host_tagged_in_different_case(app_env):
    """#69: a row the scoped list shows (tag ``payments``, scope ``Payments``)
    opens instead of redirecting to "certificate not found"."""
    pending = _seed_mixed_fleet(app_env.db)
    with TestClient(app_env.app) as client:
        _login_as(client, "viewer", "payments-view")
        ok = client.get(f"/certificates/{pending}", follow_redirects=False)
        issuers = client.get(f"/api/hosts/{pending}/issuers")
    assert ok.status_code == 200
    assert "pay-pending.example.com" in ok.text
    assert issuers.status_code == 200
