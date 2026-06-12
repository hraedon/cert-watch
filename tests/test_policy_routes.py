"""Tests for policy API and settings routes (Plan 042 / WI-5)."""

from __future__ import annotations

from fastapi.testclient import TestClient


def _reload(reload_app):
    return reload_app()


def test_get_api_policy_returns_default(reload_app):
    app_mod = _reload(reload_app)
    with TestClient(app_mod.app) as client:
        r = client.get("/api/policy")
    assert r.status_code == 200
    data = r.json()
    assert "rules" in data
    assert "default_severity" in data
    assert isinstance(data["rules"], list)
    rule_ids = [r["rule_id"] for r in data["rules"]]
    assert "key_size_rsa" in rule_ids


def test_put_api_policy_saves_and_reloads(reload_app):
    app_mod = _reload(reload_app)
    with TestClient(app_mod.app) as client:
        r = client.get("/api/policy")
        original = r.json()
        new_rules = original["rules"].copy()
        for rule in new_rules:
            if rule["rule_id"] == "key_size_rsa":
                rule["enabled"] = True
                rule["severity"] = "critical"
        r = client.put("/api/policy", json={
            "default_severity": original["default_severity"],
            "rules": new_rules,
        })
    assert r.status_code == 200
    data = r.json()
    rsa_rule = next(r for r in data["rules"] if r["rule_id"] == "key_size_rsa")
    assert rsa_rule["enabled"] is True
    assert rsa_rule["severity"] == "critical"


def test_get_api_policy_violations_empty(reload_app):
    app_mod = _reload(reload_app)
    with TestClient(app_mod.app) as client:
        r = client.get("/api/reports/policy-violations")
    assert r.status_code == 200
    data = r.json()
    assert "violations" in data
    assert isinstance(data["violations"], list)


def test_get_api_policy_violations_csv(reload_app):
    app_mod = _reload(reload_app)
    with TestClient(app_mod.app) as client:
        r = client.get("/api/reports/policy-violations?format=csv")
    assert r.status_code == 200
    assert "text/csv" in r.headers.get("content-type", "")


def test_put_api_policy_invalid_json(reload_app):
    app_mod = _reload(reload_app)
    with TestClient(app_mod.app) as client:
        r = client.put(
            "/api/policy",
            content=b"not json",
            headers={"Content-Type": "application/json"},
        )
    assert r.status_code == 400


def test_put_api_policy_invalid_default_severity(reload_app):
    app_mod = _reload(reload_app)
    with TestClient(app_mod.app) as client:
        r = client.put("/api/policy", json={
            "default_severity": "invalid",
            "rules": [],
        })
    assert r.status_code == 400
    assert "severity" in r.json()["error"].lower()


def test_put_api_policy_invalid_rule_severity(reload_app):
    app_mod = _reload(reload_app)
    with TestClient(app_mod.app) as client:
        r = client.get("/api/policy")
        original = r.json()
        rules = original["rules"][:1]
        rules[0]["severity"] = "bogus"
        r = client.put("/api/policy", json={
            "default_severity": "warning",
            "rules": rules,
        })
    assert r.status_code == 400


def test_put_api_policy_invalid_parameters(reload_app):
    app_mod = _reload(reload_app)
    with TestClient(app_mod.app) as client:
        r = client.put("/api/policy", json={
            "default_severity": "warning",
            "rules": [
                {
                    "rule_id": "key_size_rsa",
                    "category": "key",
                    "severity": "critical",
                    "enabled": True,
                    "parameters": {"min_rsa": -1},
                },
            ],
        })
    assert r.status_code == 400

    r = client.put("/api/policy", json={
        "default_severity": "warning",
        "rules": [
            {
                "rule_id": "validity_max_days",
                "category": "validity",
                "severity": "warning",
                "enabled": True,
                "parameters": {"max_days": 0},
            },
        ],
    })
    assert r.status_code == 400


def test_settings_policy_page(reload_app):
    app_mod = _reload(reload_app)
    with TestClient(app_mod.app) as client:
        r = client.get("/settings?tab=policy")
    assert r.status_code == 200
    assert 'id="tab-policy"' in r.text or 'name="policy_packs' in r.text


def test_settings_policy_save(reload_app):
    app_mod = _reload(reload_app)
    with TestClient(app_mod.app) as client:
        r = client.get("/settings?tab=policy")
        assert r.status_code == 200
        form_data = {
            "_csrf_token": "unused",
            "default_severity": "warning",
            "rule_id": ["key_size_rsa", "hash_algorithm"],
            "category_key_size_rsa": "key",
            "severity_key_size_rsa": "critical",
            "enabled_key_size_rsa": "1",
            "min_rsa_key_size_rsa": "2048",
            "category_hash_algorithm": "hash",
            "severity_hash_algorithm": "critical",
        }
        r = client.post("/settings/policy", data=form_data, follow_redirects=False)
    assert r.status_code == 303
    assert "tab=policy" in r.headers.get("location", "")


# ---------- Auth-gating tests (WI-015) ----------


def test_api_policy_get_auth_required(reload_app):
    """GET /api/policy returns 401 when unauthenticated (require_auth dependency)."""
    app_mod = reload_app(AUTH_PROVIDER="none", CERT_WATCH_ALLOW_UNAUTH="0")
    with TestClient(app_mod.app) as client:
        r = client.get("/api/policy")
    assert r.status_code == 401
    assert r.json()["error"] == "unauthenticated"


def test_api_policy_put_auth_required(reload_app):
    """PUT /api/policy returns 401 when unauthenticated (require_admin dependency)."""
    app_mod = reload_app(AUTH_PROVIDER="none", CERT_WATCH_ALLOW_UNAUTH="0")
    with TestClient(app_mod.app) as client:
        r = client.put("/api/policy", json={
            "default_severity": "warning",
            "rules": [],
        })
    assert r.status_code == 401
    assert r.json()["error"] == "unauthenticated"


def test_api_policy_violations_json_auth_required(reload_app):
    """GET /api/reports/policy-violations (JSON) returns 401 when unauthenticated."""
    app_mod = reload_app(AUTH_PROVIDER="none", CERT_WATCH_ALLOW_UNAUTH="0")
    with TestClient(app_mod.app) as client:
        r = client.get("/api/reports/policy-violations")
    assert r.status_code == 401
    assert r.json()["error"] == "unauthenticated"


def test_api_policy_violations_csv_auth_required(reload_app):
    """GET /api/reports/policy-violations?format=csv returns 401 when unauthenticated."""
    app_mod = reload_app(AUTH_PROVIDER="none", CERT_WATCH_ALLOW_UNAUTH="0")
    with TestClient(app_mod.app) as client:
        r = client.get("/api/reports/policy-violations?format=csv")
    assert r.status_code == 401
    assert r.json()["error"] == "unauthenticated"


# ---------- Role-differentiated auth tests (WI-015) ----------


def test_api_policy_get_viewer_can_read(tmp_path):
    """A viewer-role user can read GET /api/policy (require_auth, not require_admin)."""
    from cert_watch.app import create_app
    from cert_watch.auth import SESSION_COOKIE, create_session
    from cert_watch.config import Settings

    s = Settings(
        db_path=tmp_path / "db.sqlite3",
        data_dir=tmp_path,
        role_map={
            "admin": {"groups": ["g-admins"]},
            "viewer": {"groups": ["g-viewers"]},
        },
    )

    class _Provider:
        provider_name = "mock"

    app = create_app(auth_provider=_Provider(), settings=s)
    token = create_session("viewer_user", groups=["g-viewers"])
    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE, token)
        r = client.get("/api/policy")
    assert r.status_code == 200
    assert "rules" in r.json()


def test_api_policy_put_viewer_forbidden(tmp_path):
    """A viewer-role user cannot PUT /api/policy (require_admin dependency → 403)."""
    from cert_watch.app import create_app
    from cert_watch.auth import SESSION_COOKIE, create_session
    from cert_watch.config import Settings

    s = Settings(
        db_path=tmp_path / "db.sqlite3",
        data_dir=tmp_path,
        role_map={
            "admin": {"groups": ["g-admins"]},
            "viewer": {"groups": ["g-viewers"]},
        },
    )

    class _Provider:
        provider_name = "mock"

    app = create_app(auth_provider=_Provider(), settings=s)
    token = create_session("viewer_user", groups=["g-viewers"])
    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE, token)
        r = client.put("/api/policy", json={
            "default_severity": "warning",
            "rules": [],
        })
    assert r.status_code == 403
    assert "admin required" in r.json()["detail"]


def test_api_policy_put_admin_allowed(tmp_path):
    """An admin-role user can PUT /api/policy and the change persists.

    WI-017: PUT now merges incoming rules with existing rules by rule_id,
    so the test_rule is added to the default 11 rules (→ 12 total).
    """
    from cert_watch.app import create_app
    from cert_watch.auth import SESSION_COOKIE, create_session
    from cert_watch.config import Settings

    s = Settings(
        db_path=tmp_path / "db.sqlite3",
        data_dir=tmp_path,
        role_map={
            "admin": {"groups": ["g-admins"]},
        },
    )

    class _Provider:
        provider_name = "mock"

    app = create_app(auth_provider=_Provider(), settings=s)
    token = create_session("admin_user", groups=["g-admins"])
    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE, token)
        r = client.put("/api/policy", json={
            "default_severity": "warning",
            "rules": [{
                "rule_id": "test_rule",
                "category": "custom",
                "severity": "critical",
                "enabled": True,
                "parameters": {},
            }],
        })
        assert r.status_code == 200

        # Verify the policy was actually persisted (merge: default 11 + 1 new = 12)
        r2 = client.get("/api/policy")
        assert r2.status_code == 200
        body = r2.json()
        assert body["default_severity"] == "warning"
        rule_ids = [r["rule_id"] for r in body["rules"]]
        assert "test_rule" in rule_ids
        test_rule = next(r for r in body["rules"] if r["rule_id"] == "test_rule")
        assert test_rule["severity"] == "critical"
        assert test_rule["enabled"] is True


def test_api_policy_violations_viewer_can_read(tmp_path):
    """A viewer can read GET /api/reports/policy-violations (require_auth, not admin)."""
    from cert_watch.app import create_app
    from cert_watch.auth import SESSION_COOKIE, create_session
    from cert_watch.config import Settings

    s = Settings(
        db_path=tmp_path / "db.sqlite3",
        data_dir=tmp_path,
        role_map={
            "admin": {"groups": ["g-admins"]},
            "viewer": {"groups": ["g-viewers"]},
        },
    )

    class _Provider:
        provider_name = "mock"

    app = create_app(auth_provider=_Provider(), settings=s)
    token = create_session("viewer_user", groups=["g-viewers"])
    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE, token)
        r = client.get("/api/reports/policy-violations")
    assert r.status_code == 200
    assert "violations" in r.json()


def test_api_policy_violations_csv_viewer_can_read(tmp_path):
    """A viewer-role user can read GET /api/reports/policy-violations?format=csv (require_auth)."""
    from cert_watch.app import create_app
    from cert_watch.auth import SESSION_COOKIE, create_session
    from cert_watch.config import Settings

    s = Settings(
        db_path=tmp_path / "db.sqlite3",
        data_dir=tmp_path,
        role_map={
            "admin": {"groups": ["g-admins"]},
            "viewer": {"groups": ["g-viewers"]},
        },
    )

    class _Provider:
        provider_name = "mock"

    app = create_app(auth_provider=_Provider(), settings=s)
    token = create_session("viewer_user", groups=["g-viewers"])
    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE, token)
        r = client.get("/api/reports/policy-violations?format=csv")
    assert r.status_code == 200
    assert "text/csv" in r.headers.get("content-type", "")


def test_api_policy_put_operator_forbidden(tmp_path):
    """An operator-role user cannot PUT /api/policy (require_admin → 403)."""
    from cert_watch.app import create_app
    from cert_watch.auth import SESSION_COOKIE, create_session
    from cert_watch.config import Settings

    s = Settings(
        db_path=tmp_path / "db.sqlite3",
        data_dir=tmp_path,
        role_map={
            "admin": {"groups": ["g-admins"]},
            "operator": {"groups": ["g-operators"]},
        },
    )

    class _Provider:
        provider_name = "mock"

    app = create_app(auth_provider=_Provider(), settings=s)
    token = create_session("operator_user", groups=["g-operators"])
    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE, token)
        r = client.put("/api/policy", json={
            "default_severity": "warning",
            "rules": [],
        })
    assert r.status_code == 403
    assert "admin required" in r.json()["detail"]