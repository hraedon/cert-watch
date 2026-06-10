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
    assert "Policy" in r.text or "policy" in r.text


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