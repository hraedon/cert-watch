"""WI-059 — server-rendered alert-group CRUD (routes/settings/alert_groups.py).

The JSON /api/alert-groups CRUD is covered elsewhere; this exercises the
form-based Settings UI paths: create/list/update/delete, validation, and audit.
CSRF and the admin gate are relaxed by the autouse ``_isolated_data_dir``
fixture (_CSRF_BYPASS + ALLOW_UNAUTH).
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from cert_watch.database import SqliteAlertGroupRepository
from cert_watch.database.connection import _connect


def _db(tmp_path):
    return tmp_path / "cert-watch.sqlite3"


def _groups(tmp_path):
    return SqliteAlertGroupRepository(_db(tmp_path)).list_all()


def _audit_actions(tmp_path):
    with _connect(_db(tmp_path)) as conn:
        rows = conn.execute("SELECT action FROM audit_log ORDER BY id DESC").fetchall()
    return [r["action"] for r in rows]


def test_create_and_list_alert_group(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/alert-groups",
            data={
                "name": "platform-team",
                "match_tags": "platform-team, prod",
                "recipients": "ops@example.com, lead@example.com",
                "threshold_days": "14",
                "digest_cadence_days": "3",
            },
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert r.headers["location"] == "/settings?tab=alert-groups&saved=1"
        page = client.get("/settings/alert-groups").text

    groups = _groups(tmp_path)
    assert len(groups) == 1
    g = groups[0]
    assert g.name == "platform-team"
    assert g.match_tags == ["platform-team", "prod"]
    assert g.recipients == ["ops@example.com", "lead@example.com"]
    assert g.threshold_days == 14
    assert g.digest_cadence_days == 3
    assert "platform-team" in page
    assert "alert_group.create" in _audit_actions(tmp_path)


def test_name_required(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/alert-groups",
            data={"name": "  ", "recipients": "ops@example.com"},
            follow_redirects=False,
        )
    assert "error=" in r.headers["location"]
    assert _groups(tmp_path) == []


def test_invalid_recipient_email_rejected(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/alert-groups",
            data={"name": "x", "recipients": "not-an-email"},
            follow_redirects=False,
        )
    assert "error=" in r.headers["location"]
    assert _groups(tmp_path) == []


def test_duplicate_name_rejected(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        base = {"name": "team-a", "recipients": "a@example.com"}
        client.post("/settings/alert-groups", data=base, follow_redirects=False)
        r = client.post("/settings/alert-groups", data=base, follow_redirects=False)
    assert "already+exists" in r.headers["location"] or "already%20exists" in r.headers["location"]
    assert len(_groups(tmp_path)) == 1


def test_threshold_must_be_positive(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/alert-groups",
            data={"name": "x", "recipients": "a@example.com", "threshold_days": "0"},
            follow_redirects=False,
        )
    assert "error=" in r.headers["location"]
    assert _groups(tmp_path) == []


def test_empty_threshold_means_none(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        client.post(
            "/settings/alert-groups",
            data={"name": "x", "recipients": "a@example.com", "threshold_days": ""},
            follow_redirects=False,
        )
    g = _groups(tmp_path)[0]
    assert g.threshold_days is None
    assert g.digest_cadence_days == 7  # default when omitted


def test_update_alert_group(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        client.post(
            "/settings/alert-groups",
            data={"name": "old", "match_tags": "a", "recipients": "a@example.com"},
            follow_redirects=False,
        )
        gid = _groups(tmp_path)[0].id
        r = client.post(
            f"/settings/alert-groups/{gid}",
            data={"name": "new", "match_tags": "b, c", "recipients": "b@example.com",
                  "digest_cadence_days": "14"},
            follow_redirects=False,
        )
        assert r.headers["location"] == "/settings?tab=alert-groups&saved=1"
    g = _groups(tmp_path)[0]
    assert g.name == "new"
    assert g.match_tags == ["b", "c"]
    assert g.digest_cadence_days == 14
    assert "alert_group.update" in _audit_actions(tmp_path)


def test_delete_alert_group(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        client.post(
            "/settings/alert-groups",
            data={"name": "doomed", "recipients": "a@example.com"},
            follow_redirects=False,
        )
        gid = _groups(tmp_path)[0].id
        client.post(f"/settings/alert-groups/{gid}/delete", follow_redirects=False)
    assert _groups(tmp_path) == []
    assert "alert_group.delete" in _audit_actions(tmp_path)


def test_update_nonexistent_group_errors(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/alert-groups/00000000-0000-0000-0000-000000000000",
            data={"name": "x", "recipients": "a@example.com"},
            follow_redirects=False,
        )
    assert "not+found" in r.headers["location"] or "not%20found" in r.headers["location"]


def test_update_to_existing_name_rejected(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        client.post("/settings/alert-groups", data={"name": "team-a"}, follow_redirects=False)
        client.post("/settings/alert-groups", data={"name": "team-b"}, follow_redirects=False)
        team_b = next(g for g in _groups(tmp_path) if g.name == "team-b")
        r = client.post(
            f"/settings/alert-groups/{team_b.id}",
            data={"name": "team-a"},  # collide with the other group
            follow_redirects=False,
        )
    assert "already" in r.headers["location"]
    # team-b unchanged (rename rejected)
    assert {g.name for g in _groups(tmp_path)} == {"team-a", "team-b"}


def test_webhook_url_validated(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/alert-groups",
            data={"name": "x", "recipients": "a@example.com", "webhook_url": "ftp://nope.example"},
            follow_redirects=False,
        )
    assert "error=" in r.headers["location"]
    assert _groups(tmp_path) == []


def test_non_numeric_threshold_rejected(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/alert-groups",
            data={"name": "x", "recipients": "a@example.com", "threshold_days": "soon"},
            follow_redirects=False,
        )
    assert "error=" in r.headers["location"]
    assert _groups(tmp_path) == []


def test_create_csrf_failure_does_not_mutate(reload_app, csrf_strict, tmp_path, monkeypatch):
    """With CSRF enabled and no token, create must redirect with an error and not
    write a group or an audit row (guards mutate-then-check-CSRF reordering)."""
    monkeypatch.setenv("CERT_WATCH_COOKIE_SECURE", "0")
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/alert-groups",
            data={"name": "csrf-leak", "recipients": "a@example.com"},
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "csrf" in r.headers["location"].lower()
    assert _groups(tmp_path) == []
    assert "alert_group.create" not in _audit_actions(tmp_path)
