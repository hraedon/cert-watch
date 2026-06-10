"""Tests for event API routes (Plan 044)."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient

from cert_watch.database import init_schema
from cert_watch.events import Event, emit_event


def _client(reload_app):
    app_mod = reload_app()
    return TestClient(app_mod.app)


def test_api_events_list(reload_app, tmp_path):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(str(db))
    for i in range(3):
        emit_event(
            Event(
                event_type="cert_added",
                timestamp=datetime.now(UTC),
                payload={"i": i},
                source="scan",
            ),
            str(db),
        )
    with _client(reload_app) as client:
        r = client.get("/api/events")
    assert r.status_code == 200
    data = r.json()
    assert "events" in data
    assert len(data["events"]) == 3


def test_api_events_filter_by_type(reload_app, tmp_path):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(str(db))
    emit_event(
        Event(event_type="cert_added", timestamp=datetime.now(UTC), payload={}, source="scan"),
        str(db),
    )
    emit_event(
        Event(event_type="scan_failed", timestamp=datetime.now(UTC), payload={}, source="scan"),
        str(db),
    )
    with _client(reload_app) as client:
        r = client.get("/api/events", params={"event_type": "cert_added"})
    assert r.status_code == 200
    events = r.json()["events"]
    assert len(events) == 1
    assert events[0]["event_type"] == "cert_added"


def test_api_events_filter_by_source(reload_app, tmp_path):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(str(db))
    emit_event(
        Event(event_type="cert_added", timestamp=datetime.now(UTC), payload={}, source="scan"),
        str(db),
    )
    emit_event(
        Event(event_type="cert_added", timestamp=datetime.now(UTC), payload={}, source="upload"),
        str(db),
    )
    with _client(reload_app) as client:
        r = client.get("/api/events", params={"source": "upload"})
    assert r.status_code == 200
    events = r.json()["events"]
    assert len(events) == 1
    assert events[0]["source"] == "upload"


def test_api_events_pagination(reload_app, tmp_path):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(str(db))
    for i in range(5):
        emit_event(
            Event(
                event_type="cert_added",
                timestamp=datetime.now(UTC),
                payload={"i": i},
                source="scan",
            ),
            str(db),
        )
    with _client(reload_app) as client:
        r = client.get("/api/events", params={"limit": 2, "offset": 0})
    assert r.status_code == 200
    assert len(r.json()["events"]) == 2


def test_api_events_failed_deliveries(reload_app, tmp_path):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(str(db))
    from cert_watch.database.connection import _connect

    with _connect(str(db)) as conn:
        conn.execute(
            "INSERT INTO event_log"
            " (event_type, timestamp, source, payload,"
            " delivery_status, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (
                "cert_added", datetime.now(UTC).isoformat(),
                "scan", "{}", "failed",
                datetime.now(UTC).isoformat(),
            ),
        )
        conn.commit()
    with _client(reload_app) as client:
        r = client.get("/api/events/failed")
    assert r.status_code == 200
    events = r.json()["events"]
    assert len(events) == 1
    assert events[0]["delivery_status"] == "failed"


def test_api_events_stream_is_registered(reload_app):
    from cert_watch.routes.api.events import router

    routes = [r.path for r in router.routes]
    assert "/api/events" in routes
    assert "/api/events/stream" in routes
    assert "/api/events/failed" in routes


def test_settings_events_page(reload_app):
    with _client(reload_app) as client:
        r = client.get("/settings/events")
    assert r.status_code == 200
    assert "event" in r.text.lower()


def test_settings_events_save(reload_app, login_csrf, tmp_path):
    with _client(reload_app) as client:
        csrf = login_csrf(client)
        r = client.post(
            "/settings/events",
            data={
                "_csrf_token": csrf,
                "enabled_event_types": ["cert_added", "scan_failed"],
                "webhook_url": "https://example.com/hook",
                "webhook_kind": "discord",
                "rate_limit_per_second": "5",
            },
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "/settings/events" in r.headers["location"]
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(str(db))
    from cert_watch.events import load_event_config

    config = load_event_config(str(db))
    assert "cert_added" in config.enabled_event_types
    assert config.webhook_kind == "discord"
    assert config.rate_limit_per_second == 5


# ---------- Auth-gating tests (WI-015) ----------


def test_api_events_list_auth_required(reload_app):
    """GET /api/events returns 401 when unauthenticated (require_auth dependency)."""
    app_mod = reload_app(AUTH_PROVIDER="none", CERT_WATCH_ALLOW_UNAUTH="0")
    with TestClient(app_mod.app) as client:
        r = client.get("/api/events")
    assert r.status_code == 401
    assert r.json()["error"] == "unauthenticated"


def test_api_events_stream_auth_required(reload_app):
    """GET /api/events/stream returns 401 when unauthenticated (require_auth dependency)."""
    app_mod = reload_app(AUTH_PROVIDER="none", CERT_WATCH_ALLOW_UNAUTH="0")
    with TestClient(app_mod.app) as client:
        r = client.get("/api/events/stream")
    assert r.status_code == 401
    assert r.json()["error"] == "unauthenticated"


def test_api_events_failed_auth_required(reload_app):
    """GET /api/events/failed returns 401 when unauthenticated (require_auth dependency)."""
    app_mod = reload_app(AUTH_PROVIDER="none", CERT_WATCH_ALLOW_UNAUTH="0")
    with TestClient(app_mod.app) as client:
        r = client.get("/api/events/failed")
    assert r.status_code == 401
    assert r.json()["error"] == "unauthenticated"


def test_api_events_list_viewer_can_read(tmp_path):
    """A viewer-role user can read GET /api/events (require_auth, not require_admin)."""
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
        r = client.get("/api/events")
    assert r.status_code == 200


def test_api_events_stream_has_require_auth_dep():
    """The SSE endpoint uses require_auth (not require_admin), so viewers can connect.

    We verify the dependency directly rather than making a request, because
    EventSourceResponse keeps the connection open and would hang TestClient.
    """
    from cert_watch.routes.api.events import router

    route = next(r for r in router.routes if r.path == "/api/events/stream")
    dep = route.dependant.dependencies[0]
    assert dep.call.__name__ == "require_auth"