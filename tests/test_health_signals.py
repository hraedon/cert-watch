"""/api/health reflects failing delivery and unscanned endpoints (#113 item 8)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient


def _alert(db, alert_id: str, status: str) -> None:
    from cert_watch.database.connection import _connect

    with _connect(db) as conn:
        conn.execute(
            "INSERT INTO alerts (id, cert_id, alert_type, status, message, created_at,"
            " hostname, subject) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (alert_id, "c-" + alert_id, "expiry_warning", status, "expires soon",
             datetime.now(UTC).isoformat(), "h.example.invalid", "CN=h.example.invalid"),
        )
        conn.commit()


def _attempt(db, alert_id: str, outcome: str, *, age: timedelta = timedelta(0)) -> None:
    from cert_watch.database.connection import _connect
    from cert_watch.database.delivery_evidence import begin_attempt, complete_attempt

    attempt = begin_attempt(db, alert_id, "webhook", {"recipients": []})
    complete_attempt(db, attempt, {
        "outcome": outcome, "reason": "" if outcome == "accepted" else "http_status",
        "accepted": [], "refused": [], "http_status": 200 if outcome == "accepted" else 500,
    })
    if age:
        # The ledger refuses edits by design; age the rows by rebuilding them.
        with _connect(db) as conn:
            rows = conn.execute(
                "SELECT * FROM alert_delivery_events WHERE attempt_id = ?", (attempt,)
            ).fetchall()
            conn.execute("DELETE FROM alert_delivery_events WHERE attempt_id = ?", (attempt,))
            for r in rows:
                conn.execute(
                    "INSERT INTO alert_delivery_events (attempt_id, alert_id, occurred_at,"
                    " event_kind, channel, details) VALUES (?, ?, ?, ?, ?, ?)",
                    (r["attempt_id"], r["alert_id"],
                     (datetime.now(UTC) - age).isoformat(), r["event_kind"],
                     r["channel"], r["details"]),
                )
            conn.commit()


def test_failed_webhook_attempts_count_while_the_alert_retries(tmp_path, reload_app):
    """Three HTTP 500s leave the alert pending with backoff, not failed. It is
    still an alert whose delivery failed, and the strip must say so."""
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    with TestClient(app_mod.app) as client:
        _alert(db, "retrying", "pending")
        for _ in range(3):
            _attempt(db, "retrying", "failed")
        # Recovered on a retry: delivered, not failing.
        _alert(db, "recovered", "sent")
        _attempt(db, "recovered", "failed")
        _attempt(db, "recovered", "accepted")
        # Failed, then accepted on a later attempt that has not settled yet.
        _alert(db, "settling", "pending")
        _attempt(db, "settling", "failed")
        _attempt(db, "settling", "accepted")
        # Failed attempt outside the 24h window.
        _alert(db, "old", "pending")
        _attempt(db, "old", "failed", age=timedelta(hours=30))
        data = client.get("/api/health").json()
    assert data["failed_alerts_24h"] == 1
    assert data["overall"] == "warning"


def _give_up(db, alert_id: str, *, attempts: int, when: datetime) -> None:
    """Fail *alert_id* the way the dispatcher does: claim it, then give up."""
    from cert_watch.database.alert_store import AlertStore

    store = AlertStore(db)
    claimed = store.claim(
        lease_owner="test-worker", lease_expires_at=when + timedelta(minutes=5), now=when,
    )
    assert alert_id in {a.id for a in claimed}
    assert store.complete_failed(
        alert_id, lease_owner="test-worker", attempts=attempts, now=when,
        failure_reason="evidence_unavailable", error_message="gave up",
    )


def test_gave_up_alerts_still_count(tmp_path, reload_app):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"

    with TestClient(app_mod.app) as client:
        _alert(db, "gave-up", "pending")
        _give_up(db, "gave-up", attempts=3, when=datetime.now(UTC) - timedelta(hours=1))
        data = client.get("/api/health").json()
    assert data["failed_alerts_24h"] == 1


def test_alert_that_gave_up_without_an_attempt_counts(tmp_path, reload_app):
    """The bounded evidence deferral fails an alert with zero attempts, so
    ``last_attempt_at`` stays empty. It still gave up just now, and the strip
    must not stay green (#113 review)."""
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"

    with TestClient(app_mod.app) as client:
        _alert(db, "deferred-out", "pending")
        _give_up(db, "deferred-out", attempts=0, when=datetime.now(UTC))
        # Gave up two days ago: outside the window.
        _alert(db, "long-ago", "pending")
        _give_up(db, "long-ago", attempts=0, when=datetime.now(UTC) - timedelta(hours=48))
        data = client.get("/api/health").json()
        metrics = client.get("/metrics").text
    assert data["failed_alerts_24h"] == 1
    assert data["overall"] == "warning"
    assert "cert_watch_alerts_failed_recent 1.0" in metrics


def test_retried_alert_forgets_when_it_failed(tmp_path):
    from cert_watch.database import init_schema
    from cert_watch.database.alert_store import AlertStore
    from cert_watch.database.connection import _connect

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    _alert(db, "retry-me", "pending")
    _give_up(db, "retry-me", attempts=0, when=datetime.now(UTC))
    AlertStore(db).reset_pending_compat("retry-me")
    with _connect(db) as conn:
        row = conn.execute("SELECT status, failed_at FROM alerts WHERE id = 'retry-me'").fetchone()
    assert (row["status"], row["failed_at"]) == ("pending", None)


def test_unscanned_endpoint_is_not_a_healthy_pipeline(tmp_path, reload_app):
    from cert_watch.database import SqliteHostRepository

    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    with TestClient(app_mod.app) as client:
        assert client.get("/api/health").json()["overall"] == "ok"
        SqliteHostRepository(db).add("never.example.test", 443)
        data = client.get("/api/health").json()
    assert data["endpoints_without_successful_scan"] == 1
    assert data["overall"] == "warning"


def test_health_strip_renders_times_in_utc() -> None:
    """The strip formats the last-scan time as UTC 24-hour text, like the
    rest of the UI, never with the browser's locale and zone."""
    from pathlib import Path

    js = (Path(__file__).resolve().parents[1] / "src" / "cert_watch" / "static" / "js"
          / "core.js").read_text()
    strip = js[js.index("/* ---------- health strip"):]
    assert "toLocaleString" not in strip
    assert "toISOString().slice(0, 16)" in strip
    assert "' UTC'" in strip
