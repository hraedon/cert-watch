"""HTML and JSON contracts for explicit renewal-failure clearing."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from cert_watch.certificate_model import parse_certificate
from cert_watch.database import SqliteHostRepository
from cert_watch.database.connection import _connect
from tests._helpers import seed_scanned
from tests.conftest import _make_cert


@pytest.mark.parametrize("adapter", ["html", "json"])
def test_clear_route_marks_failure_and_audits(reload_app, tmp_path, adapter):
    app = reload_app().app
    db = tmp_path / "cert-watch.sqlite3"
    host_id = SqliteHostRepository(db).add("clear.example.test", 443)
    reported_at = datetime(2026, 9, 28, 12, tzinfo=UTC).isoformat()
    with _connect(db) as conn:
        conn.execute(
            """INSERT INTO renewal_attempts
               (attempt_id,host_id,is_current,source,state,opened_seq,
                suppresses_stalled,received_at,baseline_lease_claimed,
                failure_attempt_id,failure_reported_at,rule_due_at)
               VALUES ('failure-origin',?,1,'test','failed',1,0,?,1,
                       'failure-origin',?,?)""",
            (host_id, reported_at, reported_at, reported_at),
        )
        conn.commit()

    with TestClient(app) as client:
        if adapter == "html":
            response = client.post(
                f"/hosts/{host_id}/renewal-failure/clear",
                follow_redirects=False,
            )
            assert response.status_code == 303
            assert response.headers["location"].endswith("renewal_failure_cleared=1")
        else:
            response = client.post(
                f"/api/hosts/{host_id}/renewal-failure/clear", json={}
            )
            assert response.status_code == 200
            assert response.json() == {"id": host_id, "cleared": True}

    with _connect(db) as conn:
        attempt = conn.execute(
            """SELECT failure_cleared_at,closed_reason,rule_due_at
               FROM renewal_attempts WHERE attempt_id='failure-origin'"""
        ).fetchone()
        audit = conn.execute(
            """SELECT action,target_id FROM audit_log
               WHERE action='renewal_failure.clear' ORDER BY rowid DESC LIMIT 1"""
        ).fetchone()
    assert attempt["failure_cleared_at"] is not None
    assert attempt["closed_reason"] == "manual_clear"
    # The application scheduler may already have consumed the rule wake while
    # the TestClient lifespan is active; the durable clearing state must remain.
    assert (audit["action"], audit["target_id"]) == (
        "renewal_failure.clear",
        host_id,
    )


def test_json_clear_requires_an_empty_json_object(reload_app, tmp_path):
    app = reload_app().app
    db = tmp_path / "cert-watch.sqlite3"
    host_id = SqliteHostRepository(db).add("clear-shape.example.test", 443)
    with TestClient(app) as client:
        response = client.post(
            f"/api/hosts/{host_id}/renewal-failure/clear",
            json={"clear": True},
        )
    assert response.status_code == 400
    assert "empty JSON object" in response.json()["error"]


def test_noop_clear_writes_no_audit_row(reload_app, tmp_path):
    app = reload_app().app
    db = tmp_path / "cert-watch.sqlite3"
    host_id = SqliteHostRepository(db).add("noop-clear.example.test", 443)

    with TestClient(app) as client:
        response = client.post(
            f"/api/hosts/{host_id}/renewal-failure/clear", json={}
        )

    assert response.json() == {"id": host_id, "cleared": False}
    with _connect(db) as conn:
        count = conn.execute(
            "SELECT count(*) FROM audit_log WHERE action='renewal_failure.clear'"
        ).fetchone()[0]
    assert count == 0


def test_html_clear_redirects_to_current_certificate(reload_app, tmp_path):
    app = reload_app().app
    db = tmp_path / "cert-watch.sqlite3"
    hostname = "clear-current.example.test"
    host_id = SqliteHostRepository(db).add(hostname, 443)
    leaf = parse_certificate(_make_cert(hostname, days_valid=60).der)
    cert_id = seed_scanned(db, hostname, 443, leaf)
    reported_at = datetime(2026, 9, 28, 12, tzinfo=UTC).isoformat()
    with _connect(db) as conn:
        conn.execute(
            """INSERT INTO renewal_attempts
               (attempt_id,host_id,is_current,source,state,opened_seq,
                suppresses_stalled,received_at,baseline_lease_claimed,
                failure_attempt_id,failure_reported_at,rule_due_at)
               VALUES ('current-failure',?,1,'test','failed',1,0,?,1,
                       'current-failure',?,?)""",
            (host_id, reported_at, reported_at, reported_at),
        )
        conn.commit()

    with TestClient(app) as client:
        response = client.post(
            f"/hosts/{host_id}/renewal-failure/clear",
            follow_redirects=False,
        )

    assert response.headers["location"] == (
        f"/certificates/{cert_id}?renewal_failure_cleared=1"
    )
