"""Route-level audit export never runs under the global write lock (plan 057 W6).

``record_audit(conn=None)`` exports to the SIEM (network I/O, can block). Nine
handlers used to call it while holding ``get_write_lock()``, so a slow sink
stalled every writer. Each now audits after releasing the lock; this drives
each route through the app and checks, from inside the SIEM sink, that another
thread can take the lock and that the audit row is already committed.
Companion to
tests/test_resource_metadata_service.py::test_siem_export_runs_after_commit_and_outside_the_write_lock.
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from cert_watch import siem
    from cert_watch.app import create_app
    from cert_watch.certificate_model import Certificate
    from cert_watch.config import Settings
    from cert_watch.database import SqliteHostRepository, init_schema, kv_set
    from cert_watch.database.connection import get_write_lock
    from tests._helpers import seed_scanned

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    kv_set(db, "setup_complete", "1")
    host_id = SqliteHostRepository(db).add("audit.example.test", 443)
    now = datetime.now(UTC)
    cert_id = seed_scanned(db, "audit.example.test", 443, Certificate(
        subject="CN=audit.example.test", issuer="CN=CA",
        not_before=now - timedelta(days=1), not_after=now + timedelta(days=30),
        fingerprint_sha256="d" * 64,
    ))

    observed: list[tuple[str, bool, int]] = []

    def export(event: dict[str, Any]) -> None:
        acquired: list[bool] = []

        def other_writer() -> None:
            lock = get_write_lock()
            got = lock.acquire(timeout=0.5)
            acquired.append(got)
            if got:
                lock.release()

        worker = threading.Thread(target=other_writer)
        worker.start()
        worker.join()
        with sqlite3.connect(db) as other:
            committed = other.execute(
                "SELECT COUNT(*) FROM audit_log WHERE action = ? AND target_id = ?",
                (event["action"], event["target_id"]),
            ).fetchone()[0]
        observed.append((str(event["action"]), acquired[0], committed))

    monkeypatch.setattr(siem, "siem_enabled", lambda: True)
    monkeypatch.setattr(siem, "export_audit_event", export)

    import cert_watch.routes.hosts as hosts_routes

    async def no_scan(*_a: Any, **_k: Any) -> tuple[str, str]:
        return "scan_error", "not scanned in this test"

    monkeypatch.setattr(hosts_routes, "_scan_and_store", no_scan)
    monkeypatch.setattr(
        hosts_routes, "resolve_and_validate_host", lambda *_a, **_k: (None, "93.184.216.34")
    )
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AUTH_PROVIDER", "none")
    monkeypatch.setenv("CERT_WATCH_ALLOW_UNAUTH", "1")
    app = create_app(settings=Settings.from_env())
    return {"app": app, "host_id": host_id, "cert_id": cert_id, "observed": observed}


def test_route_audits_export_after_the_write_lock_is_released(env):
    host_id, cert_id = env["host_id"], env["cert_id"]
    with TestClient(env["app"]) as client:
        r = client.post(
            "/api/alert-groups", json={"name": "g", "recipients": ["ops@example.test"]}
        )
        assert r.status_code == 201, r.text
        group_id = r.json()["id"]
        steps = [
            ("PATCH", f"/api/alert-groups/{group_id}", {"json": {"name": "g2"}}),
            ("POST", f"/api/alert-groups/{group_id}/certs/{cert_id}", {}),
            ("DELETE", f"/api/alert-groups/{group_id}/certs/{cert_id}", {}),
            ("DELETE", f"/api/alert-groups/{group_id}", {}),
            ("PUT", f"/api/hosts/{host_id}/issuers", {"json": {"issuers": ["CN=Issuer"]}}),
        ]
        for method, url, kw in steps:
            r = client.request(method, url, **kw)
            assert r.status_code == 200, (method, url, r.text)
        r = client.post("/api/api-keys", json={"name": "k", "scope": "read"})
        assert r.status_code == 201, r.text
        r = client.delete(f"/api/api-keys/{r.json()['id']}")
        assert r.status_code == 200, r.text
        r = client.post(
            "/hosts", data={"hostname": "new.example.test", "port": "443"},
            follow_redirects=False,
        )
        assert r.status_code == 303, r.text

    observed = env["observed"]
    actions = [a for a, _, _ in observed]
    for expected in (
        "alert_group.create", "alert_group.update", "alert_group.assign_cert",
        "alert_group.unassign_cert", "alert_group.delete", "host.set_expected_issuers",
        "api_key.create", "api_key.revoke", "host.add",
    ):
        assert expected in actions, (expected, actions)
    held = [a for a, lock_free, _ in observed if not lock_free]
    assert not held, f"SIEM export ran under the write lock for: {held}"
    uncommitted = [a for a, _, committed in observed if committed != 1]
    assert not uncommitted, f"exported before the audit row was committed: {uncommitted}"
