"""Endpoint identity and certificate deployment chronology stay intact in reports."""
from datetime import UTC, datetime, timedelta

from cert_watch.certificate_model import Certificate
from cert_watch.database import SqliteHostRepository, init_schema, store_scan_posture
from cert_watch.database.connection import _connect
from cert_watch.readiness import build_readiness_report, readiness_report_to_dict
from cert_watch.renewal_analytics import (
    _compute_host_from_entries,
    compute_fleet_analytics,
    compute_host_analytics,
    detect_renewal_overdue,
)
from tests._helpers import seed_certificate


def test_readiness_keeps_ports_and_current_lifetime_separate(tmp_path):
    db = tmp_path / "estate.sqlite3"
    init_schema(db)
    now = datetime.now(UTC)
    for port, trust, lifetime in [(443, "public", 90), (636, "private", 365)]:
        SqliteHostRepository(db).add("dual.example.test", port)
        cert = Certificate(
            subject="CN=dual.example.test", issuer="CN=Test CA",
            not_before=now - timedelta(days=10),
            not_after=now + timedelta(days=lifetime - 10),
            san_dns_names=[], fingerprint_sha256=f"current-{port}", raw_der=b"", is_leaf=True,
        )
        cert_id = seed_certificate(db, cert, hostname="dual.example.test", port=port)
        store_scan_posture(db, cert_id, "dual.example.test", port, "A", [], chain_status=trust)
        with _connect(db) as conn:
            for idx, duration in enumerate([398, 398, lifetime]):
                scanned = now - timedelta(days=(2 - idx) * 30)
                conn.execute(
                    "INSERT INTO cert_history (hostname,port,fingerprint_sha256,issuer,"
                    "not_before,not_after,scanned_at) VALUES (?,?,?,?,?,?,?)",
                    ("dual.example.test", port, f"period-{port}-{idx}", "CN=Test CA",
                     scanned.isoformat(), (scanned + timedelta(days=duration)).isoformat(),
                     scanned.isoformat()),
                )
            conn.commit()
    report = build_readiness_report(db)
    assert (report.public_trust_hosts, report.private_ca_hosts) == (1, 1)
    result = readiness_report_to_dict(report)
    assert result["hosts"][0]["port"] == 443
    assert result["private_hosts"][0]["port"] == 636
    assert result["hosts"][0]["current_lifetime"] == 90


def test_rollback_is_a_new_deployment_period():
    now = datetime.now(UTC)
    entries = [
        {"fingerprint_sha256": fingerprint, "issuer": "CN=Test CA",
         "not_before": now.isoformat(), "not_after": (now + timedelta(days=90)).isoformat(),
         "scanned_at": (now + timedelta(days=index)).isoformat()}
        for index, fingerprint in enumerate(["A", "A", "B", "A", "A"])
    ]
    result = _compute_host_from_entries("rollback.example.test", entries)
    assert result.cert_count == 3
    assert result.median_cadence_days == 1.5


def test_overdue_deduplication_keeps_ports(tmp_path, monkeypatch):
    import json

    from cert_watch.events import get_events
    from cert_watch.renewal_analytics import RenewalOverdueSignal
    from cert_watch.scheduler import _check_renewal_overdue

    db = tmp_path / "estate.sqlite3"
    init_schema(db)
    monkeypatch.setattr(
        "cert_watch.renewal_analytics.detect_renewal_overdue",
        lambda _db, hostname, port: RenewalOverdueSignal(hostname, "shared", 2, 20, 18, "high"),
    )
    monkeypatch.setattr(
        "cert_watch.scheduler._send_renewal_webhook_if_configured", lambda *a, **k: None,
    )
    endpoints = [("dual.example.test", 443), ("dual.example.test", 636)]
    _check_renewal_overdue(db, endpoints)
    _check_renewal_overdue(db, endpoints)
    payloads = [json.loads(e["payload"]) for e in get_events(db, event_type="renewal_overdue")]
    assert len(payloads) == 2
    assert {p["port"] for p in payloads} == {443, 636}


def _history_row(
    conn, hostname: str, port: int | None, fingerprint: str,
    first_seen: datetime, not_after: datetime,
) -> None:
    conn.execute(
        "INSERT INTO cert_history (hostname,port,fingerprint_sha256,issuer,"
        "not_before,not_after,scanned_at) VALUES (?,?,?,?,?,?,?)",
        (
            hostname, port, fingerprint, "CN=Test CA",
            (not_after - timedelta(days=90)).isoformat(),
            not_after.isoformat(), first_seen.isoformat(),
        ),
    )


def test_fleet_analytics_sorts_legacy_unknown_and_numeric_ports(tmp_path):
    db = tmp_path / "legacy-port.sqlite3"
    init_schema(db)
    now = datetime.now(UTC)
    with _connect(db) as conn:
        _history_row(conn, "same.example.test", None, "legacy", now, now + timedelta(days=60))
        _history_row(conn, "same.example.test", 443, "current", now, now + timedelta(days=60))
        conn.commit()

    results = compute_fleet_analytics(db)

    assert [(result.hostname, result.port) for result in results] == [
        ("same.example.test", None),
        ("same.example.test", 443),
    ]


def test_overdue_first_seen_is_scoped_to_port(tmp_path):
    db = tmp_path / "cross-port-first-seen.sqlite3"
    init_schema(db)
    now = datetime.now(UTC)
    with _connect(db) as conn:
        # The same fingerprint was old on 443, but is newly deployed on 8443.
        _history_row(conn, "same.example.test", 443, "A", now - timedelta(days=200),
                     now + timedelta(days=10))
        _history_row(conn, "same.example.test", 8443, "B", now - timedelta(days=100),
                     now + timedelta(days=30))
        _history_row(conn, "same.example.test", 8443, "A", now - timedelta(days=1),
                     now + timedelta(days=10))
        conn.commit()

    assert detect_renewal_overdue(db, "same.example.test", port=8443) is None


def test_overdue_uses_start_of_current_rollback_period(tmp_path):
    db = tmp_path / "rollback-first-seen.sqlite3"
    init_schema(db)
    now = datetime.now(UTC)
    with _connect(db) as conn:
        _history_row(conn, "rollback.example.test", 443, "A", now - timedelta(days=200),
                     now - timedelta(days=50))
        _history_row(conn, "rollback.example.test", 443, "B", now - timedelta(days=100),
                     now + timedelta(days=30))
        _history_row(conn, "rollback.example.test", 443, "A", now - timedelta(days=1),
                     now + timedelta(days=10))
        conn.commit()

    assert detect_renewal_overdue(db, "rollback.example.test", port=443) is None


def test_scoped_omitted_port_analytics_excludes_hidden_endpoint(tmp_path):
    db = tmp_path / "scoped-host.sqlite3"
    init_schema(db)
    now = datetime.now(UTC)
    with _connect(db) as conn:
        for port, tags, fingerprint in ((443, "team-a", "visible"), (8443, "team-b", "hidden")):
            conn.execute(
                "INSERT INTO hosts (id,hostname,port,tags,added_at) VALUES (?,?,?,?,?)",
                (f"h-{port}", "same.example.test", port, tags, now.isoformat()),
            )
            _history_row(conn, "same.example.test", port, fingerprint, now,
                         now + timedelta(days=60))
        conn.commit()

    result = compute_host_analytics(
        db, "same.example.test", scope_tags=("team-a",)
    )

    assert result.cert_count == 1
    assert result.observed_lifetimes == [90]


def test_overdue_dedupe_tolerates_malformed_and_honors_legacy_event(
    tmp_path, monkeypatch,
):
    import json

    from cert_watch.events import get_events
    from cert_watch.renewal_analytics import RenewalOverdueSignal
    from cert_watch.scheduler import _check_renewal_overdue

    db = tmp_path / "legacy-events.sqlite3"
    init_schema(db)
    now = datetime.now(UTC).isoformat()
    payloads = [
        "null",
        json.dumps({"hostname": ["invalid"], "cert_fingerprint": "shared"}),
        json.dumps({"hostname": "dual.example.test", "cert_fingerprint": "shared"}),
    ]
    with _connect(db) as conn:
        conn.executemany(
            "INSERT INTO event_log (event_type,timestamp,source,payload,created_at) "
            "VALUES ('renewal_overdue',?,'test',?,?)",
            [(now, payload, now) for payload in payloads],
        )
        conn.commit()
    monkeypatch.setattr(
        "cert_watch.renewal_analytics.detect_renewal_overdue",
        lambda _db, hostname, port: RenewalOverdueSignal(
            hostname, "shared", 2, 20, 18, "high", port
        ),
    )
    monkeypatch.setattr(
        "cert_watch.scheduler._send_renewal_webhook_if_configured", lambda *a, **k: None,
    )

    _check_renewal_overdue(
        db, [("dual.example.test", 443), ("dual.example.test", 8443)]
    )

    assert len(get_events(db, event_type="renewal_overdue")) == 3


def test_host_analytics_api_accepts_valid_port_and_rejects_invalid(
    reload_app, monkeypatch,
):
    import importlib

    from fastapi.testclient import TestClient

    app_mod = reload_app()
    seen: list[int | None] = []

    def fake_compute(_db, hostname, *, port=None, scope_tags=()):
        seen.append(port)
        return _compute_host_from_entries(hostname, [], port=port)

    route_module = importlib.import_module("cert_watch.routes.api.renewal_analytics")
    monkeypatch.setattr(route_module, "compute_host_analytics", fake_compute)
    with TestClient(app_mod.app) as client:
        valid = client.get("/api/renewal-analytics/example.test?port=8443")
        invalid = client.get("/api/renewal-analytics/example.test?port=0")

    assert valid.status_code == 200
    assert valid.json()["port"] == 8443
    assert invalid.status_code == 422
    assert seen == [8443]
