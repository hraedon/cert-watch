"""One status per certificate per request, on every surface (#113, review round 3).

With a valid trust anchor but an unwritable chain-status cache, SQL correctly
treats the chain as unverified (Warning); the rows used to re-verify live and
show Healthy, and Home counted an attention item and then dropped it. Rows and
queue items now consume the status the SQL used.

Also pins the behaviours round 3 found untested (surviving mutants).
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path
from urllib.parse import quote

import pytest

from cert_watch.certificate_model import Certificate
from tests.test_status_rule_everywhere import NOW, _at, _issue, _row_key, _seed

KEY = "ok.example.test:443"
SCOPE = ("cache-probe",)


@pytest.fixture
def unwritable(tmp_path):
    """The estate, one healthy certificate tagged into its own scope, and a
    cache that rejects every write -- with the trust anchor left in place."""
    from cert_watch.database.connection import _connect

    db = tmp_path / "cert-watch.sqlite3"
    _seed(db)
    with _connect(db) as conn:
        conn.execute(
            "UPDATE certificates SET tags = 'cache-probe'"
            " WHERE hostname = 'ok.example.test' AND port = 443 AND is_leaf = 1"
        )
        conn.execute(
            "CREATE TRIGGER reject_all_cache BEFORE UPDATE OF chain_status ON certificates"
            " BEGIN SELECT RAISE(FAIL, 'cache unwritable'); END"
        )
        conn.commit()
    return db


def test_every_surface_shows_the_status_the_counts_used(unwritable, reload_app):
    from fastapi.testclient import TestClient

    from cert_watch.attention import attention_queue_page
    from cert_watch.compliance import build_compliance_report
    from cert_watch.database import (
        dashboard_urgency_stats,
        get_pivot_group_page,
        list_dashboard_grouped_page,
        list_dashboard_page,
        list_fleet_pivot,
    )

    db = unwritable
    stats = dashboard_urgency_stats(db, scope_tags=SCOPE)
    assert stats == {"expired": 0, "critical": 0, "warning": 1, "healthy": 0}

    rows, _ = list_dashboard_page(db, per_page=25, scope_tags=SCOPE)
    assert [(r["host"], r["urgency"], r["chain_status"]) for r in rows] == [
        (KEY, "warning", "unverified")
    ]
    filtered, total = list_dashboard_page(db, urgency="warning", per_page=25, scope_tags=SCOPE)
    assert total == 1
    assert [r["urgency"] for r in filtered] == ["warning"]
    grouped, _ = list_dashboard_grouped_page(db, urgency="warning", per_page=25, scope_tags=SCOPE)
    assert [r["urgency"] for r in grouped] == ["warning"]

    (group,) = list_fleet_pivot(db, "owner", scope_tags=SCOPE)
    assert group["worst_urgency"] == "warning"
    expanded, _ = get_pivot_group_page(db, "owner", group["key"], scope_tags=SCOPE)
    assert [r["urgency"] for r in expanded] == ["warning"]

    report = build_compliance_report(db, scope_tag="cache-probe", signing_key="k")
    assert {e.urgency for b in report.remediation_buckets for e in b.entries} <= {"warning"}

    items, queue_total = attention_queue_page(db, scope_tags=SCOPE)
    assert queue_total == len(items) == 1
    assert items[0]["endpoint"] == KEY
    assert items[0]["severity"] == "warning"

    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        home = client.get("/").text
        body = client.get(f"/api/pivot/owner/{quote(group['key'])}").json()
    assert "Nothing needs attention" not in home
    assert 'data-testid="attention-item"' in home
    by_key = {_row_key(e): e["urgency"] for e in body["entries"]}
    assert by_key[KEY] == "warning"


def test_a_der_length_change_changes_the_basis(tmp_path):
    """The basis covers the DER the verifier reads, not only the fingerprint
    column: a chain certificate whose bytes were truncated is re-verified."""
    from cert_watch.database import dashboard_urgency_stats
    from cert_watch.database.chain_status_cache import refresh_chain_status
    from cert_watch.database.connection import _connect

    db = tmp_path / "der.sqlite3"
    _seed(db)
    dashboard_urgency_stats(db)
    assert refresh_chain_status(db) == 0
    with _connect(db) as conn:
        leaf = conn.execute(
            "SELECT id FROM certificates WHERE hostname = 'ok.example.test' AND port = 443"
            " AND is_leaf = 1"
        ).fetchone()
        conn.execute(
            "UPDATE certificates SET raw_der = substr(raw_der, 1, 40) WHERE parent_cert_id = ?",
            (leaf["id"],),
        )
        conn.commit()
    assert refresh_chain_status(db) == 1
    with _connect(db) as conn:
        status = conn.execute(
            "SELECT chain_status FROM certificates WHERE id = ?", (leaf["id"],)
        ).fetchone()[0]
    assert status != "private"


# --- surviving mutants ---------------------------------------------------------


def test_live_verification_error_fails_closed(monkeypatch):
    """A single-certificate view verifies live; an error there is unverified."""
    from cert_watch.database.dashboard_rows import _build_dashboard_rows

    def broken(*_args):
        raise ValueError("unreadable chain")

    monkeypatch.setattr("cert_watch.cert_chain.chain_status", broken)
    leaf, _ = _issue("live.example.test", 200, None, ca=False)
    row = {
        "id": "leaf-1", "subject": leaf.subject, "issuer": leaf.issuer,
        "not_before": leaf.not_before.isoformat(), "not_after": leaf.not_after.isoformat(),
        "san_dns_names": "[]", "fingerprint_sha256": leaf.fingerprint_sha256,
        "raw_der": leaf.raw_der, "source": "uploaded", "hostname": None, "port": None,
        "is_leaf": 1, "parent_cert_id": None, "chain_valid": None, "replaces_cert_id": None,
        "tags": "",
    }
    (built,) = _build_dashboard_rows([row], [])
    assert (built["chain_status"], built["urgency"]) == ("unverified", "warning")


def test_an_upload_is_in_the_scope_of_its_own_tag(tmp_path, monkeypatch):
    from cert_watch.database import dashboard_urgency_stats, init_schema, list_dashboard_page
    from cert_watch.upload import UploadedEntry, store_uploaded

    monkeypatch.setattr("cert_watch.cert_chain.chain_status", lambda *a: "public")
    db = tmp_path / "upload-scope.sqlite3"
    init_schema(db)
    leaf, _ = _issue("vault.example.test", 200, None, ca=False)
    store_uploaded(UploadedEntry("vault.pem", leaf), db, tags="vault")
    other, _ = _issue("other.example.test", 200, None, ca=False)
    store_uploaded(UploadedEntry("other.pem", other), db, tags="elsewhere")

    rows, total = list_dashboard_page(db, per_page=25, scope_tags=("vault",))
    assert (total, [_row_key(r) for r in rows]) == (1, ["vault.example.test"])
    assert dashboard_urgency_stats(db, scope_tags=("vault",))["healthy"] == 1


def test_group_expansion_page_size_is_capped(tmp_path, reload_app):
    from fastapi.testclient import TestClient

    from cert_watch.database import SqliteHostRepository

    app_mod = reload_app()
    SqliteHostRepository(tmp_path / "cert-watch.sqlite3").add("one.example.test", 443)
    with TestClient(app_mod.app) as client:
        body = client.get("/api/pivot/owner/Unassigned?per_page=100000").json()
        tiny = client.get("/api/pivot/owner/Unassigned?per_page=0&page=0").json()
    assert body["per_page"] == 500
    assert (tiny["per_page"], tiny["page"]) == (1, 1)


def test_queue_total_counts_items_not_rows(tmp_path, monkeypatch):
    """One endpoint expiring in 3 days whose last scan failed is two items."""
    from cert_watch.attention import attention_queue_page
    from cert_watch.database import SqliteHostRepository, init_schema, replace_scanned
    from cert_watch.scheduler import ScanHistory, record_scan_history

    monkeypatch.setattr("cert_watch.cert_chain.chain_status", lambda *a: "public")
    db = tmp_path / "two-items.sqlite3"
    init_schema(db)
    SqliteHostRepository(db).add("two.example.test", 443)
    replace_scanned(db, "two.example.test", 443, Certificate(
        subject="CN=two.example.test", issuer="CN=CA",
        not_before=NOW - dt.timedelta(days=30), not_after=_at(3), fingerprint_sha256="two",
    ), [], True)
    record_scan_history(db, ScanHistory("two.example.test", 443, "failure",
                                        error_message="refused", scanned_at=NOW))
    items, total = attention_queue_page(db, window_days=0)  # no renewal-stall item
    assert sorted(i["severity"] for i in items) == ["critical", "failing"]
    assert total == 2
    head, head_total = attention_queue_page(db, window_days=0, limit=1)
    assert (len(head), head_total) == (1, 2)


def test_compliance_lists_the_chain_certificates_date(tmp_path):
    from cert_watch.compliance import build_compliance_report
    from cert_watch.database.connection import _connect, _parse_iso

    db = tmp_path / "date.sqlite3"
    _seed(db)
    report = build_compliance_report(db, signing_key="k")
    entry = next(
        e for b in report.remediation_buckets for e in b.entries
        if e.host == "expint.example.test:443"
    )
    with _connect(db) as conn:
        inter = conn.execute(
            "SELECT ch.not_after FROM certificates ch JOIN certificates c"
            " ON ch.parent_cert_id = c.id WHERE c.hostname = 'expint.example.test'"
        ).fetchone()[0]
    assert _parse_iso(entry.not_after) == _parse_iso(inter)
    assert entry.days_remaining == -3


def test_a_healthy_group_with_a_pending_endpoint_is_not_known_healthy(tmp_path, monkeypatch):
    from cert_watch.database import (
        SqliteHostRepository,
        init_schema,
        list_fleet_pivot,
        replace_scanned,
    )

    monkeypatch.setattr("cert_watch.cert_chain.chain_status", lambda *a: "public")
    db = tmp_path / "gray.sqlite3"
    init_schema(db)
    hosts = SqliteHostRepository(db)
    hosts.add("fine.example.test", 443, owner_name="Team G")
    hosts.add("never.example.test", 443, owner_name="Team G")
    replace_scanned(db, "fine.example.test", 443, Certificate(
        subject="CN=fine.example.test", issuer="CN=CA",
        not_before=NOW - dt.timedelta(days=30), not_after=_at(200), fingerprint_sha256="fine",
    ), [], True)
    (group,) = list_fleet_pivot(db, "owner")
    assert (group["key"], group["count"], group["worst_urgency"]) == ("Team G", 2, "gray")


def test_alert_group_preview_parses_tags_like_scope(tmp_path):
    from cert_watch.database import SqliteHostRepository, init_schema, replace_scanned
    from cert_watch.routes.settings.alert_groups import _match_preview

    db = tmp_path / "preview.sqlite3"
    init_schema(db)
    SqliteHostRepository(db).add("edge.example.test", 443, tags="staging, edge")
    replace_scanned(db, "edge.example.test", 443, Certificate(
        subject="CN=edge.example.test", issuer="CN=CA",
        not_before=NOW - dt.timedelta(days=30), not_after=_at(200), fingerprint_sha256="edge",
    ), [], True)
    count, sample = _match_preview(Path(db), ["edge"])
    assert count == 1
    assert sample[0]["hostname"] == "edge.example.test"
    assert _match_preview(Path(db), ["edg"])[0] == 0
