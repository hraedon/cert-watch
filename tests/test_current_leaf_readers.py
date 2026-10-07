"""Operational readers agree with inventory about duplicate scanned leaves (#156)."""

from __future__ import annotations

from datetime import timedelta

import pytest

from cert_watch.alerting.digest.expiry import ExpiryDigestKind
from cert_watch.alerting.routing import find_orphan_certs
from cert_watch.alerting.rules.expiry import evaluate_all_certs
from cert_watch.alerting.rules.renewal import renewal_window_candidates
from cert_watch.database import SqliteAlertRepository
from cert_watch.database.connection import _connect
from cert_watch.readiness import _current_endpoints
from cert_watch.renewal_webhook import _resolve_cert_details
from cert_watch.services.renewal_reports import _current_leaf
from tests.test_browse_duplicate_leaf import NOW, _estate


def _lineage_estate(tmp_path):
    db = _estate(tmp_path)
    with _connect(db) as conn:
        # The actual successor is older by timestamp: ordering solely by arrival
        # time would select the replaced row left behind by the old alias merge.
        conn.execute(
            "UPDATE certificates SET created_at=?, replaces_cert_id='stale-leaf' "
            "WHERE id='head-leaf'", ((NOW - timedelta(days=40)).isoformat(),),
        )
        conn.commit()
    return db


def test_readiness_uses_lineage_head_lifetime(tmp_path):
    db = _lineage_estate(tmp_path)
    endpoints = _current_endpoints(db, ())
    merge = next(row for row in endpoints if row["hostname"] == "merge.example.test")
    assert merge["not_after"] == (NOW + timedelta(days=150)).isoformat()


def test_renewal_webhook_enriches_only_lineage_head(tmp_path):
    db = _lineage_estate(tmp_path)
    current = _resolve_cert_details(db, "merge.example.test", 443, "b2".ljust(64, "0"))
    assert current["id"] == "head-leaf"
    assert _resolve_cert_details(db, "merge.example.test", 443, "a1".ljust(64, "0")) == {}


def test_renewal_attempt_baseline_uses_lineage_head(tmp_path):
    db = _lineage_estate(tmp_path)
    with _connect(db) as conn:
        host_id = conn.execute(
            "SELECT id FROM hosts WHERE hostname='merge.example.test'"
        ).fetchone()["id"]
        fingerprint, expiry = _current_leaf(conn, host_id)
    assert fingerprint == "b2".ljust(64, "0")
    assert expiry == (NOW + timedelta(days=150)).isoformat()


def test_orphan_inventory_omits_unlinked_stale_duplicate(tmp_path):
    db = _estate(tmp_path)
    merge = [row for row in find_orphan_certs(db) if row["hostname"] == "merge.example.test"]
    assert [row["cert_id"] for row in merge] == ["head-leaf"]


def test_expiry_does_not_alert_on_unlinked_stale_duplicate(tmp_path):
    db = _estate(tmp_path)
    assert evaluate_all_certs(db, SqliteAlertRepository(db)) == []


def test_renewal_window_omits_unlinked_stale_duplicate(tmp_path):
    db = _estate(tmp_path)
    with _connect(db) as conn:
        conn.execute("DELETE FROM renewal_attempts")
        conn.commit()
    assert renewal_window_candidates(db) == []


def test_expiry_digest_does_not_include_unlinked_stale_duplicate(tmp_path):
    db = _estate(tmp_path)
    assert ExpiryDigestKind(None).targets(db, NOW, 7) == []


def test_fingerprint_target_uses_lineage_head(tmp_path):
    from cert_watch.services.renewal_reports import resolve_target
    from tests.test_renewal_reports import _auth

    db = _lineage_estate(tmp_path)
    target = resolve_target(db, _auth("test-key"), cert_fingerprint="b2".ljust(64, "0"))
    assert target.hostname == "merge.example.test"
    assert target.baseline_not_after == (NOW + timedelta(days=150)).isoformat()


def test_renewal_failure_alert_links_to_lineage_head(tmp_path):
    from cert_watch.alerting.rules.renewal_reports import evaluate_renewal_report_alerts

    db = _lineage_estate(tmp_path)
    alerts = evaluate_renewal_report_alerts(db, SqliteAlertRepository(db))
    assert len(alerts) == 1
    assert alerts[0].cert_id == "head-leaf"


def test_renewal_digest_uses_lineage_head_expiry(tmp_path):
    from cert_watch.alerting.digest.renewal import build_renewal_digest
    from tests.test_digest import _emit_renewal

    db = _lineage_estate(tmp_path)
    _emit_renewal(db, "merge.example.test", "head-leaf")
    digests = build_renewal_digest(db, now=NOW)
    assert len(digests) == 1
    assert digests[0].host_expiry["merge.example.test"] == (
        NOW + timedelta(days=150)
    ).isoformat()


def test_group_preview_counts_current_leaves(tmp_path):
    from cert_watch.routes.settings.alert_groups import _match_preview

    db = _estate(tmp_path)
    count, _sample = _match_preview(db, ["t"])
    assert count == 2


def test_offline_routing_uses_lineage_head(tmp_path):
    from cert_watch.routing_report import build_routing_report
    from tests.test_routing_report import _seal

    db = _lineage_estate(tmp_path)
    _seal(db)
    report = build_routing_report(db)
    assert report["counts"]["leaf_certificates"] == 2
    assert "head-leaf" in {row["cert_id"] for row in report["certificates"]}
    assert "stale-leaf" not in {row["cert_id"] for row in report["certificates"]}


def test_chain_cache_refresh_skips_stale_duplicate(tmp_path, monkeypatch):
    from cert_watch.database.chain_status_cache import refresh_chain_status

    db = _estate(tmp_path)
    monkeypatch.setattr("cert_watch.cert_chain.chain_status", lambda *args: "valid")
    assert refresh_chain_status(db) == 2
    with _connect(db) as conn:
        assert conn.execute(
            "SELECT chain_status FROM certificates WHERE id='stale-leaf'"
        ).fetchone()[0] is None


def test_existing_stale_detail_resolves_to_lineage_head(tmp_path):
    from cert_watch.database.dashboard_detail import resolve_current_certificate

    db = _lineage_estate(tmp_path)
    ref = resolve_current_certificate(db, "stale-leaf")
    assert ref is not None
    assert (ref.cert_id, ref.superseded) == ("head-leaf", True)
    assert resolve_current_certificate(db, "head-leaf") is None


@pytest.mark.parametrize("successor", ["cycle", "different-port", "non-leaf"])
def test_selected_head_still_alerts_with_irrelevant_or_cyclic_successor(tmp_path, successor):
    from tests.test_browse_duplicate_leaf import _insert_leaf

    db = _estate(tmp_path)
    with _connect(db) as conn:
        conn.execute("DELETE FROM renewal_attempts")
        conn.execute(
            "UPDATE certificates SET not_after=? WHERE id='head-leaf'",
            ((NOW + timedelta(days=3)).isoformat(),),
        )
        if successor == "cycle":
            conn.execute(
                "UPDATE certificates SET replaces_cert_id='head-leaf' WHERE id='stale-leaf'"
            )
            conn.execute(
                "UPDATE certificates SET replaces_cert_id='stale-leaf' WHERE id='head-leaf'"
            )
        else:
            _insert_leaf(conn, "irrelevant", "merge.example.test", "d4", NOW, days=200)
            conn.execute(
                "UPDATE certificates SET replaces_cert_id='head-leaf' WHERE id='irrelevant'"
            )
            if successor == "different-port":
                conn.execute("UPDATE certificates SET port=8443 WHERE id='irrelevant'")
            else:
                conn.execute("UPDATE certificates SET is_leaf=0 WHERE id='irrelevant'")
        conn.commit()
    assert {row["id"] for row in renewal_window_candidates(db)} == {"head-leaf"}
    alerts = evaluate_all_certs(db, SqliteAlertRepository(db))
    assert alerts
    assert {alert.cert_id for alert in alerts} == {"head-leaf"}


@pytest.mark.parametrize("visible", [True, False])
def test_existing_stale_page_authorizes_destination_and_preserves_query(
    tmp_path, monkeypatch, visible,
):
    from tests.test_tag_scoped_access import _make_scoped_app, _scoped_client

    db = _lineage_estate(tmp_path)
    old_id = "a" * 32
    head_id = "b" * 32
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.start", lambda self: None)
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.stop", lambda *args, **kwargs: True)
    with _connect(db) as conn:
        conn.execute("UPDATE hosts SET tags='' WHERE hostname='merge.example.test'")
        conn.execute("UPDATE certificates SET tags='team-a' WHERE id='stale-leaf'")
        conn.execute(
            "UPDATE certificates SET tags=? WHERE id='head-leaf'",
            ("team-a" if visible else "team-b",),
        )
        conn.execute("UPDATE certificates SET id=? WHERE id='stale-leaf'", (old_id,))
        conn.execute(
            "UPDATE certificates SET id=?, replaces_cert_id=? WHERE id='head-leaf'",
            (head_id, old_id),
        )
        conn.commit()
    app, groups = _make_scoped_app(db, tmp_path, scope_tag="team-a")
    with _scoped_client(app, groups) as client:
        response = client.get(
            f"/certificates/{old_id}?endpoint_saved=1&superseded=0", follow_redirects=False,
        )
    assert response.status_code == 303
    expected = (
        f"/certificates/{head_id}?endpoint_saved=1&superseded=1"
        if visible else "/?error=certificate+not+found"
    )
    assert response.headers["location"] == expected


def test_offline_report_keeps_rowid_tie_breaker(tmp_path):
    from cert_watch.routing_report import build_routing_report
    from tests.test_routing_report import _seal

    db = _estate(tmp_path)
    with _connect(db) as conn:
        conn.execute("UPDATE certificates SET created_at=?", (NOW.isoformat(),))
        # Rowid order differs from lexicographic primary-key order.
        conn.execute("UPDATE certificates SET id='z-old' WHERE id='stale-leaf'")
        conn.execute("UPDATE certificates SET id='a-new' WHERE id='head-leaf'")
        conn.commit()
    _seal(db)
    report = build_routing_report(db)
    ids = {row["cert_id"] for row in report["certificates"]}
    assert "a-new" in ids
    assert "z-old" not in ids


def test_uploaded_leaves_stay_individual_and_keep_exact_detail_links(tmp_path):
    from cert_watch.database.dashboard_detail import resolve_current_certificate
    from cert_watch.routes.settings.alert_groups import _match_preview

    db = _estate(tmp_path)
    with _connect(db) as conn:
        conn.execute(
            "UPDATE certificates SET source='uploaded' WHERE id IN ('stale-leaf','head-leaf')"
        )
        conn.commit()
    assert _match_preview(db, ["t"])[0] == 3
    assert len(find_orphan_certs(db)) == 3
    assert resolve_current_certificate(db, "stale-leaf") is None
    assert resolve_current_certificate(db, "head-leaf") is None


def test_cache_does_not_publish_a_leaf_superseded_during_computation(tmp_path, monkeypatch):
    from cert_watch.database import chain_status_cache
    from tests.test_browse_duplicate_leaf import _insert_leaf

    db = _estate(tmp_path)
    compute = chain_status_cache._compute
    monkeypatch.setattr("cert_watch.cert_chain.chain_status", lambda *args: "valid")

    def supersede(conn, leaf_ids, anchors, trust):
        updates = compute(conn, leaf_ids, anchors, trust)
        _insert_leaf(conn, "new-head", "merge.example.test", "d4", NOW, days=200)
        conn.commit()
        return updates

    monkeypatch.setattr(chain_status_cache, "_compute", supersede)
    assert chain_status_cache.refresh_chain_status(db) == 1
    with _connect(db) as conn:
        rows = conn.execute(
            "SELECT chain_status FROM certificates WHERE hostname='merge.example.test'"
        ).fetchall()
    assert all(row[0] is None for row in rows)


def test_group_population_skips_duplicates_but_explicit_routing_keeps_history(tmp_path):
    from cert_watch.alerting.routing import resolve_all_group_recipients, resolve_routing
    from cert_watch.database import SqliteAlertGroupRepository

    db = _estate(tmp_path)
    SqliteAlertGroupRepository(db).create(
        name="team", recipients=["team@example.test"], match_tags=["t"],
    )
    population = resolve_all_group_recipients(db)
    assert "head-leaf" in population
    assert "stale-leaf" not in population
    historical = resolve_routing(db, ("stale-leaf",))
    assert historical["stale-leaf"]["recipients"] == ["team@example.test"]
