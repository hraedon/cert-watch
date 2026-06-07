"""BC-097: the Discover page must not block on live crt.sh in the request path.

It renders from the reconciliation cache and warms stale/missing domains in a
background thread, so a cold load returns immediately showing "reconciling…"
rather than serially querying crt.sh (15s timeout each) for every domain.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from cert_watch.certificate_model import Certificate


def _seed_scanned(db, cn: str, der: bytes) -> None:
    from cert_watch.scan import ScannedEntry, store_scanned

    now = datetime.now(UTC)
    leaf = Certificate(
        subject=f"CN={cn}", issuer="CN=Test Issuer",
        not_before=now - timedelta(days=1), not_after=now + timedelta(days=90),
        san_dns_names=[cn], fingerprint_sha256=f"fp-{cn}", raw_der=der, is_leaf=True,
    )
    store_scanned(ScannedEntry(host=cn, port=443, leaf=leaf, chain=[]), db)


def test_discover_cold_load_does_not_reconcile_synchronously(
    reload_app, monkeypatch, self_signed_leaf
):
    import cert_watch.ct_monitor as ctm
    from cert_watch.config import Settings
    from cert_watch.database import init_schema

    ctm._CT_RECON_CACHE.clear()
    with ctm._CT_REFRESH_LOCK:
        ctm._CT_REFRESH_INFLIGHT.clear()

    def fake_query(domain, **kwargs):
        # Fast error string so the background worker finishes without network I/O.
        return f"error: stub for {domain}"

    monkeypatch.setattr(ctm, "query_ct_log", fake_query)

    app_mod = reload_app()
    db = Settings.from_env().db_path
    init_schema(db)
    _seed_scanned(db, "app.example.com", self_signed_leaf.der)

    with TestClient(app_mod.app) as client:
        resp = client.get("/discover")

    assert resp.status_code == 200
    # Cold load with a tracked domain → background refresh kicked, "reconciling…"
    # shown. A synchronous reconcile would have left the cache fresh (no indicator).
    assert "discover-reconciling" in resp.text


def test_reconciliation_helpers_cache_and_freshness(monkeypatch, tmp_path):
    # Note: conftest neutralizes time.sleep in unit tests, so this drives the
    # worker directly (deterministic) rather than racing a real thread. The
    # live thread path is covered end-to-end by the cold-load HTTP test above.
    import cert_watch.ct_monitor as ctm

    ctm._CT_RECON_CACHE.clear()
    with ctm._CT_REFRESH_LOCK:
        ctm._CT_REFRESH_INFLIGHT.clear()

    monkeypatch.setattr(ctm, "query_ct_log", lambda domain, **kw: f"error: stub {domain}")

    db = str(tmp_path / "ct.sqlite3")
    # Cold: peek does no I/O and finds nothing.
    assert ctm.peek_reconciliation(db, "example.com") == (None, None)

    # The worker (what start_reconciliation_refresh runs off-thread) warms cache.
    ctm._refresh_worker(db, ["example.com"])
    result, age = ctm.peek_reconciliation(db, "example.com")
    assert result is not None
    assert age is not None

    # A fresh entry → nothing to start, no in-flight work spawned.
    assert ctm.start_reconciliation_refresh(db, ["example.com"]) is False
