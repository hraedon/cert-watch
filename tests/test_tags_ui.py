"""GUI tagging (#7): edit cert/host tags, effective-tag display, dashboard search."""

from __future__ import annotations

import sqlite3

from fastapi.testclient import TestClient

from cert_watch.database import init_schema


def _seed_cert_on_host(db, leaf_pem_file, *, hostname="leaf.example.com", port=443):
    from cert_watch.database import SqliteHostRepository
    from cert_watch.upload import store_uploaded, upload_certificate

    cert_id = store_uploaded(upload_certificate(leaf_pem_file), db)
    SqliteHostRepository(db).add(hostname, port)
    with sqlite3.connect(str(db)) as conn:
        conn.execute(
            "UPDATE certificates SET hostname = ?, port = ? WHERE id = ?",
            (hostname, port, cert_id),
        )
        conn.commit()
    return cert_id


def test_set_cert_tags_and_show(tmp_path, reload_app, leaf_pem_file):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    cert_id = _seed_cert_on_host(db, leaf_pem_file)

    with TestClient(app_mod.app) as client:
        r = client.post(
            f"/certificates/{cert_id}/tags",
            data={"tags": "prod,  payments , prod"},  # dupes/space normalized
            follow_redirects=False,
        )
        assert r.status_code == 303
        page = client.get(f"/certificates/{cert_id}").text

    from cert_watch.database import SqliteCertificateRepository

    assert SqliteCertificateRepository(db).get_tags(cert_id) == "prod,payments"
    assert "prod" in page and "payments" in page


def test_host_tags_are_effective_on_cert(tmp_path, reload_app, leaf_pem_file):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    cert_id = _seed_cert_on_host(db, leaf_pem_file)
    with sqlite3.connect(str(db)) as conn:
        host_id = conn.execute(
            "SELECT id FROM hosts WHERE hostname = ? AND port = ?",
            ("leaf.example.com", 443),
        ).fetchone()[0]

    with TestClient(app_mod.app) as client:
        r = client.post(
            f"/hosts/{host_id}/tags", data={"tags": "team-infra"}, follow_redirects=False
        )
        assert r.status_code == 303
        page = client.get(f"/certificates/{cert_id}").text

    # The host tag is inherited (effective) and flagged as host-sourced.
    assert "team-infra" in page
    assert "(host)" in page


def test_dashboard_search_matches_tags(tmp_path, reload_app, leaf_pem_file):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    cert_id = _seed_cert_on_host(db, leaf_pem_file)
    from cert_watch.database import SqliteCertificateRepository

    SqliteCertificateRepository(db).set_tags(cert_id, "payments")

    with TestClient(app_mod.app) as client:
        hit = client.get("/?q=payments").text
        miss = client.get("/?q=zzz-no-such-tag").text

    assert "leaf.example.com" in hit
    assert "leaf.example.com" not in miss
