"""A certificate served by several endpoints links each one from its detail page.

Notes, owner and renewal settings are host-scoped, so each endpoint serving
the same certificate has its own. The detail page lists the others so each
one's notes can be reached and edited.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from cert_watch.certificate_model import parse_certificate
from cert_watch.database import SqliteHostRepository, init_schema, list_shared_endpoints
from cert_watch.database.connection import _connect
from tests._helpers import seed_scanned
from tests.conftest import _make_cert


@pytest.fixture(autouse=True)
def _no_startup_scan(monkeypatch):
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.start", lambda self: None)
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.stop", lambda self: None)


def _serve(db, hostname, leaf, *, tags="", notes=""):
    SqliteHostRepository(db).add(hostname, 443, tags=tags, notes=notes)
    return seed_scanned(db, hostname, 443, leaf)


def test_detail_lists_the_other_endpoints_serving_the_certificate(
    tmp_path, reload_app, self_signed_leaf
):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    shared = parse_certificate(self_signed_leaf.der)
    www = _serve(db, "www.example.test", shared)
    api = _serve(db, "api.example.test", shared, notes="Behind the k8s ingress")
    mail = _serve(db, "mail.example.test", shared)
    unrelated = parse_certificate(_make_cert("other.example.test").der)
    other = _serve(db, "other.example.test", unrelated)

    with TestClient(reload_app().app) as client:
        page = client.get(f"/certificates/{www}")
        alone = client.get(f"/certificates/{other}")

    assert page.status_code == 200
    assert page.text.count('data-testid="shared-endpoint"') == 2
    assert f'href="/certificates/{api}"' in page.text
    assert f'href="/certificates/{mail}"' in page.text
    assert "Behind the k8s ingress" in page.text
    assert f'href="/certificates/{other}"' not in page.text
    assert 'data-testid="shared-endpoints"' not in alone.text


def test_an_endpoint_whose_head_leaf_differs_is_not_listed(tmp_path, self_signed_leaf):
    # An old alias merge can leave an endpoint holding a stale leaf beside its
    # head (#151). Only the head says what the endpoint serves now.
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    shared = parse_certificate(self_signed_leaf.der)
    www = _serve(db, "www.example.test", shared)
    _serve(db, "api.example.test", parse_certificate(_make_cert("api.example.test").der))
    with _connect(db) as conn:
        conn.execute(
            """INSERT INTO certificates
               (id,subject,issuer,not_before,not_after,san_dns_names,fingerprint_sha256,
                raw_der,source,hostname,port,is_leaf,parent_cert_id,tags,created_at,updated_at)
               VALUES ('stale-leaf',?,?,?,?,'[]',?,x'00','scanned','api.example.test',443,1,
                       NULL,'','2020-01-01T00:00:00+00:00','2020-01-01T00:00:00+00:00')""",
            (
                shared.subject,
                shared.issuer,
                shared.not_before.isoformat(),
                shared.not_after.isoformat(),
                shared.fingerprint_sha256,
            ),
        )

    assert list_shared_endpoints(db, www, shared.fingerprint_sha256) == ()


def test_a_scoped_viewer_sees_only_endpoints_in_scope(tmp_path, self_signed_leaf):
    from tests.test_tag_scoped_access import _make_scoped_app, _scoped_client

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    shared = parse_certificate(self_signed_leaf.der)
    www = _serve(db, "www.example.test", shared, tags="team-a")
    api = _serve(db, "api.example.test", shared, tags="team-a")
    hidden = _serve(db, "hidden.example.test", shared, tags="team-b", notes="Team B only")

    app, groups = _make_scoped_app(db, tmp_path, scope_tag="team-a")
    with _scoped_client(app, groups) as client:
        page = client.get(f"/certificates/{www}")

    assert page.status_code == 200
    assert f'href="/certificates/{api}"' in page.text
    assert f'href="/certificates/{hidden}"' not in page.text
    assert "hidden.example.test" not in page.text
    assert "Team B only" not in page.text
