"""WI-060 — alert-group match preview.

`_match_preview` counts leaf certs whose effective (cert ∪ host) tags intersect
a candidate tag set, with a small sample. Surfaced two ways: an inline per-group
match count on the alert-groups tab, and a read-only GET preview endpoint for
testing a tag set before committing it.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cert_watch.certificate_model import Certificate
from cert_watch.database import (
    SqliteAlertGroupRepository,
    SqliteCertificateRepository,
    SqliteHostRepository,
    init_schema,
)
from cert_watch.database.connection import _connect
from cert_watch.routes.settings.alert_groups import _match_preview


def _make_cert(repo: SqliteCertificateRepository, fingerprint: str) -> str:
    cert = Certificate(
        subject="CN=test.example.com",
        issuer="CN=issuer",
        not_before=datetime.now(UTC) - timedelta(days=360),
        not_after=datetime.now(UTC) + timedelta(days=5),
        san_dns_names=["test.example.com"],
        fingerprint_sha256=fingerprint,
        raw_der=b"\x00" * 10,
        is_leaf=True,
    )
    return repo.add(cert)


def _seed(db: Path, hostname: str, *, host_tags: str = "", cert_tags: str = "") -> str:
    SqliteHostRepository(db).add(hostname, 443, tags=host_tags)
    repo = SqliteCertificateRepository(db, hostname=hostname, port=443)
    cert_id = _make_cert(repo, fingerprint=(hostname.encode().hex() + "00") * 16)
    if cert_tags:
        with _connect(db) as conn:
            conn.execute(
                "UPDATE certificates SET tags = ? WHERE id = ?", (cert_tags, cert_id)
            )
            conn.commit()
    return cert_id


@pytest.fixture
def db(tmp_path: Path) -> Path:
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    return db


# ---------- _match_preview (unit) ----------


def test_match_preview_counts_host_and_cert_tags(db):
    _seed(db, "h1.example.com", host_tags="epic")
    _seed(db, "h2.example.com", host_tags="infra")
    _seed(db, "h3.example.com", cert_tags="epic")  # cert-level only
    _seed(db, "h4.example.com", host_tags="unrelated")

    count, sample = _match_preview(db, ["epic"], sample_limit=5)
    assert count == 2  # h1 (host tag) + h3 (cert tag)
    assert {s["hostname"] for s in sample} == {"h1.example.com", "h3.example.com"}


def test_match_preview_multi_tag_union(db):
    _seed(db, "h1.example.com", host_tags="epic")
    _seed(db, "h2.example.com", host_tags="infra")
    _seed(db, "h3.example.com", host_tags="monitoring")

    count, _ = _match_preview(db, ["epic", "infra"], sample_limit=0)
    assert count == 2  # union, not intersection


def test_match_preview_case_insensitive(db):
    _seed(db, "h1.example.com", host_tags="Epic")
    count, _ = _match_preview(db, ["EPIC"], sample_limit=0)
    assert count == 1


def test_match_preview_empty_tags_is_zero(db):
    _seed(db, "h1.example.com", host_tags="epic")
    assert _match_preview(db, [], sample_limit=5) == (0, [])
    assert _match_preview(db, [""], sample_limit=5) == (0, [])


def test_match_preview_sample_limit(db):
    for i in range(7):
        _seed(db, f"h{i}.example.com", host_tags="epic")
    count, sample = _match_preview(db, ["epic"], sample_limit=3)
    assert count == 7
    assert len(sample) == 3


def test_match_preview_like_wildcard_in_tag_does_not_overmatch(db):
    """A tag containing a LIKE wildcard (% or _) must not match everything (BC-051)."""
    _seed(db, "h1.example.com", host_tags="epic")
    _seed(db, "h2.example.com", host_tags="infra")
    # '%' would match all rows if not escaped; here it must match nothing real.
    count, _ = _match_preview(db, ["%"], sample_limit=0)
    assert count == 0
    # An underscore wildcard tag likewise matches only a literal "_" tag.
    count2, _ = _match_preview(db, ["_"], sample_limit=0)
    assert count2 == 0


def test_match_preview_only_counts_leaf_certs(db):
    """Non-leaf (chain) certs are not counted -- alerts apply to leaf certs."""
    SqliteHostRepository(db).add("h.example.com", 443, tags="epic")
    repo = SqliteCertificateRepository(db, hostname="h.example.com", port=443)
    leaf = Certificate(
        subject="CN=leaf", issuer="CN=issuer",
        not_before=datetime.now(UTC) - timedelta(days=360),
        not_after=datetime.now(UTC) + timedelta(days=5),
        san_dns_names=["h.example.com"], fingerprint_sha256="aa" * 32,
        raw_der=b"\x00" * 10, is_leaf=True,
    )
    intermediate = Certificate(
        subject="CN=intermediate", issuer="CN=root",
        not_before=datetime.now(UTC) - timedelta(days=360),
        not_after=datetime.now(UTC) + timedelta(days=5),
        san_dns_names=[], fingerprint_sha256="bb" * 32,
        raw_der=b"\x00" * 10, is_leaf=False,
    )
    repo.add(leaf)
    repo.add(intermediate)
    # Tag both via SQL so the chain cert also carries the tag.
    with _connect(db) as conn:
        conn.execute("UPDATE certificates SET tags = 'epic' WHERE is_leaf = 1")
        conn.execute("UPDATE certificates SET tags = 'epic' WHERE is_leaf = 0")
        conn.commit()
    count, _ = _match_preview(db, ["epic"], sample_limit=0)
    assert count == 1  # only the leaf


def test_match_preview_parity_with_tags_match(db):
    """_match_preview's SQL count must equal the canonical tags_match over leaf
    certs' effective tags (the parity guarantee for the tag-based baseline).

    Guards the core contract: the preview's escaped-LIKE SQL agrees with the
    Python tags_match that the alert engine uses, for the tag-only half of
    routing (no manual assignments / role-links in this fixture).
    """
    from cert_watch.tags import tags_match

    _seed(db, "a.example.com", host_tags="epic")
    _seed(db, "b.example.com", host_tags="infra, monitoring")
    _seed(db, "c.example.com", cert_tags="epic")
    _seed(db, "d.example.com", host_tags="prod")

    cert_repo = SqliteCertificateRepository(db)
    with _connect(db) as conn:
        leaf_ids = [r["id"] for r in conn.execute(
            "SELECT id FROM certificates WHERE is_leaf = 1"
        ).fetchall()]

    def engine_count(match_tags: list[str]) -> int:
        return sum(
            1 for cid in leaf_ids
            if tags_match(cert_repo.effective_tags(cid), match_tags)
        )

    for match_tags in (
        ["epic"], ["infra"], ["infra", "monitoring"],
        ["epic", "prod"], ["nonexistent"], [],
    ):
        expected = engine_count(match_tags)
        preview_count, _ = _match_preview(db, match_tags, sample_limit=0)
        assert preview_count == expected, (
            f"parity mismatch for {match_tags}: preview={preview_count} engine={expected}"
        )


def test_match_preview_non_ascii_casefold_parity(db):
    """WI-066: non-ASCII tag casing matches with the same parity as the Python
    casefold engine. SQLite LIKE is ASCII-CI only, so without cw_casefold the
    SQL undercounts vs tags_match for the ß/SS case-variant."""
    from cert_watch.tags import tags_match

    _seed(db, "de.example.com", host_tags="STRASSE")  # ASCII all-caps

    # The engine matches the eszett case-variant via casefold (ß -> ss):
    assert tags_match(["STRASSE"], ["Straße"]) is True
    # The SQL preview must agree. Before WI-066 this was 0 (LIKE is ASCII-CI:
    # "STRASSE" and "Straße" differ in the ß/ss bytes and LIKE only folds A-Z).
    assert _match_preview(db, ["Straße"], sample_limit=0)[0] == 1
    # The plain lower-case ASCII variant also matches.
    assert _match_preview(db, ["strasse"], sample_limit=0)[0] == 1


# ---------- routes (inline count + preview endpoint) ----------


def _db_path(tmp_path: Path) -> Path:
    return tmp_path / "cert-watch.sqlite3"


def test_inline_match_count_on_alert_groups_page(reload_app, tmp_path):
    app_mod = reload_app()
    db = _db_path(tmp_path)
    with TestClient(app_mod.app) as client:
        # Seed after the app lifespan has initialized the schema.
        SqliteHostRepository(db).add("tagged.example.com", 443, tags="platform")
        SqliteCertificateRepository(db, hostname="tagged.example.com", port=443).add(
            Certificate(
                subject="CN=tagged", issuer="CN=issuer",
                not_before=datetime.now(UTC) - timedelta(days=360),
                not_after=datetime.now(UTC) + timedelta(days=5),
                san_dns_names=["tagged.example.com"], fingerprint_sha256="cc" * 32,
                raw_der=b"\x00" * 10, is_leaf=True,
            )
        )
        SqliteAlertGroupRepository(db).create("platform", ["ops@x.com"], ["platform"])
        gid = SqliteAlertGroupRepository(db).get_by_name("platform").id

        page = client.get("/settings/alert-groups").text

    assert f'data-testid="ag-match-count-{gid}"' in page
    assert "1 cert" in page  # singular form


def test_preview_endpoint_shows_count_and_sample(reload_app, tmp_path):
    app_mod = reload_app()
    db = _db_path(tmp_path)
    with TestClient(app_mod.app) as client:
        SqliteHostRepository(db).add("tagged.example.com", 443, tags="epic")
        SqliteCertificateRepository(db, hostname="tagged.example.com", port=443).add(
            Certificate(
                subject="CN=tagged", issuer="CN=issuer",
                not_before=datetime.now(UTC) - timedelta(days=360),
                not_after=datetime.now(UTC) + timedelta(days=5),
                san_dns_names=["tagged.example.com"], fingerprint_sha256="dd" * 32,
                raw_der=b"\x00" * 10, is_leaf=True,
            )
        )
        r = client.get("/settings/alert-groups/preview", params={"match_tags": "epic"})
    assert r.status_code == 200
    body = r.text
    assert 'data-testid="ag-preview-result"' in body
    assert "tagged.example.com" in body  # sample hostname rendered
    assert "<strong>1</strong>" in body  # count rendered (singular)


def test_preview_endpoint_no_matches_message(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/settings/alert-groups/preview", params={"match_tags": "nope"})
    assert r.status_code == 200
    assert "No certs carry" in r.text  # zero-match guidance copy
