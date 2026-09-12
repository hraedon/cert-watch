"""Shared certificate fingerprints must not confer access to other endpoints."""
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from cert_watch.attention import build_attention_queue
from cert_watch.certificate_model import _from_x509
from cert_watch.database import (
    SqliteCertificateRepository,
    SqliteHostRepository,
    init_schema,
    list_dashboard_grouped_page,
)
from tests._helpers import seed_certificate


def _shared_endpoints(tmp_path, chain_triplet, *, tag_on="host", tag="team", hidden_tag="hidden"):
    db = tmp_path / "scope.sqlite3"
    init_schema(db)
    hosts = SqliteHostRepository(db)
    now = datetime.now(UTC)
    certificate = _from_x509(chain_triplet["leaf"].cert)
    ids = []
    for port, scope, days in ((443, tag, 3), (636, hidden_tag, -2)):
        hosts.add("shared.example.test", port, tags=scope if tag_on == "host" else "")
        # Deliberately inconsistent retained metadata exercises worst-urgency
        # aggregation, as well as identity, for the same shared fingerprint.
        cert_id = seed_certificate(
            db, replace(certificate, not_after=now + timedelta(days=days)),
            hostname="shared.example.test", port=port,
        )
        if tag_on == "cert":
            SqliteCertificateRepository(db).set_tags(cert_id, scope)
        ids.append(cert_id)
    return db, ids, certificate


@pytest.mark.parametrize("tag_on", ["host", "cert"])
def test_shared_fingerprint_scopes_children_counts_and_urgency(tmp_path, chain_triplet, tag_on):
    db, (visible_id, hidden_id), _ = _shared_endpoints(tmp_path, chain_triplet, tag_on=tag_on)

    rows, total = list_dashboard_grouped_page(db, scope_tags=["team"], per_page=0)

    assert total == 1
    group = rows[0]
    assert group["host_count"] == 1
    assert [child["id"] for child in group["hosts"]] == [visible_id]
    assert group["urgency"] == "critical"
    assert group["urgency_summary"] == {"critical": 1}
    assert "hidden" not in group["tags"]
    assert hidden_id not in str(rows)


@pytest.mark.parametrize("urgency, expected_count", [("critical", 1), ("expired", 0)])
def test_scope_is_applied_before_group_status_filter(
    tmp_path, chain_triplet, urgency, expected_count,
):
    db, (visible_id, _), _ = _shared_endpoints(tmp_path, chain_triplet)

    rows, total = list_dashboard_grouped_page(
        db, scope_tags=["team"], urgency=urgency, per_page=0,
    )

    assert total == expected_count
    assert [child["id"] for group in rows for child in group["hosts"]] == (
        [visible_id] if expected_count else []
    )


def test_admin_retains_all_shared_endpoints(tmp_path, chain_triplet):
    db, cert_ids, _ = _shared_endpoints(tmp_path, chain_triplet)

    rows, total = list_dashboard_grouped_page(db, scope_tags=(), per_page=0)

    assert total == 1
    assert rows[0]["host_count"] == 2
    assert {child["id"] for child in rows[0]["hosts"]} == set(cert_ids)
    assert rows[0]["urgency"] == "expired"


@pytest.mark.parametrize("tag_on", ["host", "cert"])
def test_attention_cannot_expand_access_through_shared_fingerprint(tmp_path, chain_triplet, tag_on):
    db, (visible_id, hidden_id), _ = _shared_endpoints(tmp_path, chain_triplet, tag_on=tag_on)

    queue = build_attention_queue(db, scope_tags=["team"])

    assert queue
    assert {item["cert_id"] for item in queue} == {visible_id}
    assert {item["endpoint"] for item in queue} == {"shared.example.test:443"}
    assert hidden_id not in str(queue)


@pytest.mark.parametrize("scope, stored_tag", [("team_%", "team_%"), ("Straße", "STRASSE")])
def test_group_scope_preserves_literal_and_casefold_matching(
    tmp_path, chain_triplet, scope, stored_tag,
):
    db, (visible_id, _), _ = _shared_endpoints(
        tmp_path, chain_triplet, tag=stored_tag, hidden_tag="team_A",
    )

    rows, total = list_dashboard_grouped_page(db, scope_tags=[scope], per_page=0)

    assert total == 1
    assert [child["id"] for child in rows[0]["hosts"]] == [visible_id]


def test_uploaded_shared_fingerprint_does_not_hide_pending_endpoint(tmp_path, chain_triplet):
    db, cert_ids, certificate = _shared_endpoints(tmp_path, chain_triplet)
    pending_id = SqliteHostRepository(db).add("upload-only.example.test", 8443)
    upload_id = seed_certificate(
        db, certificate, source="uploaded", hostname="upload-only.example.test", port=8443,
    )

    rows, total = list_dashboard_grouped_page(db, per_page=0)

    assert total == 3
    assert {row["kind"] for row in rows} == {"grouped", "uploaded", "pending"}
    group = next(row for row in rows if row["kind"] == "grouped")
    assert {child["id"] for child in group["hosts"]} == set(cert_ids)
    assert next(row for row in rows if row["kind"] == "uploaded")["id"] == upload_id
    assert next(row for row in rows if row["kind"] == "pending")["host_id"] == pending_id
