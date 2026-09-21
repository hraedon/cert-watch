from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from cert_watch.audit import list_audit
from cert_watch.certificate_model import Certificate
from cert_watch.database import (
    SqliteCertificateRepository,
    SqliteHostRepository,
    init_schema,
)
from cert_watch.services import resource_metadata
from cert_watch.services.resource_metadata import (
    ResourceMetadataNotFoundError,
    ResourceMetadataValidationError,
    update_certificate_tags,
    update_host_notes,
    update_host_tags,
)


def test_host_notes_and_tags_share_validation_persistence_and_audit(tmp_path: Path) -> None:
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    repo = SqliteHostRepository(db)
    host_id = repo.add("metadata.example.test")

    notes = update_host_notes(
        db, host_id, "renew through ACME", actor="operator", source_ip="192.0.2.10"
    )
    tags = update_host_tags(
        db, host_id, " prod, web,prod ", actor="operator", source_ip="192.0.2.10"
    )

    stored = repo.get(host_id)
    assert stored is not None
    assert notes == stored.notes == "renew through ACME"
    assert tags.tags == ("prod", "web")
    assert stored.tags == "prod,web"
    audit = list_audit(db, target_id=host_id)
    assert [row["action"] for row in audit] == ["host.update_tags", "host.update_notes"]
    assert json.loads(audit[0]["detail"]) == {"tags": "prod,web"}


def test_certificate_tags_return_effective_host_tags(tmp_path: Path) -> None:
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    hosts = SqliteHostRepository(db)
    hosts.add("metadata.example.test", tags="platform")
    certs = SqliteCertificateRepository(
        db, source="scanned", hostname="metadata.example.test", port=443
    )
    now = datetime.now(UTC)
    cert_id = certs.add(
        Certificate(
            subject="CN=metadata.example.test",
            issuer="CN=Test CA",
            not_before=now - timedelta(days=1),
            not_after=now + timedelta(days=30),
        )
    )

    result = update_certificate_tags(
        db, cert_id, "prod, platform", actor="operator", source_ip=None
    )

    assert result.tags == ("prod", "platform")
    assert set(result.effective_tags) == {"platform", "prod"}
    assert SqliteCertificateRepository(db).get_tags(cert_id) == "prod,platform"


def test_metadata_validation_and_missing_target_precede_audit(tmp_path: Path) -> None:
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)

    with pytest.raises(ResourceMetadataValidationError, match="notes too long"):
        update_host_notes(db, "missing", "x" * 10_001, actor="operator", source_ip=None)
    with pytest.raises(ResourceMetadataNotFoundError):
        update_host_tags(db, "missing", "prod", actor="operator", source_ip=None)

    assert list_audit(db) == []


def test_audit_failure_rolls_back_metadata_update(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    repo = SqliteHostRepository(db)
    host_id = repo.add("metadata.example.test", notes="before")

    def fail_audit(*args: object, **kwargs: object) -> None:
        raise RuntimeError("audit unavailable")

    monkeypatch.setattr(resource_metadata, "record_audit", fail_audit)
    with pytest.raises(RuntimeError, match="audit unavailable"):
        update_host_notes(db, host_id, "after", actor="operator", source_ip=None)

    stored = repo.get(host_id)
    assert stored is not None
    assert stored.notes == "before"
    assert list_audit(db, target_id=host_id) == []
