from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from cert_watch.audit import list_audit
from cert_watch.certificate_model import Certificate
from cert_watch.database import SqliteHostRepository, init_schema
from cert_watch.services import host_ownership
from cert_watch.services.host_ownership import (
    HostOwnershipTargetError,
    HostOwnershipUpdate,
    HostOwnershipValidationError,
    resolve_host_ownership_target,
    update_host_ownership,
)
from tests._helpers import seed_certificate


def _certificate() -> Certificate:
    now = datetime.now(UTC)
    return Certificate(
        subject="CN=owner.example.test",
        issuer="CN=Test CA",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=30),
    )


def test_ownership_update_is_partial_and_audited(tmp_path: Path) -> None:
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    repo = SqliteHostRepository(db)
    host_id = repo.add(
        "owner.example.test",
        owner_name="Before",
        owner_email="before@example.test",
        renewal_method="manual",
    )

    result = update_host_ownership(
        db,
        host_id,
        HostOwnershipUpdate(
            owner_name="After",
            runbook_url="https://wiki.example.test/renewal",
        ),
        actor="operator",
        source_ip="192.0.2.10",
    )

    assert result.owner_name == "After"
    assert result.owner_email == "before@example.test"
    assert result.renewal_method == "manual"
    assert result.runbook_url == "https://wiki.example.test/renewal"
    audit = list_audit(db, target_id=host_id)
    assert len(audit) == 1
    detail = json.loads(audit[0]["detail"])
    assert detail["owner_name"] == "After"
    assert detail["runbook_url"] == "https://wiki.example.test/renewal"


def test_ownership_validation_precedes_mutation(tmp_path: Path) -> None:
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    repo = SqliteHostRepository(db)
    host_id = repo.add("owner.example.test", owner_name="Before")

    with pytest.raises(HostOwnershipValidationError, match="invalid email"):
        update_host_ownership(
            db,
            host_id,
            HostOwnershipUpdate(owner_name="After", owner_email="not-an-email"),
            actor="operator",
            source_ip=None,
        )

    stored = repo.get(host_id)
    assert stored is not None
    assert stored.owner_name == "Before"
    assert list_audit(db, target_id=host_id) == []


def test_audit_failure_rolls_back_ownership_update(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    repo = SqliteHostRepository(db)
    host_id = repo.add("owner.example.test", owner_name="Before")

    def fail_audit(*args: object, **kwargs: object) -> None:
        raise RuntimeError("audit unavailable")

    monkeypatch.setattr(host_ownership, "record_audit", fail_audit)
    with pytest.raises(RuntimeError, match="audit unavailable"):
        update_host_ownership(
            db,
            host_id,
            HostOwnershipUpdate(owner_name="After"),
            actor="operator",
            source_ip=None,
        )

    stored = repo.get(host_id)
    assert stored is not None
    assert stored.owner_name == "Before"


def test_resolve_ownership_target_accepts_host_or_certificate_id(tmp_path: Path) -> None:
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    repo = SqliteHostRepository(db)
    host_id = repo.add("owner.example.test", port=8443)
    seed_certificate(
        db,
        _certificate(),
        cert_id="cert-id",
        hostname="owner.example.test",
        port=8443,
    )

    by_host = resolve_host_ownership_target(db, host_id)
    by_certificate = resolve_host_ownership_target(db, "cert-id")

    assert (by_host.host_id, by_host.source) == (host_id, "host")
    assert (by_certificate.host_id, by_certificate.source) == (host_id, "certificate")


def test_resolve_ownership_target_reports_missing_association(tmp_path: Path) -> None:
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    seed_certificate(
        db,
        _certificate(),
        cert_id="cert-id",
        source="uploaded",
        hostname="",
        port=443,
    )

    with pytest.raises(HostOwnershipTargetError) as exc_info:
        resolve_host_ownership_target(db, "cert-id")

    assert exc_info.value.reason == "no_host_associated"
