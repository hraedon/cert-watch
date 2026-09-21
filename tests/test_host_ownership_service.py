from __future__ import annotations

import json
from pathlib import Path

import pytest

from cert_watch.audit import list_audit
from cert_watch.database import SqliteHostRepository, init_schema
from cert_watch.services import host_ownership
from cert_watch.services.host_ownership import (
    HostOwnershipUpdate,
    HostOwnershipValidationError,
    update_host_ownership,
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
