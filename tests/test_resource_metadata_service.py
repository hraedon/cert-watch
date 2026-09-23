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
        db, host_id, "renew through ACME", auth=None, actor="operator", source_ip="192.0.2.10"
    )
    tags = update_host_tags(
        db, host_id, " prod, web,prod ", auth=None, actor="operator", source_ip="192.0.2.10"
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
        db, cert_id, "prod, platform", auth=None, actor="operator", source_ip=None
    )

    assert result.tags == ("prod", "platform")
    assert set(result.effective_tags) == {"platform", "prod"}
    assert SqliteCertificateRepository(db).get_tags(cert_id) == "prod,platform"


def test_metadata_validation_and_missing_target_precede_audit(tmp_path: Path) -> None:
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)

    with pytest.raises(ResourceMetadataValidationError, match="notes too long"):
        update_host_notes(db, "missing", "x" * 10_001, auth=None, actor="operator", source_ip=None)
    with pytest.raises(ResourceMetadataNotFoundError):
        update_host_tags(db, "missing", "prod", auth=None, actor="operator", source_ip=None)

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
        update_host_notes(db, host_id, "after", auth=None, actor="operator", source_ip=None)

    stored = repo.get(host_id)
    assert stored is not None
    assert stored.notes == "before"
    assert list_audit(db, target_id=host_id) == []


def test_siem_export_runs_after_commit_and_outside_the_write_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A SIEM sink can block, so it must never run under the global write lock,
    and the event it carries must describe a row that is already committed."""
    import sqlite3
    import threading

    from cert_watch import siem
    from cert_watch.database.connection import get_write_lock
    from cert_watch.services.host_ownership import (
        HostOwnershipUpdate,
        update_host_ownership,
    )

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    host_id = SqliteHostRepository(db).add("siem.example.test")
    observed: list[tuple[str, bool, int]] = []

    def export(event: dict[str, object]) -> None:
        acquired: list[bool] = []

        def other_writer() -> None:
            lock = get_write_lock()
            got = lock.acquire(timeout=0.5)
            acquired.append(got)
            if got:
                lock.release()

        worker = threading.Thread(target=other_writer)
        worker.start()
        worker.join()
        with sqlite3.connect(db) as other:
            committed = other.execute(
                "SELECT COUNT(*) FROM audit_log WHERE action = ?", (event["action"],)
            ).fetchone()[0]
        observed.append((str(event["action"]), acquired[0], committed))

    monkeypatch.setattr(siem, "siem_enabled", lambda: True)
    monkeypatch.setattr(siem, "export_audit_event", export)

    update_host_notes(db, host_id, "n", auth=None, actor="op", source_ip=None)
    update_host_tags(db, host_id, "prod", auth=None, actor="op", source_ip=None)
    update_host_ownership(
        db, host_id, HostOwnershipUpdate(owner_name="Ops"), auth=None, actor="op", source_ip=None
    )

    assert [action for action, _, _ in observed] == [
        "host.update_notes", "host.update_tags", "owner.update",
    ]
    assert all(lock_free for _, lock_free, _ in observed)
    assert all(committed == 1 for _, _, committed in observed)


def test_record_audit_without_conn_never_raises_on_bad_input(tmp_path: Path) -> None:
    from cert_watch.audit import record_audit

    record_audit(
        tmp_path / "missing.sqlite3",
        actor=object(),  # type: ignore[arg-type]
        action="probe.bad_input",
        target_type="host",
        target_id="x",
    )
