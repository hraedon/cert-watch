"""Application services for host notes and resource tags."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from cert_watch.audit import record_audit
from cert_watch.database.connection import _connect, get_write_lock
from cert_watch.database.metadata_ops import (
    update_certificate_tags as persist_certificate_tags,
)
from cert_watch.database.metadata_ops import update_host_notes as persist_host_notes
from cert_watch.database.metadata_ops import update_host_tags as persist_host_tags
from cert_watch.database.repo import SqliteCertificateRepository
from cert_watch.tags import format_tags, parse_tags

MAX_NOTES_LENGTH = 10_000
MAX_TAGS_LENGTH = 2_000


@dataclass(frozen=True)
class TagUpdateResult:
    resource_id: str
    normalized: str
    tags: tuple[str, ...]
    effective_tags: tuple[str, ...] = ()


class ResourceMetadataValidationError(ValueError):
    """A note or tag value is not safe to persist."""


class ResourceMetadataNotFoundError(LookupError):
    """The host or certificate being updated does not exist."""


def _run_transaction(
    db_path: str | Path,
    *,
    persist: Callable[[sqlite3.Connection], bool],
    action: str,
    target_type: str,
    target_id: str,
    detail: dict[str, object],
    actor: str,
    source_ip: str | None,
) -> None:
    with get_write_lock():
        conn = _connect(db_path)
        try:
            if not persist(conn):
                raise ResourceMetadataNotFoundError(f"{target_type} not found")
            record_audit(
                db_path,
                actor=actor,
                action=action,
                target_type=target_type,
                target_id=target_id,
                detail=detail,
                source_ip=source_ip,
                conn=conn,
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise


def update_host_notes(
    db_path: str | Path,
    host_id: str,
    notes: str,
    *,
    actor: str,
    source_ip: str | None,
) -> str:
    if not isinstance(notes, str):
        raise ResourceMetadataValidationError("notes must be a string")
    if len(notes) > MAX_NOTES_LENGTH:
        raise ResourceMetadataValidationError("notes too long (max 10000)")
    _run_transaction(
        db_path,
        persist=lambda conn: persist_host_notes(conn, host_id, notes),
        action="host.update_notes",
        target_type="host",
        target_id=host_id,
        detail={"notes_length": len(notes)},
        actor=actor,
        source_ip=source_ip,
    )
    return notes


def normalize_tags(tags: str) -> str:
    if not isinstance(tags, str):
        raise ResourceMetadataValidationError("tags must be a string")
    normalized = format_tags(parse_tags(tags))
    if len(normalized) > MAX_TAGS_LENGTH:
        raise ResourceMetadataValidationError("tags too long (max 2000)")
    return normalized


def update_host_tags(
    db_path: str | Path,
    host_id: str,
    tags: str,
    *,
    actor: str,
    source_ip: str | None,
) -> TagUpdateResult:
    normalized = normalize_tags(tags)
    _run_transaction(
        db_path,
        persist=lambda conn: persist_host_tags(conn, host_id, normalized),
        action="host.update_tags",
        target_type="host",
        target_id=host_id,
        detail={"tags": normalized},
        actor=actor,
        source_ip=source_ip,
    )
    return TagUpdateResult(host_id, normalized, tuple(parse_tags(normalized)))


def update_certificate_tags(
    db_path: str | Path,
    cert_id: str,
    tags: str,
    *,
    actor: str,
    source_ip: str | None,
) -> TagUpdateResult:
    normalized = normalize_tags(tags)
    _run_transaction(
        db_path,
        persist=lambda conn: persist_certificate_tags(conn, cert_id, normalized),
        action="cert.update_tags",
        target_type="certificate",
        target_id=cert_id,
        detail={"tags": normalized},
        actor=actor,
        source_ip=source_ip,
    )
    effective = SqliteCertificateRepository(db_path).effective_tags(cert_id)
    return TagUpdateResult(
        cert_id,
        normalized,
        tuple(parse_tags(normalized)),
        tuple(effective),
    )
