"""Application services for host notes and resource tags.

Each service requires the acting :class:`~cert_watch.auth.rbac.AuthContext`
(``auth``; trusted internal/auth-disabled callers use ``AuthContext.system()``)
and enforces tag scope itself, inside the write lock, before it validates or persists anything:
target scope first, then input validation, then (for tags) that every new tag
is within scope. Route adapters only translate the exceptions.

An input may be passed as a zero-argument callable (a :data:`Deferred`), which
runs after the target-scope check: a JSON adapter hands over its body parser,
so a caller outside the target's scope is refused before its body is judged.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cert_watch.audit import export_audit, record_audit
from cert_watch.auth.scope import (
    ensure_new_tags_in_scope,
    ensure_write_scope,
    ensure_write_scope_on,
    require_auth_context,
    unknown_target_scope_error,
)
from cert_watch.database.connection import _connect, begin_immediate, get_write_lock
from cert_watch.database.metadata_ops import (
    update_certificate_tags as persist_certificate_tags,
)
from cert_watch.database.metadata_ops import update_host_notes as persist_host_notes
from cert_watch.database.metadata_ops import update_host_tags as persist_host_tags
from cert_watch.database.repo import SqliteCertificateRepository
from cert_watch.services.certificate_identity import (
    ensure_not_superseded,
    refuse_if_superseded,
)
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


# A value, or a zero-argument callable producing it (raising
# ResourceMetadataValidationError for bad input) that runs after the scope check.
type Deferred[T] = T | Callable[[], T]


def _value[T](value: Deferred[T]) -> T:
    return value() if callable(value) else value


def _transact(
    db_path: str | Path,
    *,
    persist: Callable[[sqlite3.Connection], bool],
    action: str,
    target_type: str,
    target_id: str,
    detail: dict[str, object],
    actor: str,
    source_ip: str | None,
    guard: Callable[[sqlite3.Connection], None] | None = None,
) -> dict[str, Any] | None:
    """Persist + audit in one ``BEGIN IMMEDIATE`` transaction. *guard* runs
    first inside it, so a check it makes holds until the write commits. The
    caller holds the write lock and calls :func:`export_audit` on the
    returned event once it is released."""
    conn = _connect(db_path)
    try:
        begin_immediate(conn)
        if guard is not None:
            guard(conn)
        if not persist(conn):
            raise ResourceMetadataNotFoundError(f"{target_type} not found")
        audit_event = record_audit(
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
    return audit_event


def update_host_notes(
    db_path: str | Path,
    host_id: str,
    notes: Deferred[Any],
    *,
    auth: Any,
    actor: str,
    source_ip: str | None,
) -> str:
    require_auth_context(auth)
    with get_write_lock():
        ensure_write_scope(auth, db_path, host_id=host_id)
        value = _value(notes)
        if not isinstance(value, str):
            raise ResourceMetadataValidationError("notes must be a string")
        if len(value) > MAX_NOTES_LENGTH:
            raise ResourceMetadataValidationError("notes too long (max 10000)")
        event = _transact(
            db_path,
            persist=lambda conn: persist_host_notes(conn, host_id, value),
            guard=lambda conn: ensure_write_scope_on(conn, auth, host_id=host_id),
            action="host.update_notes",
            target_type="host",
            target_id=host_id,
            detail={"notes_length": len(value)},
            actor=actor,
            source_ip=source_ip,
        )
    export_audit(event)
    return value


def normalize_tags(tags: Any) -> str:
    if not isinstance(tags, str):
        raise ResourceMetadataValidationError("tags must be a string")
    normalized = format_tags(parse_tags(tags))
    if len(normalized) > MAX_TAGS_LENGTH:
        raise ResourceMetadataValidationError("tags too long (max 2000)")
    return normalized


def update_host_tags(
    db_path: str | Path,
    host_id: str,
    tags: Deferred[Any],
    *,
    auth: Any,
    actor: str,
    source_ip: str | None,
) -> TagUpdateResult:
    require_auth_context(auth)
    with get_write_lock():
        ensure_write_scope(auth, db_path, host_id=host_id)
        normalized = normalize_tags(_value(tags))
        ensure_new_tags_in_scope(auth, normalized)
        event = _transact(
            db_path,
            persist=lambda conn: persist_host_tags(conn, host_id, normalized),
            guard=lambda conn: ensure_write_scope_on(conn, auth, host_id=host_id),
            action="host.update_tags",
            target_type="host",
            target_id=host_id,
            detail={"tags": normalized},
            actor=actor,
            source_ip=source_ip,
        )
    export_audit(event)
    return TagUpdateResult(host_id, normalized, tuple(parse_tags(normalized)))


def update_certificate_tags(
    db_path: str | Path,
    cert_id: str,
    tags: Deferred[Any],
    *,
    auth: Any,
    actor: str,
    source_ip: str | None,
) -> TagUpdateResult:
    require_auth_context(auth)
    with get_write_lock():
        def hidden() -> Exception:
            return unknown_target_scope_error(auth, db_path)

        def guard(conn: sqlite3.Connection) -> None:
            # Inside the write transaction, immediately before the write:
            # lineage, then the authoritative scope check (#115 rounds 3, 10).
            ensure_not_superseded(conn, cert_id, auth=auth, hidden=hidden)
            ensure_write_scope_on(conn, auth, cert_id=cert_id)

        refuse_if_superseded(db_path, cert_id, auth=auth, hidden=hidden)
        ensure_write_scope(auth, db_path, cert_id=cert_id)
        normalized = normalize_tags(_value(tags))
        ensure_new_tags_in_scope(auth, normalized)
        event = _transact(
            db_path,
            persist=lambda conn: persist_certificate_tags(conn, cert_id, normalized),
            guard=guard,
            action="cert.update_tags",
            target_type="certificate",
            target_id=cert_id,
            detail={"tags": normalized},
            actor=actor,
            source_ip=source_ip,
        )
    export_audit(event)
    effective = SqliteCertificateRepository(db_path).effective_tags(cert_id)
    return TagUpdateResult(
        cert_id,
        normalized,
        tuple(parse_tags(normalized)),
        tuple(effective),
    )
