"""One atomic edit for every host field owned by the detail page."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cert_watch.audit import export_audit, record_audit
from cert_watch.auth.scope import (
    ensure_tag_update_retains_scope,
    ensure_write_scope,
    ensure_write_scope_on,
    require_auth_context,
    unknown_target_scope_error,
)
from cert_watch.database import HostEntry, SqliteHostRepository
from cert_watch.database.connection import _connect, _sql_now, begin_immediate, get_write_lock
from cert_watch.database.metadata_ops import (
    update_certificate_tags as persist_certificate_tags,
)
from cert_watch.database.renewal_attempts import host_projection_sql
from cert_watch.scan_freshness import scan_interval_out_of_range
from cert_watch.services.certificate_identity import (
    ensure_not_superseded,
    refuse_if_superseded,
)
from cert_watch.services.host_management import HostNotFoundError, HostValidationError
from cert_watch.services.host_ownership import (
    HostOwnershipUpdate,
    HostOwnershipValidationError,
    resolve_host_ownership_target,
    validate_host_ownership,
)
from cert_watch.services.renewal_reports import write_through_renewal_status_on
from cert_watch.services.resource_metadata import (
    MAX_NOTES_LENGTH,
    ResourceMetadataValidationError,
    _authorize_tag_transition,
    normalize_tags,
)
from cert_watch.tags import parse_tags


@dataclass(frozen=True)
class HostEditUpdate:
    owner_name: Any = ""
    owner_email: Any = ""
    owner_slack: Any = ""
    renewal_method: Any = ""
    runbook_url: Any = ""
    scan_interval_hours: Any = None
    threshold_days: Any = None
    renewal_status: Any = None
    renewal_status_seen: Any = None
    require_renewal_status_seen: bool = False
    notes: Any = ""
    tags: Any = ""


@dataclass(frozen=True)
class HostEditResult:
    host: HostEntry
    tags: tuple[str, ...]
    tags_apply_to: str


def _optional_positive_int(value: Any, *, field: str) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise HostValidationError(f"{field} must be a whole number, or blank.")
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise HostValidationError(f"{field} must be a whole number, or blank.") from None
    if isinstance(value, float) and value != parsed:
        raise HostValidationError(f"{field} must be a whole number, or blank.")
    return parsed


def _validate(
    update: HostEditUpdate, current: HostEntry
) -> tuple[HostOwnershipUpdate, int | None, int | None, str]:
    for field in ("notes", "tags"):
        if not isinstance(getattr(update, field), str):
            raise ResourceMetadataValidationError(f"{field} must be a string")
    ownership = validate_host_ownership(
        HostOwnershipUpdate(
            owner_name=update.owner_name,
            owner_email=update.owner_email,
            owner_slack=update.owner_slack,
            renewal_method=update.renewal_method,
            runbook_url=update.runbook_url,
            renewal_status=update.renewal_status,
            renewal_status_seen=update.renewal_status_seen,
            require_renewal_status_seen=update.require_renewal_status_seen,
        )
    )
    for field in (
        "owner_name",
        "owner_email",
        "owner_slack",
        "renewal_method",
        "runbook_url",
    ):
        if getattr(ownership, field) is None:
            raise HostOwnershipValidationError(field, f"{field} must be a string")
    if len(update.notes) > MAX_NOTES_LENGTH:
        raise ResourceMetadataValidationError("notes too long (max 10000)")

    interval = _optional_positive_int(update.scan_interval_hours, field="Scan interval")
    threshold = _optional_positive_int(update.threshold_days, field="Alert threshold")
    if interval != current.scan_interval_hours and scan_interval_out_of_range(interval):
        raise HostValidationError(
            "Scan interval must be between 1 and 8760 hours, or blank for daily."
        )
    if threshold is not None and not 1 <= threshold <= 2**63 - 1:
        raise HostValidationError(
            "Alert threshold must be a positive whole number within the stored range."
        )
    return ownership, interval, threshold, normalize_tags(update.tags)


def edit_host(
    db_path: str | Path,
    resource_id: str,
    update: HostEditUpdate | Callable[[], HostEditUpdate],
    *,
    auth: Any,
    actor: str,
    source_ip: str | None,
) -> HostEditResult:
    """Update ownership, cadence, notes and the detail page's tag field atomically.

    ``resource_id`` may be a current certificate or host id. Certificate detail
    keeps its existing certificate-own-tags capability; pending-host detail edits
    host tags. Superseded certificate ids are refused both before and inside the
    write transaction.
    """
    require_auth_context(auth)
    target = resolve_host_ownership_target(db_path, resource_id, auth=auth)
    named_cert = target.resource_id if target.source == "certificate" else ""

    def hidden() -> Exception:
        return unknown_target_scope_error(auth, db_path)

    with get_write_lock():
        if named_cert:
            refuse_if_superseded(db_path, named_cert, auth=auth, hidden=hidden)
        # Every field except certificate tags belongs to the host.  A route
        # addressed by certificate id must therefore pass the host boundary,
        # and its tag write must independently pass the certificate boundary.
        ensure_write_scope(auth, db_path, host_id=target.host_id)
        if named_cert:
            ensure_write_scope(auth, db_path, cert_id=named_cert)
        current = SqliteHostRepository(db_path).get(target.host_id)
        if current is None:
            raise HostNotFoundError("host not found")
        resolved = update() if callable(update) else update
        ownership, interval, threshold, normalized_tags = _validate(resolved, current)
        if named_cert:
            with _connect(db_path) as read_conn:
                row = read_conn.execute(
                    "SELECT tags FROM certificates WHERE id = ?", (named_cert,)
                ).fetchone()
            if row is None:
                raise HostNotFoundError("certificate not found")
            current_resource_tags = row["tags"]
        else:
            current_resource_tags = current.tags
        normalized_tags = _authorize_tag_transition(
            auth, current_resource_tags, normalized_tags
        )
        final_effective_tags = parse_tags(normalized_tags)
        if named_cert:
            final_effective_tags.extend(parse_tags(current.tags))
        ensure_tag_update_retains_scope(auth, final_effective_tags)

        conn = _connect(db_path)
        try:
            begin_immediate(conn)
            if named_cert:
                ensure_not_superseded(conn, named_cert, auth=auth, hidden=hidden)
            ensure_write_scope_on(conn, auth, host_id=target.host_id)
            if named_cert:
                ensure_write_scope_on(conn, auth, cert_id=named_cert)
            if named_cert:
                resource_tags = conn.execute(
                    "SELECT tags FROM certificates WHERE id = ?", (named_cert,)
                ).fetchone()
            else:
                resource_tags = conn.execute(
                    "SELECT tags FROM hosts WHERE id = ?", (target.host_id,)
                ).fetchone()
            if resource_tags is None:
                raise HostNotFoundError(
                    "certificate not found" if named_cert else "host not found"
                )
            normalized_tags = _authorize_tag_transition(
                auth, resource_tags["tags"], normalized_tags
            )
            host_tags = conn.execute(
                "SELECT tags FROM hosts WHERE id = ?", (target.host_id,)
            ).fetchone()
            final_effective_tags = parse_tags(normalized_tags)
            if named_cert and host_tags is not None:
                final_effective_tags.extend(parse_tags(host_tags["tags"]))
            ensure_tag_update_retains_scope(auth, final_effective_tags)
            cursor = conn.execute(
                "UPDATE hosts SET owner_name = ?, owner_email = ?, owner_slack = ?, "
                "renewal_method = ?, runbook_url = ?, scan_interval_hours = ?, "
                "threshold_days = ?, notes = ?"
                + (", tags = ?" if not named_cert else "")
                + " WHERE id = ?",
                (
                    ownership.owner_name,
                    ownership.owner_email,
                    ownership.owner_slack,
                    ownership.renewal_method,
                    ownership.runbook_url,
                    interval,
                    threshold,
                    resolved.notes,
                    *((normalized_tags,) if not named_cert else ()),
                    target.host_id,
                ),
            )
            if cursor.rowcount == 0:
                raise HostNotFoundError("host not found")
            if named_cert and not persist_certificate_tags(conn, named_cert, normalized_tags):
                raise HostNotFoundError("certificate not found")
            from cert_watch.config import current_settings

            received = datetime.now(UTC)
            derived_status, renewal_audit = write_through_renewal_status_on(
                conn,
                db_path,
                current_settings(db_path),
                target.host_id,
                ownership.renewal_status,
                seen_status=ownership.renewal_status_seen,
                require_seen_status=ownership.require_renewal_status_seen,
                auth=auth,
                actor=actor,
                source_ip=source_ip,
                now=received,
            )
            row = conn.execute(
                f"SELECT {host_projection_sql('h', '?')} FROM hosts h WHERE h.id = ?",
                (_sql_now(received), target.host_id),
            ).fetchone()
            assert row is not None
            updated = SqliteHostRepository(db_path)._row_to_host(row)
            assert updated.renewal_status == derived_status
            event = record_audit(
                db_path,
                actor=actor,
                action="host.edit",
                target_type="host",
                target_id=target.host_id,
                detail={
                    "owner_name": ownership.owner_name,
                    "owner_email": ownership.owner_email,
                    "owner_slack": ownership.owner_slack,
                    "renewal_method": ownership.renewal_method,
                    "runbook_url": ownership.runbook_url,
                    "scan_interval_hours": interval,
                    "threshold_days": threshold,
                    "renewal_status": ownership.renewal_status,
                    "notes_length": len(resolved.notes),
                    "tags": normalized_tags,
                    "tags_apply_to": "certificate" if named_cert else "host",
                },
                source_ip=source_ip,
                conn=conn,
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    export_audit(event)
    export_audit(renewal_audit)
    return HostEditResult(
        updated,
        tuple(parse_tags(normalized_tags)),
        "certificate" if named_cert else "host",
    )
