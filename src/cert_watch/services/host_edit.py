"""One atomic edit for every host field owned by the detail page."""

from __future__ import annotations

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
from cert_watch.database import HostEntry, SqliteHostRepository
from cert_watch.database.connection import _connect, begin_immediate, get_write_lock
from cert_watch.database.metadata_ops import (
    update_certificate_tags as persist_certificate_tags,
)
from cert_watch.email_validation import is_safe_email_address
from cert_watch.scan_freshness import scan_interval_out_of_range
from cert_watch.services.certificate_identity import (
    ensure_not_superseded,
    refuse_if_superseded,
)
from cert_watch.services.host_management import HostNotFoundError, HostValidationError
from cert_watch.services.host_ownership import (
    VALID_RENEWAL_METHODS,
    VALID_RENEWAL_STATUSES,
    HostOwnershipValidationError,
    resolve_host_ownership_target,
    runbook_url_error,
)
from cert_watch.services.resource_metadata import (
    MAX_NOTES_LENGTH,
    ResourceMetadataValidationError,
    normalize_tags,
)


@dataclass(frozen=True)
class HostEditUpdate:
    owner_name: Any = ""
    owner_email: Any = ""
    owner_slack: Any = ""
    renewal_method: Any = ""
    runbook_url: Any = ""
    scan_interval_hours: Any = None
    threshold_days: Any = None
    renewal_status: Any = "pending"
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


def _validate(update: HostEditUpdate, current: HostEntry) -> tuple[int | None, int | None, str]:
    for field in (
        "owner_name", "owner_email", "owner_slack", "renewal_method",
        "runbook_url", "renewal_status", "notes", "tags",
    ):
        if not isinstance(getattr(update, field), str):
            raise ResourceMetadataValidationError(f"{field} must be a string")
    if update.owner_email and not is_safe_email_address(update.owner_email):
        raise HostOwnershipValidationError(
            "owner_email", f"invalid email: {update.owner_email}"
        )
    if update.renewal_method not in VALID_RENEWAL_METHODS:
        raise HostOwnershipValidationError("renewal_method", "invalid renewal method")
    if update.renewal_status not in VALID_RENEWAL_STATUSES:
        raise HostValidationError("Choose a valid operator-reported renewal status.")
    url_error = runbook_url_error(update.runbook_url)
    if url_error:
        raise HostOwnershipValidationError("runbook_url", url_error)
    if len(update.notes) > MAX_NOTES_LENGTH:
        raise ResourceMetadataValidationError("notes too long (max 10000)")

    interval = _optional_positive_int(
        update.scan_interval_hours, field="Scan interval"
    )
    threshold = _optional_positive_int(update.threshold_days, field="Alert threshold")
    if interval != current.scan_interval_hours and scan_interval_out_of_range(interval):
        raise HostValidationError(
            "Scan interval must be between 1 and 8760 hours, or blank for daily."
        )
    if threshold is not None and not 1 <= threshold <= 2**63 - 1:
        raise HostValidationError(
            "Alert threshold must be a positive whole number within the stored range."
        )
    return interval, threshold, normalize_tags(update.tags)


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
        ensure_write_scope(auth, db_path, **target.scope_target())
        current = SqliteHostRepository(db_path).get(target.host_id)
        if current is None:
            raise HostNotFoundError("host not found")
        resolved = update() if callable(update) else update
        interval, threshold, normalized_tags = _validate(resolved, current)
        ensure_new_tags_in_scope(auth, normalized_tags)

        conn = _connect(db_path)
        try:
            begin_immediate(conn)
            if named_cert:
                ensure_not_superseded(conn, named_cert, auth=auth, hidden=hidden)
            ensure_write_scope_on(conn, auth, **target.scope_target())
            cursor = conn.execute(
                "UPDATE hosts SET owner_name = ?, owner_email = ?, owner_slack = ?, "
                "renewal_method = ?, runbook_url = ?, scan_interval_hours = ?, "
                "threshold_days = ?, renewal_status = ?, notes = ?"
                + (", tags = ?" if not named_cert else "")
                + " WHERE id = ?",
                (
                    resolved.owner_name.strip(), resolved.owner_email.strip(),
                    resolved.owner_slack.strip(), resolved.renewal_method,
                    resolved.runbook_url.strip(), interval, threshold,
                    resolved.renewal_status, resolved.notes,
                    *((normalized_tags,) if not named_cert else ()), target.host_id,
                ),
            )
            if cursor.rowcount == 0:
                raise HostNotFoundError("host not found")
            if named_cert and not persist_certificate_tags(conn, named_cert, normalized_tags):
                raise HostNotFoundError("certificate not found")
            row = conn.execute("SELECT * FROM hosts WHERE id = ?", (target.host_id,)).fetchone()
            assert row is not None
            updated = SqliteHostRepository(db_path)._row_to_host(row)
            event = record_audit(
                db_path,
                actor=actor,
                action="host.edit",
                target_type="host",
                target_id=target.host_id,
                detail={
                    "owner_name": resolved.owner_name.strip(),
                    "owner_email": resolved.owner_email.strip(),
                    "owner_slack": resolved.owner_slack.strip(),
                    "renewal_method": resolved.renewal_method,
                    "runbook_url": resolved.runbook_url.strip(),
                    "scan_interval_hours": interval,
                    "threshold_days": threshold,
                    "renewal_status": resolved.renewal_status,
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
    from cert_watch.tags import parse_tags

    return HostEditResult(
        updated,
        tuple(parse_tags(normalized_tags)),
        "certificate" if named_cert else "host",
    )
