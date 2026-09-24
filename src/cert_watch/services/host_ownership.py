"""Host ownership application service.

Both the server-rendered form and JSON API use this service so authorization
(tag scope), validation, persistence, and audit behavior cannot drift between
route adapters. Scope is checked inside the write lock, before validation.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from cert_watch.audit import export_audit, record_audit
from cert_watch.auth.scope import (
    ScopeDeniedError,
    ensure_write_scope,
    require_auth_context,
    write_scope_error,
)
from cert_watch.database.connection import _connect, begin_immediate, get_write_lock
from cert_watch.database.host_ops import (
    resolve_host_target,
)
from cert_watch.database.host_ops import (
    update_host_ownership as persist_host_ownership,
)
from cert_watch.email_validation import is_safe_email_address
from cert_watch.services.certificate_identity import (
    ensure_not_superseded,
    refuse_if_superseded,
)

VALID_RENEWAL_METHODS = frozenset({"", "acme", "cert-manager", "manual"})
VALID_RENEWAL_STATUSES = frozenset({"pending", "in_progress", "renewed"})


@dataclass(frozen=True)
class HostOwnershipUpdate:
    """A partial host ownership update; ``None`` leaves a field unchanged."""

    owner_name: str | None = None
    owner_email: str | None = None
    owner_slack: str | None = None
    renewal_status: str | None = None
    renewal_method: str | None = None
    runbook_url: str | None = None


@dataclass(frozen=True)
class HostOwnership:
    host_id: str
    owner_name: str
    owner_email: str
    owner_slack: str
    renewal_status: str
    renewal_method: str
    runbook_url: str
    notes: str


@dataclass(frozen=True)
class HostOwnershipTarget:
    host_id: str
    source: str  # "host" or "certificate": what resource_id named
    resource_id: str = ""

    def scope_target(self) -> dict[str, str]:
        """What tag scope is judged against: the host, or -- when the route
        named a certificate -- that certificate's effective (cert ∪ host) tags."""
        if self.source == "host" or not self.resource_id:
            return {"host_id": self.host_id}
        return {"cert_id": self.resource_id}


class HostOwnershipValidationError(ValueError):
    """The requested ownership update is invalid."""

    def __init__(self, field: str, message: str) -> None:
        super().__init__(message)
        self.field = field


class HostNotFoundError(LookupError):
    """The ownership target does not exist."""


class HostOwnershipTargetError(LookupError):
    """A host or certificate id cannot resolve to an ownership target."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason.replace("_", " "))
        self.reason = reason


def runbook_url_error(url: str) -> str | None:
    """Return an error when a stored runbook link has an unsafe scheme."""
    if not url.strip():
        return None
    if urlparse(url.strip()).scheme.lower() not in ("http", "https"):
        return "runbook_url must be an http(s) URL"
    return None


def _validate(update: HostOwnershipUpdate) -> None:
    for field_name in ("owner_name", "owner_email", "owner_slack"):
        value = getattr(update, field_name)
        if value is not None and not isinstance(value, str):
            raise HostOwnershipValidationError(field_name, f"{field_name} must be a string")

    if update.owner_email and not is_safe_email_address(update.owner_email):
        raise HostOwnershipValidationError(
            "owner_email", f"invalid email: {update.owner_email}"
        )
    if update.renewal_status is not None:
        if not isinstance(update.renewal_status, str):
            raise HostOwnershipValidationError(
                "renewal_status", "renewal_status must be a string"
            )
        if update.renewal_status not in VALID_RENEWAL_STATUSES:
            raise HostOwnershipValidationError(
                "renewal_status",
                f"renewal_status must be one of {set(VALID_RENEWAL_STATUSES)}"
            )
    if update.renewal_method is not None:
        if not isinstance(update.renewal_method, str):
            raise HostOwnershipValidationError(
                "renewal_method", "renewal_method must be a string"
            )
        if update.renewal_method not in VALID_RENEWAL_METHODS:
            raise HostOwnershipValidationError(
                "renewal_method",
                f"renewal_method must be one of {set(VALID_RENEWAL_METHODS)}"
            )
    if update.runbook_url is not None:
        if not isinstance(update.runbook_url, str):
            raise HostOwnershipValidationError(
                "runbook_url", "runbook_url must be a string"
            )
        error = runbook_url_error(update.runbook_url)
        if error:
            raise HostOwnershipValidationError("runbook_url", error)


def _unknown_answer(auth: Any, db_path: str | Path) -> Callable[[], Exception]:
    """What an id that names no host or certificate gets from this caller:
    the scope refusal for a scoped caller (authorization comes before the
    lookup), else the lookup failure. Only scoped callers can be denied the
    current certificate, so in practice this is the scope refusal."""

    def answer() -> Exception:
        error = write_scope_error(auth, db_path)
        return ScopeDeniedError(error) if error else HostOwnershipTargetError("resource_not_found")

    return answer


def resolve_host_ownership_target(
    db_path: str | Path, resource_id: str, *, auth: Any
) -> HostOwnershipTarget:
    """Resolve the legacy certificate-or-host route id to one host target.

    *auth* is the acting AuthContext. When nothing resolves, the caller's
    scope is judged first, so a scoped caller gets the same refusal for an
    id that does not exist as for another team's (#112 review); an unscoped
    caller gets the lookup failure. A certificate that exists but has no
    host is judged by its own effective tags, as ``update_host_ownership``
    would judge it.

    An id that names a certificate a renewal has replaced -- gone, or a
    stale row still coexisting with its successor -- raises
    :class:`CertificateSupersededError` naming the current certificate when
    *auth* may see both it and the addressed row; otherwise it gets exactly
    the unknown-id answer. The authoritative check is repeated inside the
    write transaction by :func:`update_host_ownership`.
    """
    require_auth_context(auth)
    lookup = resolve_host_target(_connect(db_path), resource_id)
    if lookup.status != "host":
        # A renewed-away certificate id -- gone, or a stale row still
        # coexisting with its successor -- is refused, or answered as unknown
        # when the caller can't see it or the current certificate.
        refuse_if_superseded(
            db_path, resource_id, auth=auth, hidden=_unknown_answer(auth, db_path)
        )
    if lookup.host is None:
        ensure_write_scope(auth, db_path, cert_id=resource_id)
        raise HostOwnershipTargetError(lookup.status)
    return HostOwnershipTarget(
        host_id=lookup.host.id, source=lookup.status, resource_id=resource_id,
    )


def update_host_ownership(
    db_path: str | Path,
    target: str | HostOwnershipTarget,
    update: HostOwnershipUpdate | Callable[[], HostOwnershipUpdate],
    *,
    auth: Any,
    actor: str,
    source_ip: str | None,
) -> HostOwnership:
    """Authorize, validate, persist, and audit one host ownership update atomically.

    *target* is a host id, or a resolved :class:`HostOwnershipTarget` (whose
    scope may be judged through the certificate the route named). *update*
    may be a callable -- e.g. a JSON body parser raising
    :class:`HostOwnershipValidationError` -- run after the scope check.
    *auth* is the required acting AuthContext; internal callers use the
    explicit system principal when unrestricted access is intended.
    """
    require_auth_context(auth)
    if isinstance(target, str):
        target = HostOwnershipTarget(host_id=target, source="host", resource_id=target)
    host_id = target.host_id
    named_cert = target.resource_id if target.source == "certificate" else ""
    with get_write_lock():
        if named_cert:
            refuse_if_superseded(
                db_path, named_cert, auth=auth, hidden=_unknown_answer(auth, db_path)
            )
        ensure_write_scope(auth, db_path, **target.scope_target())
        if callable(update):
            update = update()
        _validate(update)
        detail = asdict(update)
        conn = _connect(db_path)
        try:
            begin_immediate(conn)
            if named_cert:
                # The route named a certificate: if a renewal replaced it since
                # the target was resolved -- in this process or another --
                # refuse rather than act on a stale id. Checked inside the
                # write transaction, so it still holds when the write commits.
                ensure_not_superseded(
                    conn, named_cert, auth=auth, hidden=_unknown_answer(auth, db_path)
                )
            updated = persist_host_ownership(conn, host_id, **detail)
            if updated is None:
                raise HostNotFoundError("host not found")
            audit_event = record_audit(
                db_path,
                actor=actor,
                action="owner.update",
                target_type="host",
                target_id=host_id,
                detail=detail,
                source_ip=source_ip,
                conn=conn,
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    export_audit(audit_event)

    return HostOwnership(
        host_id=host_id,
        owner_name=updated.owner_name,
        owner_email=updated.owner_email,
        owner_slack=updated.owner_slack,
        renewal_status=updated.renewal_status,
        renewal_method=updated.renewal_method,
        runbook_url=updated.runbook_url,
        notes=updated.notes,
    )
