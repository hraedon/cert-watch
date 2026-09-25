"""Tag-scope authorization decisions (WI-051 / WI-052 / Plan 053).

The predicates take the acting :class:`~cert_watch.auth.rbac.AuthContext`
rather than a request, so application services can enforce them inside their
write transaction. Service entry points require a context; trusted internal
and auth-disabled callers use :meth:`AuthContext.system` explicitly.
``routes/_scoped.py`` wraps them for request-level callers.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cert_watch.auth.rbac import AuthContext


class MissingAuthContextError(RuntimeError):
    """A service mutation was attempted without an explicit principal."""


def require_auth_context(auth_ctx: Any) -> AuthContext:
    """Fail closed unless a service caller supplies a real acting principal."""
    if not isinstance(auth_ctx, AuthContext):
        raise MissingAuthContextError("auth context is required")
    return auth_ctx


def _folded(tags: Any) -> set[str]:
    """Casefold a tag collection: scope matching is case-insensitive (#69),
    as in ``tags_match`` and the SQL-side effective-tag filter."""
    return {t.casefold() for t in tags}


def _effective_tags(
    db_path: str | Path,
    *,
    cert_id: str | None = None,
    host_id: str | None = None,
) -> set[str]:
    """Return the effective (cert ∪ host) tag set for a target, if it exists."""
    from cert_watch.database import SqliteCertificateRepository
    from cert_watch.tags import parse_tags

    tags: set[str] = set()
    if cert_id:
        cert_repo = SqliteCertificateRepository(db_path)
        cert = cert_repo.get_by_id(cert_id)
        if cert is not None:
            tags.update(cert_repo.effective_tags(cert_id))
            return tags
    if host_id:
        from cert_watch.database import SqliteHostRepository

        host_repo = SqliteHostRepository(db_path)
        host = host_repo.get(host_id)
        if host is not None:
            tags.update(parse_tags(host.tags))
        return tags
    return tags


def write_scope_error(
    auth_ctx: Any,
    db_path: str | Path,
    *,
    cert_id: str | None = None,
    host_id: str | None = None,
) -> str | None:
    """Return an error message if *auth_ctx* may not mutate the target.

    Admins, unscoped users and the low-level request helper's missing-context
    case pass. Targets whose effective tags do not include any of the user's
    scope tags are denied. Services first reject missing contexts, then call
    this inside their write transaction; :func:`scope_write_denied` is the
    request-level wrapper.
    """
    if auth_ctx is None or getattr(auth_ctx, "is_admin", False):
        return None
    scope_tag = getattr(auth_ctx, "scope_tag", "") or ""
    if not scope_tag:
        return None
    from cert_watch.tags import parse_tags

    scope_tags = _folded(parse_tags(scope_tag))
    target_tags = _effective_tags(db_path, cert_id=cert_id, host_id=host_id)
    if not scope_tags & _folded(target_tags):
        return "operation not permitted outside your team scope"
    # Plan 053 (WI-064): visibility is necessary but no longer sufficient —
    # the write tier must also cover the target's tags. may_write_tags is
    # True for global writers and for any intersecting per-tag operator.
    may_write_tags = getattr(auth_ctx, "may_write_tags", None)
    if callable(may_write_tags) and not may_write_tags(target_tags):
        return "your access to this resource's tags is read-only"
    return None


def new_tags_scope_error(auth_ctx: Any, new_tags: str) -> str | None:
    """Return an error message if *new_tags* are not all within *auth_ctx*'s scope.

    For scoped users, every submitted tag must be in their scope set.
    Admins, unscoped users and the low-level request helper's missing-context
    case can set any tags. Services reject a missing context before this check.
    """
    if auth_ctx is None or getattr(auth_ctx, "is_admin", False):
        return None
    scope_tag = getattr(auth_ctx, "scope_tag", "") or ""
    if not scope_tag:
        return None
    from cert_watch.tags import parse_tags

    scope_tags = _folded(parse_tags(scope_tag))
    for tag in parse_tags(new_tags):
        if tag.casefold() not in scope_tags:
            return f"tag '{tag}' is outside your team scope"
    return None


class ScopeDeniedError(PermissionError):
    """The acting user's tag scope does not cover this write. ``str(exc)``
    is the user-facing message the route adapters have always shown."""


def unknown_target_scope_error(auth_ctx: Any, db_path: str | Path) -> Exception:
    """What a certificate id that doesn't exist gets from this caller -- used
    where an id must be answered exactly like an unknown one: the scope
    refusal for a scoped caller, else ``CertificateNotFoundError``."""
    from cert_watch.services.certificate_identity import CertificateNotFoundError

    message = write_scope_error(auth_ctx, db_path)
    if message:
        return ScopeDeniedError(message)
    return CertificateNotFoundError("certificate not found")


def _effective_tags_on(
    conn: Any, *, cert_id: str | None = None, host_id: str | None = None
) -> set[str]:
    """:func:`_effective_tags` read on *conn*, inside the caller's write
    transaction (the repository helpers use their own and would commit it)."""
    from cert_watch.tags import merge_tags, parse_tags

    if cert_id:
        row = conn.execute(
            "SELECT c.tags AS cert_tags, h.tags AS host_tags FROM certificates c "
            "LEFT JOIN hosts h ON h.hostname = c.hostname AND h.port = c.port "
            "WHERE c.id = ?",
            (cert_id,),
        ).fetchone()
        if row is not None:
            return set(merge_tags(row["cert_tags"], row["host_tags"]))
    if host_id:
        row = conn.execute("SELECT tags FROM hosts WHERE id = ?", (host_id,)).fetchone()
        if row is not None:
            return set(parse_tags(row["tags"]))
    return set()


def ensure_write_scope_on(
    conn: Any,
    auth_ctx: Any,
    *,
    cert_id: str | None = None,
    host_id: str | None = None,
) -> None:
    """The authoritative scope check: :func:`ensure_write_scope` evaluated on
    *conn* after ``BEGIN IMMEDIATE``, immediately before the write, so a
    concurrent change of the target's tags (a host moved to another team)
    can't land between the check and the write (#115 review round 10). The
    earlier :func:`ensure_write_scope` stays for response ordering."""
    require_auth_context(auth_ctx)
    if getattr(auth_ctx, "is_admin", False):
        return
    scope_tag = getattr(auth_ctx, "scope_tag", "") or ""
    if not scope_tag:
        return
    from cert_watch.tags import parse_tags

    target_tags = _effective_tags_on(conn, cert_id=cert_id, host_id=host_id)
    if not _folded(parse_tags(scope_tag)) & _folded(target_tags):
        raise ScopeDeniedError("operation not permitted outside your team scope")
    may_write_tags = getattr(auth_ctx, "may_write_tags", None)
    if callable(may_write_tags) and not may_write_tags(target_tags):
        raise ScopeDeniedError("your access to this resource's tags is read-only")


def ensure_write_scope(
    auth_ctx: Any,
    db_path: str | Path,
    *,
    cert_id: str | None = None,
    host_id: str | None = None,
) -> None:
    """Raise :class:`ScopeDeniedError` unless *auth_ctx* may mutate the target."""
    require_auth_context(auth_ctx)
    error = write_scope_error(auth_ctx, db_path, cert_id=cert_id, host_id=host_id)
    if error:
        raise ScopeDeniedError(error)


def ensure_new_tags_in_scope(auth_ctx: Any, new_tags: str) -> None:
    """Raise :class:`ScopeDeniedError` unless every tag is within scope."""
    require_auth_context(auth_ctx)
    error = new_tags_scope_error(auth_ctx, new_tags)
    if error:
        raise ScopeDeniedError(error)
