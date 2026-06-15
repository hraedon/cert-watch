"""Helpers for tag-scoped access control (WI-051 / WI-052)."""

from __future__ import annotations

from pathlib import Path

from fastapi import Request


def scope_tags_from_auth(auth_ctx) -> tuple[str, ...]:
    """Return the active scope tags for tag-scoped access control (WI-051).

    Admins and unscoped users get an empty tuple (see everything). Scoped
    non-admin users get their scope tag(s) as a tuple.
    """
    if auth_ctx is None:
        return ()
    if getattr(auth_ctx, "is_admin", False):
        return ()
    scope_tag = getattr(auth_ctx, "scope_tag", "") or ""
    if not scope_tag:
        return ()
    from cert_watch.tags import parse_tags

    return tuple(parse_tags(scope_tag))


def tags_with_scope(request: Request, tags: str) -> str:
    """Merge the authenticated user's scope tag into *tags* (WI-052)."""
    auth_ctx = getattr(request.state, "auth_context", None)
    scope = (getattr(auth_ctx, "scope_tag", "") or "") if auth_ctx else ""
    if not scope:
        return tags
    from cert_watch.tags import format_tags, merge_tags

    return format_tags(merge_tags(tags, scope))


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


def scope_write_denied(
    request: Request,
    db_path: str | Path,
    *,
    cert_id: str | None = None,
    host_id: str | None = None,
) -> str | None:
    """Return an error message if a scoped user can't mutate the target.

    Admins and users without a scope tag pass. Targets whose effective tags
    do not include any of the user's scope tags are denied.
    """
    auth_ctx = getattr(request.state, "auth_context", None)
    if auth_ctx is None or getattr(auth_ctx, "is_admin", False):
        return None
    scope_tag = getattr(auth_ctx, "scope_tag", "") or ""
    if not scope_tag:
        return None
    from cert_watch.tags import parse_tags

    scope_tags = parse_tags(scope_tag)
    target_tags = _effective_tags(db_path, cert_id=cert_id, host_id=host_id)
    if any(t in target_tags for t in scope_tags):
        return None
    return "operation not permitted outside your team scope"
