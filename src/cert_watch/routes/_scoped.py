"""Helpers for tag-scoped access control (WI-051 / WI-052)."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import quote

from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse

from cert_watch.auth.scope import (
    _effective_tags,
    _folded,
    new_tags_scope_error,
    write_scope_error,
)
from cert_watch.services.certificate_identity import CertificateSupersededError


def scope_tags_from_auth(auth_ctx: Any) -> tuple[str, ...]:
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


def scope_write_denied(
    request: Request,
    db_path: str | Path,
    *,
    cert_id: str | None = None,
    host_id: str | None = None,
) -> str | None:
    """:func:`write_scope_error` for the request's AuthContext."""
    return write_scope_error(
        getattr(request.state, "auth_context", None),
        db_path, cert_id=cert_id, host_id=host_id,
    )


def scope_read_denied(
    request: Request,
    db_path: str | Path,
    *,
    cert_id: str | None = None,
    host_id: str | None = None,
) -> str | None:
    """Return an error message if a scoped user can't read the target.

    Analogous to :func:`scope_write_denied` but for read access.  Admins and
    unscoped users pass.  Targets whose effective tags do not include any of
    the user's scope tags are denied.
    """
    auth_ctx = getattr(request.state, "auth_context", None)
    if auth_ctx is None or getattr(auth_ctx, "is_admin", False):
        return None
    scope_tag = getattr(auth_ctx, "scope_tag", "") or ""
    if not scope_tag:
        return None
    from cert_watch.tags import parse_tags

    scope_tags = _folded(parse_tags(scope_tag))
    target_tags = _effective_tags(db_path, cert_id=cert_id, host_id=host_id)
    if scope_tags & _folded(target_tags):
        return None
    return "resource not in your team scope"


def enforce_scope_tag(
    request: Request,
    user_tag: str,
) -> str | None:
    """Validate that a requested *user_tag* filter is within the caller's scope.

    For scoped users, a non-empty tag must match one of their scope tags.
    An empty tag is allowed: the caller then scopes the result to the user's
    visibility (``scope_tags_from_auth``) in the query itself (#112), which is
    what makes this check a narrowing filter rather than the only guard.
    Admins and unscoped users can pass any tag. Returns an error message if
    the tag is not allowed, or None if it is.
    """
    from cert_watch.tags import parse_tags

    # One tag per report, for everyone. The report filters on the whole value
    # as one tag, so a list such as ``payments,hr-ops`` used to pass this check
    # on the overlapping part and then produce a signed, empty report named
    # for the other team's tag (#116 review).
    if len(parse_tags(user_tag)) > 1:
        return "requested tag must be a single tag"
    auth_ctx = getattr(request.state, "auth_context", None)
    if auth_ctx is None or getattr(auth_ctx, "is_admin", False):
        return None
    scope_tag = getattr(auth_ctx, "scope_tag", "") or ""
    if not scope_tag:
        return None
    scope_tags = _folded(parse_tags(scope_tag))
    if not user_tag:
        return None
    if not scope_tags & _folded(parse_tags(user_tag)):
        return "requested tag is outside your team scope"
    return None


def scope_new_tags_denied(
    request: Request,
    new_tags: str,
) -> str | None:
    """:func:`new_tags_scope_error` for the request's AuthContext."""
    return new_tags_scope_error(getattr(request.state, "auth_context", None), new_tags)


def superseded_json(exc: CertificateSupersededError) -> JSONResponse:
    """409 naming the current certificate for a mutation on a renewed-away id
    (:mod:`cert_watch.services.certificate_identity`)."""
    return JSONResponse(
        status_code=409,
        content={
            "error": "certificate superseded by a renewal; nothing was changed",
            "cert_id": exc.cert_id,
            "current_cert_id": exc.current_id,
        },
    )


def superseded_redirect(exc: CertificateSupersededError) -> RedirectResponse:
    """The HTML-form counterpart of :func:`superseded_json`: back to the
    current certificate with a note."""
    message = (
        "This certificate was renewed before your change was saved, so nothing "
        "was changed. This is the current certificate; make the change again here."
    )
    return RedirectResponse(
        url=f"/certificates/{exc.current_id}?error={quote(message)}", status_code=303
    )
