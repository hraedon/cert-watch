"""Mutations addressed by a certificate id that a renewal has replaced (#115).

A renewal gives the endpoint's certificate a new id. A request prepared
against the old id -- a form left open, an API call queued behind the scan
that renewed it -- can no longer mean what its sender saw, and the old row is
gone, so applying it would either silently do nothing (an unassign that
removes no row but answers "unassigned") or act on a certificate the sender
never looked at (a delete that follows the id to its successor).

The rule for every certificate-id-addressed mutation: call
:func:`ensure_not_superseded` on the connection that performs the write,
after ``BEGIN IMMEDIATE`` and before the write, and commit both together.
``BEGIN IMMEDIATE`` takes SQLite's write lock, so no other connection -- in
this process or another -- can renew the certificate between the check and
the write (the scan's replace also runs under ``BEGIN IMMEDIATE``).

Whether the write may go ahead is decided from certificate rows alone
(:func:`cert_watch.database.cert_lineage.row_lineage`); lifecycle events
never authorize or refuse a write:

* the addressed row exists and nothing replaces it: go ahead;
* exactly one unambiguous, loop-free chain of rows on the same endpoint
  leads from it to a current certificate (the head): refuse with
  :class:`CertificateSupersededError` naming the head -- or with the route's
  unknown-id answer (*hidden*) when the caller can't see the addressed row or
  the head. A stale row can coexist with its successor; acting on it would
  bypass the current certificate's scope;
* rows replace it but the chain is ambiguous, loops or changes endpoint:
  refuse with the unknown-id answer. Never go ahead;
* no row has the id: nothing can be written, and the route's ordinary
  unknown-id handling applies. Only the *answer* may differ: when
  :func:`~cert_watch.database.cert_lineage.navigation_hint` (the same resolver
  the stale-link page uses) finds the certificate that replaced it and the
  caller may see it, the refusal names it instead of saying "not found".

The id is never retargeted to the head, and a no-op is never reported as a
success.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from typing import Any


class CertificateNotFoundError(LookupError):
    """The route's unknown-id answer, where the route supplies none of its own."""


class CertificateSupersededError(LookupError):
    """The id named a certificate that has since been replaced by a renewal."""

    def __init__(self, cert_id: str, current_id: str) -> None:
        super().__init__("certificate superseded by a renewal; nothing was changed")
        self.cert_id = cert_id
        self.current_id = current_id


def _may_read(conn: sqlite3.Connection, auth: Any, cert_id: str) -> bool:
    """Tag-scope read check computed on *conn*, inside the caller's
    transaction (the repository helpers would commit it)."""
    if auth is None or getattr(auth, "is_admin", False) or getattr(auth, "is_system", False):
        return True
    scope_tag = getattr(auth, "scope_tag", "") or ""
    if not scope_tag:
        return True
    from cert_watch.tags import merge_tags, parse_tags

    row = conn.execute(
        "SELECT c.tags AS cert_tags, h.tags AS host_tags FROM certificates c "
        "LEFT JOIN hosts h ON h.hostname = c.hostname AND h.port = c.port "
        "WHERE c.id = ?",
        (cert_id,),
    ).fetchone()
    if row is None:
        return False
    effective = {t.casefold() for t in merge_tags(row["cert_tags"], row["host_tags"])}
    return bool({t.casefold() for t in parse_tags(scope_tag)} & effective)


def ensure_not_superseded(
    conn: sqlite3.Connection,
    cert_id: str,
    *,
    auth: Any,
    hidden: Callable[[], Exception] | None = None,
    answer_missing: bool = True,
) -> None:
    """Refuse a write addressed to a renewed-away (or invalid-lineage) id.

    For a missing id nothing is decided here: with *answer_missing* (the
    default) the refusal names the certificate that replaced it, which only
    shapes the answer of a write that would change nothing anyway. A route
    whose write still does something for a missing id (unassign removing a
    dangling assignment) passes ``answer_missing=False`` and annotates its
    own response with :func:`replacement_hint` -- events never gate a write.

    *conn* must be the connection that performs the guarded write, inside a
    ``BEGIN IMMEDIATE`` transaction it has not yet committed. Only reads on
    *conn*; never commits. ``hidden()`` is the route's unknown-id error; it
    defaults to :class:`CertificateNotFoundError`.
    """
    from cert_watch.database.cert_lineage import navigation_hint, row_lineage

    unknown = hidden or (lambda: CertificateNotFoundError("certificate not found"))
    lineage = row_lineage(conn, cert_id)
    if lineage.kind == "current":
        return
    if lineage.kind == "invalid":
        raise unknown()
    if lineage.kind == "superseded":
        assert lineage.head is not None
        if _may_read(conn, auth, cert_id) and _may_read(conn, auth, lineage.head):
            raise CertificateSupersededError(cert_id, lineage.head)
        raise unknown()
    # Missing: the write goes on to the route's ordinary handling; only the
    # answer may name the certificate that replaced it.
    if not answer_missing:
        return
    head = navigation_hint(conn, cert_id)
    if head is not None and _may_read(conn, auth, head):
        raise CertificateSupersededError(cert_id, head)


def replacement_hint(conn: sqlite3.Connection, cert_id: str, *, auth: Any) -> str | None:
    """The current certificate a missing *cert_id* was renewed to, when the
    navigation hint resolves and *auth* may see it -- for annotating a
    response only."""
    from cert_watch.database.cert_lineage import navigation_hint

    head = navigation_hint(conn, cert_id)
    return head if head is not None and _may_read(conn, auth, head) else None


def refuse_if_superseded(
    db_path: Any,
    cert_id: str,
    *,
    auth: Any,
    hidden: Callable[[], Exception] | None = None,
) -> None:
    """Early, advisory form of :func:`ensure_not_superseded`, before a
    service's scope checks, so a renewed-away id is answered as such rather
    than as an out-of-scope target. Not a guarantee: the service repeats the
    check inside the write transaction."""
    from cert_watch.database.connection import _connect

    ensure_not_superseded(_connect(db_path), cert_id, auth=auth, hidden=hidden)
