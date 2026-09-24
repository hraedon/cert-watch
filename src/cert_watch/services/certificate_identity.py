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

An id is superseded only when a stored leaf names it in ``replaces_cert_id``
(its successor). Such an id is refused with
:class:`CertificateSupersededError`, carrying the successor's id, so the
client can re-read the current certificate and decide again. It is never
retargeted to the successor and never answered with success for a no-op.

An id with no successor row -- one that never existed, or that an operator
deleted -- is not "superseded": it falls through to the caller's ordinary
handling. So does a superseded id whose successor the caller's tag scope
does not cover: the refusal would reveal that the id was real and renewed,
so the caller gets exactly the answer an unknown id gets.
"""

from __future__ import annotations

import sqlite3
from typing import Any


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


def ensure_not_superseded(conn: sqlite3.Connection, cert_id: str, *, auth: Any) -> None:
    """Raise :class:`CertificateSupersededError` if *cert_id* was renewed away.

    *conn* must be the connection that performs the guarded write, inside a
    ``BEGIN IMMEDIATE`` transaction it has not yet committed. Only reads on
    *conn*; never commits.
    """
    if conn.execute("SELECT 1 FROM certificates WHERE id = ?", (cert_id,)).fetchone():
        return
    successor = conn.execute(
        "SELECT id FROM certificates WHERE replaces_cert_id = ? AND is_leaf = 1 "
        "ORDER BY created_at DESC, rowid DESC LIMIT 1",
        (cert_id,),
    ).fetchone()
    if successor is None:
        return
    if not _may_read(conn, auth, str(successor["id"])):
        return
    raise CertificateSupersededError(cert_id, str(successor["id"]))



def refuse_if_superseded(db_path: Any, cert_id: str, *, auth: Any) -> None:
    """Early, advisory form of :func:`ensure_not_superseded`, before a
    service's scope checks, so a renewed-away id is answered as such rather
    than as an out-of-scope target. Not a guarantee: the service repeats the
    check inside the write transaction."""
    from cert_watch.database.connection import _connect

    ensure_not_superseded(_connect(db_path), cert_id, auth=auth)
