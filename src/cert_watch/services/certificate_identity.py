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

An id is superseded when renewal lineage leads from it to a current
certificate: a leaf that names it in ``replaces_cert_id``, or -- once that
row is gone too -- the ``cert_renewed`` event that recorded the renewal,
followed hop by hop to a row that still exists and that nothing replaces
(the head). This is checked before asking whether the addressed row still
exists: a stale row can coexist with its successor, and acting on it would
bypass the current certificate's scope. Such an id is refused with
:class:`CertificateSupersededError`, carrying the head's id, so the client
can re-read the current certificate and decide again. It is never
retargeted to the head and never answered with success for a no-op.

Only renewal lineage counts. An id that never existed, or whose certificate
an operator deleted (its endpoint's next certificate is a ``cert_added``, not
a renewal of it), is not superseded and gets the caller's ordinary handling.

A caller whose tag scope does not cover the head -- or the addressed row,
while it still exists -- gets exactly the answer an unknown id gets on that
route: the refusal would otherwise reveal that the id
was real and renewed. For an addressed row that no longer exists, falling
through gives that answer; for a stale row that still exists, the caller
supplies it (*hidden*), because falling through would act on the stale row.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
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


def _endpoint(hostname: Any, port: Any) -> tuple[str, int] | None:
    """A canonical ``(hostname, port)``, or ``None`` when either is missing."""
    import contextlib

    from cert_watch.host_validation import canonical_hostname

    if not hostname or port is None:
        return None
    name = str(hostname)
    with contextlib.suppress(ValueError):
        name = canonical_hostname(name)
    try:
        return name, int(port)
    except (TypeError, ValueError):
        return None


def _row_endpoint(conn: sqlite3.Connection, cert_id: str) -> tuple[str, int] | None:
    row = conn.execute(
        "SELECT hostname, port FROM certificates WHERE id = ?", (cert_id,)
    ).fetchone()
    return _endpoint(row["hostname"], row["port"]) if row is not None else None


# Renewal events for one replaced id. A payload that isn't valid JSON is
# skipped (json_extract on it would raise and fail every mutation), via CASE
# so the guard can't be reordered after the extraction.
_RENEWAL_EVENTS = (
    "SELECT CASE WHEN json_valid(payload) THEN json_extract(payload, '$.cert_id') END"
    " AS cert_id,"
    " CASE WHEN json_valid(payload) THEN json_extract(payload, '$.hostname') END AS hostname,"
    " CASE WHEN json_valid(payload) THEN json_extract(payload, '$.port') END AS port"
    " FROM event_log WHERE event_type = 'cert_renewed'"
    " AND CASE WHEN json_valid(payload)"
    " THEN json_extract(payload, '$.replaced_cert_id') END = ?"
)


def current_head(conn: sqlite3.Connection, cert_id: str) -> str | None:
    """The current certificate renewal lineage leads to from *cert_id*, or
    ``None``. Reads only on *conn*.

    Every hop is bound to one endpoint: the addressed certificate's
    ``(hostname, port)`` when its row still exists, else the first hop's.
    A successor row or ``cert_renewed`` event at another endpoint, a hop
    without an endpoint, more than one candidate successor, a lineage that
    loops, or one that dead-ends in a deleted row all fail closed: ``None``,
    so the id is treated as not superseded (never redirected elsewhere).
    """
    endpoint = _row_endpoint(conn, cert_id) if _exists(conn, cert_id) else None
    seen = {cert_id}
    current = cert_id
    while True:
        rows = conn.execute(
            "SELECT id, hostname, port FROM certificates "
            "WHERE replaces_cert_id = ? AND id != ? AND is_leaf = 1",
            (current, current),
        ).fetchall()
        if len(rows) > 1:
            return None
        if rows:
            successor = str(rows[0]["id"])
            hop_endpoint = _endpoint(rows[0]["hostname"], rows[0]["port"])
        else:
            events = conn.execute(_RENEWAL_EVENTS, (current,)).fetchall()
            candidates = {
                (str(e["cert_id"]), _endpoint(e["hostname"], e["port"]))
                for e in events
                if e["cert_id"]
            }
            if not candidates:
                break
            if len(candidates) > 1:
                return None
            ((successor, hop_endpoint),) = candidates
            if _exists(conn, successor) and _row_endpoint(conn, successor) != hop_endpoint:
                return None
        if hop_endpoint is None:
            return None
        if endpoint is None:
            endpoint = hop_endpoint
        elif hop_endpoint != endpoint:
            return None
        if successor in seen:
            return None
        seen.add(successor)
        current = successor
    if current == cert_id or not _exists(conn, current):
        return None
    return current


def _exists(conn: sqlite3.Connection, cert_id: str) -> bool:
    row = conn.execute("SELECT 1 FROM certificates WHERE id = ?", (cert_id,)).fetchone()
    return row is not None


def ensure_not_superseded(
    conn: sqlite3.Connection,
    cert_id: str,
    *,
    auth: Any,
    hidden: Callable[[], Exception] | None = None,
) -> None:
    """Raise :class:`CertificateSupersededError` if *cert_id* was renewed away.

    *conn* must be the connection that performs the guarded write, inside a
    ``BEGIN IMMEDIATE`` transaction it has not yet committed. Only reads on
    *conn*; never commits. When the caller may not see the current
    certificate, raises ``hidden()`` -- the route's unknown-id error -- if
    given, else returns (for an addressed row that no longer exists that is
    already the unknown-id path).
    """
    head = current_head(conn, cert_id)
    if head is None:
        return
    # Out of scope for the addressed row (when it still exists) or for the
    # head: the unknown-id answer -- authorization comes before any lookup
    # a caller could learn from (#112).
    addressed_exists = conn.execute(
        "SELECT 1 FROM certificates WHERE id = ?", (cert_id,)
    ).fetchone()
    if (addressed_exists and not _may_read(conn, auth, cert_id)) or not _may_read(
        conn, auth, head
    ):
        if hidden is not None:
            raise hidden()
        return
    raise CertificateSupersededError(cert_id, head)


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
