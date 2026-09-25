"""Renewal lineage of a certificate id (#115).

Two questions, answered separately on purpose:

* :func:`row_lineage` -- *may a write addressed to this id go ahead?* It uses
  stored certificate rows only (``replaces_cert_id`` among existing rows).
  Events never authorize or refuse a write.
* :func:`navigation_hint` -- *where should a person holding this missing id
  be sent?* It reads the renewal record (``certificate_lineage``, migration
  0042) and certificate rows -- never the event log -- and it never changes
  whether a write happens.
  Both the stale-link page redirect and the mutation routes' "renewed,
  nothing was changed" answer use it, so they cannot disagree.

Trust boundary: ``certificates`` and ``certificate_lineage`` are written only
by the application (the renewal record by the scan, in the same transaction
as the new certificate). The checks here defend against records that are
stale, duplicated, contradictory or looping -- a leftover duplicate row, a
deleted head, an ambiguous chain. Forging mutually consistent records needs
direct write access to the database, which is trusted and out of scope.
"""

from __future__ import annotations

import contextlib
import sqlite3
from dataclasses import dataclass
from typing import Any, Literal

Endpoint = tuple[str, int]


@dataclass(frozen=True)
class Lineage:
    """What row lineage says about an id.

    ``missing``: no row has this id (nothing to authorize; the route's
    ordinary unknown-id handling applies). ``current``: the row exists and no
    row replaces it. ``superseded``: exactly one unambiguous, loop-free chain
    of rows on the same endpoint leads from it to ``head``. ``invalid``:
    rows replace it, but the chain is ambiguous, loops, changes endpoint or
    has no endpoint -- a write must be refused, never allowed.
    """

    kind: Literal["missing", "current", "superseded", "invalid"]
    head: str | None = None


def strict_port(value: Any) -> int | None:
    """A port from a stored value: an int (not a bool) or an all-digit
    string. Anything else -- floats, bools, signs, blanks -- is invalid."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        port = value
    elif isinstance(value, str) and value.isascii() and value.isdigit():
        port = int(value)
    else:
        return None
    return port if 0 < port < 65536 else None


def endpoint_of(hostname: Any, port: Any) -> Endpoint | None:
    """A canonical ``(hostname, port)``, or ``None`` if either is unusable."""
    from cert_watch.host_validation import canonical_hostname

    parsed_port = strict_port(port)
    if not hostname or not isinstance(hostname, str) or parsed_port is None:
        return None
    name = hostname
    with contextlib.suppress(ValueError):
        name = canonical_hostname(name)
    return name, parsed_port


def _row(conn: sqlite3.Connection, cert_id: str) -> sqlite3.Row | None:
    row: sqlite3.Row | None = conn.execute(
        "SELECT id, hostname, port FROM certificates WHERE id = ?", (cert_id,)
    ).fetchone()
    return row


def _successor_rows(conn: sqlite3.Connection, cert_id: str) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT id, hostname, port FROM certificates "
        "WHERE replaces_cert_id = ? AND id != ? AND is_leaf = 1",
        (cert_id, cert_id),
    ).fetchall()


def row_lineage(conn: sqlite3.Connection, cert_id: str) -> Lineage:
    """Authorization view of *cert_id*'s lineage, from certificate rows only.
    Reads only on *conn*."""
    addressed = _row(conn, cert_id)
    if addressed is None:
        return Lineage("missing")
    anchor = endpoint_of(addressed["hostname"], addressed["port"])
    seen = {cert_id}
    current = cert_id
    while True:
        successors = _successor_rows(conn, current)
        if not successors:
            break
        if len(successors) > 1 or anchor is None:
            return Lineage("invalid")
        nxt = successors[0]
        if endpoint_of(nxt["hostname"], nxt["port"]) != anchor or nxt["id"] in seen:
            return Lineage("invalid")
        seen.add(str(nxt["id"]))
        current = str(nxt["id"])
    if current == cert_id:
        return Lineage("current")
    return Lineage("superseded", current)


def _lineage_successors(conn: sqlite3.Connection, cert_id: str) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT new_cert_id, hostname, port FROM certificate_lineage "
        "WHERE old_cert_id = ? AND new_cert_id != ?",
        (cert_id, cert_id),
    ).fetchall()


def _anchor(conn: sqlite3.Connection, cert_id: str) -> Endpoint | None:
    """The endpoint *cert_id* was renewed at, from the renewal record: every
    ``certificate_lineage`` row naming it as the old id must agree."""
    endpoints = {endpoint_of(r["hostname"], r["port"]) for r in _lineage_successors(conn, cert_id)}
    if len(endpoints) != 1:
        return None
    (endpoint,) = endpoints
    return endpoint


def navigation_hint(conn: sqlite3.Connection, cert_id: str) -> str | None:
    """The current certificate a person holding the missing id *cert_id*
    should be shown, or ``None``. Never used to decide a write.

    Reads only the renewal record (``certificate_lineage``, written by the
    scan with each renewal) and certificate rows -- never the event log,
    whose retention and Settings → Event stream choices must not break links.
    The renewal record naming the id fixes its endpoint. Each hop -- a
    lineage row or a stored leaf naming the current id -- must offer exactly
    one successor, on that endpoint, without looping, and the last
    certificate must exist there. Any failure: no hint. The caller checks
    the head is visible to the viewer.
    """
    if _row(conn, cert_id) is not None:
        return None  # not a missing id
    anchor = _anchor(conn, cert_id)
    if anchor is None:
        return None
    seen = {cert_id}
    current = cert_id
    while True:
        candidates: dict[str, set[Endpoint | None]] = {}
        for row in _successor_rows(conn, current):
            candidates.setdefault(str(row["id"]), set()).add(
                endpoint_of(row["hostname"], row["port"])
            )
        for edge in _lineage_successors(conn, current):
            candidates.setdefault(str(edge["new_cert_id"]), set()).add(
                endpoint_of(edge["hostname"], edge["port"])
            )
        if not candidates:
            break
        if len(candidates) > 1:
            return None
        ((successor, endpoints),) = candidates.items()
        if endpoints != {anchor} or successor in seen:
            return None
        seen.add(successor)
        current = successor
    if current == cert_id:
        return None
    head = _row(conn, current)
    if head is None or endpoint_of(head["hostname"], head["port"]) != anchor:
        return None
    return current
