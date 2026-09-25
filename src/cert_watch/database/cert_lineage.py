"""Renewal lineage of a certificate id (#115).

Two questions, answered separately on purpose:

* :func:`row_lineage` -- *may a write addressed to this id go ahead?* It uses
  stored certificate rows only (``replaces_cert_id`` among existing rows).
  Events never authorize or refuse a write.
* :func:`navigation_hint` -- *where should a person holding this missing id
  be sent?* It may read lifecycle events, but only when every event naming
  the id agrees on its endpoint, and it never changes whether a write
  happens.
  Both the stale-link page redirect and the mutation routes' "renewed,
  nothing was changed" answer use it, so they cannot disagree.

Trust boundary: ``event_log`` and ``certificates`` are written only by the
application. The checks here defend against records that are stale,
duplicated, contradictory, malformed or misattributed in *one* of them (an
old event, a leftover duplicate row, a payload naming the wrong endpoint).
A scenario that needs forged, mutually consistent rows in *both* tables
requires direct write access to the database, which is trusted and out of
scope.
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


# Lifecycle events, skipping payloads that aren't valid JSON (json_extract
# on one would raise). CASE forces the json_valid test before extraction.
def _event_field(name: str) -> str:
    return f"CASE WHEN json_valid(payload) THEN json_extract(payload, '$.{name}') END"


_OWN_EVENTS = (
    f"SELECT {_event_field('hostname')} AS hostname, {_event_field('port')} AS port "
    "FROM event_log WHERE event_type IN ('cert_added', 'cert_renewed') "
    f"AND {_event_field('cert_id')} = ?"
)
_RENEWALS_OF = (
    f"SELECT {_event_field('cert_id')} AS cert_id, {_event_field('hostname')} AS hostname, "
    f"{_event_field('port')} AS port FROM event_log WHERE event_type = 'cert_renewed' "
    f"AND {_event_field('replaced_cert_id')} = ?"
)


def _anchor(conn: sqlite3.Connection, cert_id: str) -> Endpoint | None:
    """The endpoint *cert_id* belonged to, from the lifecycle events that
    name it: its own issuance (``cert_added``, or ``cert_renewed`` as the new
    id) and the ``cert_renewed`` that replaced it. Either kind anchors on its
    own -- the issuance event ages out of retention long before a 90-day
    certificate is renewed, while the renewal event is fresh -- but every
    event that names the id must agree on one endpoint, or there is none.
    Renewal events alone anchor only when a stored successor row naming the
    id is on that endpoint too."""
    own = conn.execute(_OWN_EVENTS, (cert_id,)).fetchall()
    renewed = conn.execute(_RENEWALS_OF, (cert_id,)).fetchall()
    endpoints = {endpoint_of(e["hostname"], e["port"]) for e in [*own, *renewed]}
    if len(endpoints) != 1:
        return None
    (endpoint,) = endpoints
    if not own:
        # Only renewal events are left, and a lone one would be both the
        # anchor and the first hop -- "all agree" is vacuous. Require a
        # surviving successor row that names the id and sits on the same
        # endpoint (#115 review round 8).
        rows = _successor_rows(conn, cert_id)
        if not any(endpoint_of(r["hostname"], r["port"]) == endpoint for r in rows):
            return None
    return endpoint


def navigation_hint(conn: sqlite3.Connection, cert_id: str) -> str | None:
    """The current certificate a person holding the missing id *cert_id*
    should be shown, or ``None``. Never used to decide a write.

    The lifecycle events naming the id fix its endpoint (see
    :func:`_anchor`); with none left, there is no hint. Each hop -- a row naming
    the current id in ``replaces_cert_id`` or a ``cert_renewed`` event naming
    it as replaced -- must offer exactly one successor, on that endpoint
    (both the row's and the event's, where both exist), without looping. The
    last certificate must exist, on that endpoint. Any failure: no hint.
    The caller checks the head is visible to the viewer.
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
        for event in conn.execute(_RENEWALS_OF, (current,)):
            if not event["cert_id"]:
                return None
            candidates.setdefault(str(event["cert_id"]), set()).add(
                endpoint_of(event["hostname"], event["port"])
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
