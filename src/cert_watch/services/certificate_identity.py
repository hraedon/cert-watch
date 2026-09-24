"""Mutations addressed by a certificate id that a renewal has replaced (#115).

A renewal gives the endpoint's certificate a new id. A request prepared
against the old id -- a form left open, an API call queued behind the scan
that renewed it -- can no longer mean what its sender saw, and the old row is
gone, so applying it would either silently do nothing (an unassign that
removes no row but answers "unassigned") or act on a certificate the sender
never looked at (a delete that follows the id to its successor).

The rule for every certificate-id-addressed mutation: call
:func:`ensure_not_superseded` inside the write lock, before the mutation, in
the same critical section as the write. An id that names a replaced
certificate is refused with :class:`CertificateSupersededError`, carrying the
current certificate's id when the caller may see it, so the client can
re-read the current certificate and decide again. It is never retargeted to
the successor and never answered with success for a no-op. Ids that no
certificate ever had fall through to the caller's own not-found handling.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


class CertificateSupersededError(LookupError):
    """The id named a certificate that has since been replaced by a renewal."""

    def __init__(self, cert_id: str, current_id: str | None) -> None:
        super().__init__("certificate superseded by a renewal; nothing was changed")
        self.cert_id = cert_id
        # None when the caller's tag scope does not cover the current
        # certificate: its id is not revealed, and the caller answers exactly
        # as for an unknown id.
        self.current_id = current_id


def _may_read(auth: Any, db_path: str | Path, cert_id: str) -> bool:
    if auth is None or getattr(auth, "is_admin", False) or getattr(auth, "is_system", False):
        return True
    scope_tag = getattr(auth, "scope_tag", "") or ""
    if not scope_tag:
        return True
    from cert_watch.auth.scope import _effective_tags, _folded
    from cert_watch.tags import parse_tags

    return bool(_folded(parse_tags(scope_tag)) & _folded(_effective_tags(db_path, cert_id=cert_id)))


def ensure_not_superseded(db_path: str | Path, cert_id: str, *, auth: Any) -> None:
    """Raise :class:`CertificateSupersededError` if *cert_id* was renewed away.

    Must be called with the write lock held, in the same critical section as
    the mutation it guards: a scan renews under that lock, so the answer
    cannot change before the write.
    """
    from cert_watch.database.connection import _connect
    from cert_watch.database.dashboard_detail import resolve_current_certificate

    with _connect(db_path) as conn:
        exists = conn.execute(
            "SELECT 1 FROM certificates WHERE id = ?", (cert_id,)
        ).fetchone()
    if exists is not None:
        return
    ref = resolve_current_certificate(db_path, cert_id)
    if ref is None or not ref.superseded:
        return
    current = ref.cert_id if _may_read(auth, db_path, ref.cert_id) else None
    raise CertificateSupersededError(cert_id, current)
