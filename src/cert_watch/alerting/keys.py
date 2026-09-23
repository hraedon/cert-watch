"""Stable alert identities for endpoint-bound and uploaded certificates."""

from __future__ import annotations


def certificate_alert_key(
    prefix: str,
    *,
    cert_id: str,
    fingerprint: str | None,
    hostname: str | None,
    port: int | None,
    suffix: tuple[str, ...] = (),
) -> str:
    """Build a key scoped to the route-bearing endpoint when one exists.

    Uploaded certificates have no endpoint route, so their database row is the
    stable identity. Empty fingerprints also fall back to the row identity.
    """
    if hostname and port is not None:
        identity = f"{hostname}:{port}:{fingerprint or cert_id}"
    else:
        identity = f"cert:{cert_id}"
    return ":".join((prefix, identity, *suffix))
