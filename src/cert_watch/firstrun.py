"""First-run security posture decision (BC-114).

The single most important security decision cert-watch makes is what a fresh
instance with no configured auth provider does on startup: serve open (dev),
auto-provision a local admin, or refuse to start. That decision used to live
inline in the side-effecting ``app.lifespan`` (schema init, scheduler, logging),
where it could only be exercised through the heavyweight startup path. This
module isolates it as two pure functions so it can be exhaustively table-tested
on its own. ``app.lifespan`` consumes them and performs the side effects.
"""

from __future__ import annotations

import enum

# Loopback binds that are not, by themselves, reachable from the network.
_LOOPBACK_BINDS = frozenset({"127.0.0.1", "::1", "localhost"})


class FirstRunPosture(enum.Enum):
    """What an instance should do given its auth + exposure posture."""

    AUTHENTICATED = "authenticated"  # a real provider is configured — gate is moot
    SERVE_OPEN = "serve_open"        # no provider, but safe to serve open (dev / opt-out)
    PROVISION_ADMIN = "provision"    # no provider on a network-exposed bind — auto-provision


def is_network_exposed(bind_host: str, trust_proxy: bool) -> bool:
    """Return True if the instance is reachable from the network.

    A routable bind is exposed; a loopback bind is exposed only when a proxy
    republishes it (``CERT_WATCH_TRUST_PROXY=1``, e.g. IIS/nginx).
    ``CERT_WATCH_HOST`` is the source of truth for the bind — the entrypoint
    normalizes ``--host``/env into it so this can't diverge from the real bind
    (BC-090).
    """
    return bind_host not in _LOOPBACK_BINDS or trust_proxy


def first_run_action(
    *, has_provider: bool, allow_unauth: bool, network_exposed: bool
) -> FirstRunPosture:
    """Decide the first-run posture from the auth/exposure facts (pure).

    - A configured auth provider ⇒ ``AUTHENTICATED`` (this whole gate is moot).
    - No provider, but either an explicit opt-out (``allow_unauth``) or a
      non-exposed bind ⇒ ``SERVE_OPEN`` (bare-loopback dev + the /setup wizard).
    - No provider on a network-exposed bind ⇒ ``PROVISION_ADMIN``: come up
      authenticated rather than open.

    The caller provisions on ``PROVISION_ADMIN`` and then re-evaluates: if
    provisioning succeeded the result becomes ``AUTHENTICATED``; if it failed (or
    was skipped) the result is still ``PROVISION_ADMIN``, which the caller treats
    as the fail-closed signal — refuse to serve open rather than expose an
    unauthenticated app.
    """
    if has_provider:
        return FirstRunPosture.AUTHENTICATED
    if allow_unauth or not network_exposed:
        return FirstRunPosture.SERVE_OPEN
    return FirstRunPosture.PROVISION_ADMIN
