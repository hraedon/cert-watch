"""SecurityContext — the cryptographic signing material for the app.

Plan 018 B1 / WI-083: instead of mutating module-level globals (`_signing_key` in
``auth.session``, `_csrf_secret_val` in ``middleware``) at lifespan startup,
the resolved keys live in a single immutable object created once and carried on
``app.state.security``. Request-path code reads it from ``request.app.state``;
the OAuth provider receives it at construction (``OAuthProvider(security=…)``).
The module globals remain only as an import-time fallback for direct unit-test
calls that don't go through the app (set via ``conftest``).

Keeping this in its own leaf module avoids an import cycle between
``auth.session`` and ``middleware`` (which already import each other's symbols).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SecurityContext:
    """Immutable signing keys for session tokens and CSRF tokens."""

    signing_key: str
    csrf_secret: str
