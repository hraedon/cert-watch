"""Local break-glass admin: scrypt hashing and the composite provider.

The local admin evaluates before the primary provider and works regardless of
external provider availability. `_CompositeProvider` lives here because it is
small and tightly coupled to `LocalAdminProvider`.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import logging
import os

from .protocol import AuthProvider, AuthResult

logger = logging.getLogger("cert_watch.auth")

# Fixed salt + params used to compute a dummy scrypt hash on username mismatch
# so timing is indistinguishable from the username-match path (BC-072). The
# value is not secret — its only purpose is to spend comparable CPU time.
_DUMMY_SALT = b"cert-watch-dummy"
_DUMMY_N = 2**14
_DUMMY_R = 8
_DUMMY_P = 1


def _scrypt_hash(
    password: str, *, n: int = 2**14, r: int = 8, p: int = 1, salt: bytes | None = None,
) -> str:
    salt = salt or os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=32)
    return f"scrypt${n}${r}${p}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_scrypt_hash(password: str, stored_hash: str) -> bool:
    if not stored_hash or not stored_hash.startswith("scrypt$"):
        return False
    parts = stored_hash.split("$")
    if len(parts) != 6:
        return False
    try:
        n = int(parts[1])
        r = int(parts[2])
        p = int(parts[3])
        salt = base64.b64decode(parts[4])
        expected_dk = base64.b64decode(parts[5])
    except Exception:
        return False
    if n < 2 or r < 1 or p < 1 or len(expected_dk) != 32:
        logger.warning(
            "Rejecting scrypt hash with invalid parameters: n=%s r=%s p=%s",
            parts[1], parts[2], parts[3],
        )
        return False
    if n < 2**14 or r < 8:
        logger.warning(
            "Scrypt hash with weak parameters (n=%s r=%s p=%s) — "
            "production should use n>=16384 r>=8",
            parts[1], parts[2], parts[3],
        )
    dk = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=32)
    return hmac.compare_digest(dk, expected_dk)


class LocalAdminProvider(AuthProvider):
    def __init__(self, username: str, password_hash: str, db_path: str | None = None) -> None:
        self.username = username
        self.password_hash = password_hash
        self.db_path = db_path

    def _dummy_verify(self, password: str, hash_ref: str = "") -> None:
        """Compute a throwaway scrypt hash to equalize timing on username
        mismatch (BC-072). Without this, a non-matching username returns
        immediately while a matching username spends ~100ms in scrypt, letting
        an attacker enumerate the break-glass username by response timing.

        Uses the *stored* hash's cost parameters (review F#1): a custom-cost
        admin hash (e.g. n=2**16, or an imported third-party hash with weaker
        params) would otherwise make the verify path cost differently than this
        dummy, reintroducing the very timing oracle this method exists to close.
        """
        n, r, p = _DUMMY_N, _DUMMY_R, _DUMMY_P
        parts = hash_ref.split("$") if hash_ref else []
        if len(parts) == 6:
            try:
                n, r, p = int(parts[1]), int(parts[2]), int(parts[3])
            except ValueError:
                n, r, p = _DUMMY_N, _DUMMY_R, _DUMMY_P
        try:
            hashlib.scrypt(
                password.encode(), salt=_DUMMY_SALT, n=n, r=r, p=p, dklen=32
            )
        except (ValueError, MemoryError):
            # Pathological stored params — still spend baseline time so the
            # mismatch path never returns conspicuously fast (and never raises).
            with contextlib.suppress(ValueError, MemoryError):
                hashlib.scrypt(
                    password.encode(), salt=_DUMMY_SALT,
                    n=_DUMMY_N, r=_DUMMY_R, p=_DUMMY_P, dklen=32,
                )

    def authenticate(self, username: str, password: str) -> AuthResult:
        if not username or not password:
            return AuthResult(success=False, error="username and password required")

        # Plan 040: try the users table first (full local auth)
        if self.db_path:
            try:
                from cert_watch.database.users_roles import (
                    SqliteRoleRepository,
                    SqliteUserRepository,
                )

                user_repo = SqliteUserRepository(self.db_path)
                user = user_repo.get_by_username(username)
                if user is not None and user.password_hash:
                    if verify_scrypt_hash(password, user.password_hash):
                        role_name = ""
                        if user.role_id:
                            role_repo = SqliteRoleRepository(self.db_path)
                            role = role_repo.get(user.role_id)
                            if role:
                                role_name = role.name
                        return AuthResult(
                            success=True,
                            username=username,
                            email=user.email,
                            groups=[role_name] if role_name else [],
                            roles=[role_name] if role_name else [],
                        )
                    # Wrong password for DB user — spend dummy time then fail
                    self._dummy_verify(password, user.password_hash)
                    return AuthResult(success=False, error="invalid credentials")
            except Exception:
                logger.debug("local auth DB lookup failed", exc_info=True)

        # Legacy break-glass path (env-var local admin)
        if username != self.username:
            self._dummy_verify(password, self.password_hash)
            return AuthResult(success=False, error="invalid credentials")
        if not verify_scrypt_hash(password, self.password_hash):
            return AuthResult(success=False, error="invalid credentials")
        logger.warning("BREAK-GLASS LOGIN: local admin '%s' authenticated", username)
        return AuthResult(
            success=True,
            username=username,
            email="",
            groups=["admins"],
            roles=["admin"],
        )

    def start_oauth_flow(self, redirect_uri: str) -> AuthResult:
        return AuthResult(success=False, error="Use form login for local admin")

    def complete_oauth_flow(self, code: str, redirect_uri: str, state: str = "") -> AuthResult:
        return AuthResult(success=False, error="Use form login for local admin")

    @property
    def provider_name(self) -> str:
        return "local-admin"

    @property
    def supports_form_login(self) -> bool:
        return True

    @property
    def is_break_glass_enabled(self) -> bool:
        return True


class _CompositeProvider(AuthProvider):
    def __init__(self, local: LocalAdminProvider, primary: AuthProvider) -> None:
        self._local = local
        self._primary = primary

    def authenticate(self, username: str, password: str) -> AuthResult:
        result = self._local.authenticate(username, password)
        if result.success:
            return result
        # Always attempt the primary provider — skipping it when local fails
        # would leak timing: fast return = local username mismatch (dummy only),
        # slow return = local matched + password wrong + primary tried.
        #
        # Note: this means every wrong-username attempt produces a real
        # primary-provider round-trip (e.g. LDAP search+bind ~50-500ms) that
        # lands in the primary's access log. The local timing oracle is closed;
        # the remote one (LDAP log shows each attempted username) is inherent
        # to any composite-provider design that tries primary as a fallback.
        primary_result = self._primary.authenticate(username, password)
        return primary_result if primary_result.success else result

    def start_oauth_flow(self, redirect_uri: str) -> AuthResult:
        return self._primary.start_oauth_flow(redirect_uri)

    def complete_oauth_flow(self, code: str, redirect_uri: str, state: str = "") -> AuthResult:
        return self._primary.complete_oauth_flow(code, redirect_uri, state)

    @property
    def provider_name(self) -> str:
        return self._primary.provider_name

    @property
    def supports_form_login(self) -> bool:
        return True

    @property
    def is_break_glass_enabled(self) -> bool:
        return True
