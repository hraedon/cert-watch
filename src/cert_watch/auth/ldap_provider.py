"""LDAP/AD authentication provider via ldap3."""

from __future__ import annotations

import logging
from pathlib import Path

from .protocol import AuthProvider, AuthResult

logger = logging.getLogger("cert_watch.auth")


class LDAPAuthProvider(AuthProvider):
    """LDAP/AD authentication via ldap3.

    Supports:
    - Private-CA TLS: validate server cert against LDAP_CA_CERT / LDAP_CA_CERT_FILE
    - DC failover: comma-separated LDAP_SERVER list → ServerPool with FIRST strategy
    - Transitive group filter: LDAP_REQUIRED_GROUPS enforces membership via
      LDAP_MATCHING_RULE_IN_CHAIN (OID 1.2.840.113556.1.4.1941)
    """

    def __init__(
        self,
        server_url: str,
        base_dn: str,
        bind_dn: str = "",
        bind_password: str = "",
        user_search_filter: str = "(sAMAccountName={username})",
        start_tls: bool = False,
        ca_cert: str = "",
        required_groups: list[str] | None = None,
        connect_timeout: int = 5,
        group_filter: str = "",
    ) -> None:
        self.server_url = server_url
        self.base_dn = base_dn
        self.bind_dn = bind_dn
        self.bind_password = bind_password
        self.user_search_filter = user_search_filter
        self.start_tls = start_tls
        self.ca_cert = ca_cert
        self.required_groups = required_groups or []
        self.connect_timeout = connect_timeout
        self.group_filter = group_filter
        is_ldaps = any(s.lower().startswith("ldaps://") for s in server_url.split(","))
        if not is_ldaps and not start_tls and (bind_dn or bind_password):
            logger.warning(
                "LDAP connection over plaintext ldap:// without STARTTLS — "
                "bind credentials will be transmitted in cleartext. "
                "Use ldaps:// or set LDAP_START_TLS=1."
            )
        try:
            import ldap3  # noqa: F401
        except ImportError:
            raise RuntimeError(
                "LDAP auth requires the 'ldap3' package. "
                "Install it with: pip install cert-watch[auth-ldap]"
            ) from None

    def _build_tls(self) -> tuple:
        """Build ldap3.Tls and server list from config.

        Returns (tls_obj, servers) where servers is a list of ldap3.Server.
        For ldaps:// with ca_cert configured, sets CERT_REQUIRED (fail-closed).
        For start_tls, TLS is negotiated after connect.
        For plain ldap://, returns (None, servers).
        """
        import ssl

        import ldap3

        server_urls = [s.strip() for s in self.server_url.split(",") if s.strip()]
        tls = None
        is_ldaps = any(s.lower().startswith("ldaps://") for s in server_urls)

        if is_ldaps or self.start_tls:
            tls_kwargs: dict = {}
            if self.ca_cert:
                tls_kwargs["validate"] = ssl.CERT_REQUIRED
                ca_path = self._resolve_ca_cert()
                if ca_path and ca_path.exists():
                    tls_kwargs["ca_certs_file"] = str(ca_path)
                else:
                    tls_kwargs["ca_certs_data"] = self.ca_cert
            else:
                tls_kwargs["validate"] = ssl.CERT_REQUIRED

            if self.start_tls and not is_ldaps and not self.ca_cert:
                logger.warning(
                    "STARTTLS without LDAP_CA_CERT — validating against system trust "
                    "store only; private-CA servers will fail. "
                    "Set LDAP_CA_CERT or LDAP_CA_CERT_FILE to pin your CA."
                )

            if is_ldaps and not self.ca_cert:
                logger.warning(
                    "LDAPS without LDAP_CA_CERT — validating against system trust "
                    "store only; private-CA servers will fail. "
                    "Set LDAP_CA_CERT or LDAP_CA_CERT_FILE to pin your CA."
                )

            tls = ldap3.Tls(**tls_kwargs)

        servers = [
            ldap3.Server(url, get_info=ldap3.NONE, tls=tls, connect_timeout=self.connect_timeout)
            for url in server_urls
        ]
        return tls, servers

    def _resolve_ca_cert(self) -> Path | None:
        """If ca_cert looks like a file path that exists, return it; else None.

        ``ca_cert`` is usually inline PEM (e.g. ``LDAP_CA_CERT`` or the contents
        of ``LDAP_CA_CERT_FILE`` read by ``read_secret``). Inline PEM must never
        be stat-ed as a path: a long string makes ``Path.is_file()`` raise
        ``OSError(ENAMETOOLONG)`` (not return False), which previously bubbled up
        as a generic "authentication failed" and broke every private-CA LDAPS
        login. Treat anything that looks like PEM — or is too long / multi-line to
        be a path — as inline data, and guard the stat itself.
        """
        val = self.ca_cert
        if not val or "BEGIN CERTIFICATE" in val or "\n" in val or len(val) > 1024:
            return None
        try:
            p = Path(val)
            if p.is_file():
                return p
        except OSError:
            return None
        return None

    def _build_group_filter(self, group_dn: str) -> str:
        """Build a single group-membership LDAP filter fragment.

        Uses ``self.group_filter`` as a template with ``{group}`` placeholder.
        When empty (default), uses the AD transitive OID
        ``(memberOf:1.2.840.113556.1.4.1941:={group})`` for backward compat.
        """
        import ldap3

        escaped = ldap3.utils.conv.escape_filter_chars(group_dn)
        if self.group_filter:
            return "(" + self.group_filter.replace("{group}", escaped) + ")"
        return f"(memberOf:1.2.840.113556.1.4.1941:={escaped})"

    def authenticate(self, username: str, password: str) -> AuthResult:
        if not username or not password:
            return AuthResult(success=False, error="username and password required")
        try:
            import ldap3
        except ImportError:
            return AuthResult(success=False, error="ldap3 not installed")

        try:
            tls, servers = self._build_tls()

            pool_or_single: ldap3.ServerPool | ldap3.Server
            if len(servers) > 1:
                pool_or_single = ldap3.ServerPool(
                    servers, pool_strategy=ldap3.FIRST, active=True,
                )
            else:
                pool_or_single = servers[0]

            # SSL/TLS is determined by the Server (ldaps:// scheme), not the
            # Connection — ldap3.Connection has no `use_ssl` kwarg and current
            # versions reject it outright.
            conn = ldap3.Connection(
                pool_or_single,
                user=self.bind_dn or None,
                password=self.bind_password or None,
                auto_bind=False,
            )
            if self.start_tls and tls:
                conn.start_tls()
            conn.bind()

            search_filter = self.user_search_filter.replace(
                "{username}", ldap3.utils.conv.escape_filter_chars(username)
            )

            if self.required_groups:
                group_filters = " ".join(
                    self._build_group_filter(g)
                    for g in self.required_groups
                )
                search_filter = f"(&{search_filter}(|{group_filters}))"

            conn.search(
                self.base_dn,
                search_filter,
                attributes=["distinguishedName", "cn", "mail", "memberOf"],
            )
            if not conn.entries:
                conn.unbind()
                if self.required_groups:
                    return AuthResult(
                        success=False,
                        error="user not found or not in required group(s)",
                    )
                return AuthResult(success=False, error="user not found")

            user_dn = str(conn.entries[0].distinguishedName)
            user_groups = (
                list(conn.entries[0].memberOf.values)
                if hasattr(conn.entries[0], "memberOf")
                else []
            )
            conn.unbind()

            user_conn = ldap3.Connection(
                pool_or_single, user=user_dn, password=password,
                auto_bind=False,
            )
            if self.start_tls and tls:
                user_conn.start_tls()
            # ldap3's bind() returns False on bad credentials (it does not raise
            # unless raise_exceptions=True), so the result MUST be checked. This
            # is the actual password-verification step — ignoring it is an auth
            # bypass (any password would be accepted for an existing user).
            bound = user_conn.bind()
            user_conn.unbind()
            if not bound:
                return AuthResult(success=False, error="invalid credentials")

            return AuthResult(
                success=True,
                username=username,
                groups=user_groups,
            )
        except ldap3.core.exceptions.LDAPBindError:
            return AuthResult(success=False, error="invalid credentials")
        except Exception as exc:
            logger.warning("LDAP auth error: %s", exc)
            return AuthResult(success=False, error="authentication failed")

    def start_oauth_flow(self, redirect_uri: str) -> AuthResult:
        return AuthResult(success=False, error="OAuth not available with LDAP provider")

    def complete_oauth_flow(self, code: str, redirect_uri: str, state: str = "") -> AuthResult:
        return AuthResult(success=False, error="OAuth not available with LDAP provider")

    @property
    def provider_name(self) -> str:
        return "ldap"

    @property
    def supports_form_login(self) -> bool:
        return True
