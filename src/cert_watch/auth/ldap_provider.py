"""LDAP/AD authentication provider via ldap3."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from .protocol import AuthProvider, AuthResult

logger = logging.getLogger("cert_watch.auth")


def insecure_ldap_error(
    server_url: str, *, start_tls: bool, allow_insecure: bool
) -> str | None:
    """Explain why a configured LDAP endpoint would send simple-bind secrets in clear."""
    urls = [value.strip() for value in server_url.split(",") if value.strip()]
    has_plain_endpoint = any(not value.lower().startswith("ldaps://") for value in urls)
    if has_plain_endpoint and not start_tls and not allow_insecure:
        return (
            "Insecure LDAP simple bind refused: use ldaps:// or set LDAP_START_TLS=1. "
            "Set CERT_WATCH_LDAP_ALLOW_INSECURE=1 only for a trusted legacy deployment."
        )
    return None


# Shown at the sign-in page when the directory cannot be asked at all. It
# names no configuration detail; the server log carries the reason.
LDAP_MISCONFIGURED = (
    "Directory sign-in is misconfigured. An administrator can sign in with the "
    "local account and correct Settings → Sign-in; the server log has the details."
)


def _outer_pair_wraps_all(value: str) -> bool:
    """Whether *value*'s first ``(`` closes at its last character.

    Literal parentheses in an LDAP filter value are escaped (``\\28``/``\\29``,
    RFC 4515), so unescaped ones are always structure and depth counting is
    exact. ``(a)(b)`` starts and ends with parentheses but is two filters.
    """
    if not (value.startswith("(") and value.endswith(")")):
        return False
    depth = 0
    for index, char in enumerate(value):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index == len(value) - 1
    return False


def normalize_user_filter(template: str) -> str:
    """Add the outer parentheses RFC 4515 requires when they are missing."""
    template = template.strip()
    if template and not _outer_pair_wraps_all(template):
        return f"({template})"
    return template


def normalize_group_filter(template: str) -> str:
    """Drop one outer pair: each group fragment is wrapped when it is built."""
    template = template.strip()
    if _outer_pair_wraps_all(template):
        return template[1:-1].strip()
    return template


def _filter_syntax_error(search_filter: str) -> str | None:
    try:
        from ldap3.core.exceptions import LDAPInvalidFilterError
        from ldap3.operation.search import parse_filter
    except ImportError:
        return None  # the provider refuses to start without ldap3 anyway
    try:
        # The arguments a default ldap3.Connection passes to the same parser.
        parse_filter(
            search_filter, None, auto_escape=True, auto_encode=True,
            validator=None, check_names=False,
        )
    except LDAPInvalidFilterError as exc:
        return str(exc)
    return None


def user_filter_error(template: str) -> str | None:
    """Why *template* cannot work as the LDAP user search filter, or None."""
    template = normalize_user_filter(template)
    if "{username}" not in template:
        return "must contain {username}, which is replaced by the name typed at sign-in"
    syntax = _filter_syntax_error(template.replace("{username}", "user"))
    if syntax:
        return f"is not a valid LDAP filter ({syntax})"
    return None


def group_filter_error(template: str) -> str | None:
    """Why *template* cannot work as the LDAP group filter, or None."""
    template = normalize_group_filter(template)
    if not template:
        return None  # the built-in nested-membership rule
    if "{group}" not in template:
        return "must contain {group}, which is replaced by each required group's DN"
    syntax = _filter_syntax_error("(" + template.replace("{group}", "CN=group") + ")")
    if syntax:
        return f"is not a valid LDAP filter ({syntax})"
    return None


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
        allow_insecure: bool = False,
        ca_cert: str = "",
        required_groups: list[str] | None = None,
        connect_timeout: int = 5,
        group_filter: str = "",
    ) -> None:
        self.server_url = server_url
        self.base_dn = base_dn
        self.bind_dn = bind_dn
        self.bind_password = bind_password
        self.user_search_filter = normalize_user_filter(user_search_filter)
        self.start_tls = start_tls
        self.allow_insecure = allow_insecure
        self.ca_cert = ca_cert
        self.required_groups = required_groups or []
        self.connect_timeout = connect_timeout
        self.group_filter = normalize_group_filter(group_filter)
        # Checked once here so a bad filter is reported when the provider is
        # built (startup, or saving Settings → Sign-in), not only as failed
        # sign-ins. Never raised: the local account must stay usable to fix it.
        self.config_error = self._filter_config_error()
        if self.config_error:
            logger.error("LDAP sign-in will fail until this is fixed: %s", self.config_error)
        endpoints = [value.strip() for value in server_url.split(",") if value.strip()]
        has_plain_endpoint = any(
            not endpoint.lower().startswith("ldaps://") for endpoint in endpoints
        )
        if has_plain_endpoint and not start_tls and allow_insecure:
            logger.warning(
                "CERT_WATCH_LDAP_ALLOW_INSECURE=1 permits plaintext LDAP simple binds; "
                "directory credentials will be transmitted in cleartext."
            )
        try:
            import ldap3  # noqa: F401
        except ImportError:
            raise RuntimeError(
                "LDAP auth requires the 'ldap3' package. "
                "Install it with: pip install cert-watch[auth-ldap]"
            ) from None

    def _filter_config_error(self) -> str | None:
        user_error = user_filter_error(self.user_search_filter)
        if user_error:
            return (
                f"the LDAP user search filter {self.user_search_filter!r} {user_error}. "
                "Set it under Settings → Sign-in or with LDAP_USER_FILTER, e.g. "
                "(sAMAccountName={username})."
            )
        if self.required_groups:
            group_error = group_filter_error(self.group_filter)
            if group_error:
                return (
                    f"LDAP_GROUP_FILTER {self.group_filter!r} {group_error}, "
                    "e.g. member={group}."
                )
        return None

    def _build_tls(self) -> tuple[Any, list[Any]]:
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
            tls_kwargs: dict[str, Any] = {}
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
        insecure_error = insecure_ldap_error(
            self.server_url,
            start_tls=self.start_tls,
            allow_insecure=self.allow_insecure,
        )
        if insecure_error:
            # Shown as-is (pre-1.0 hardening): it names the setting to change.
            return AuthResult(success=False, error=insecure_error, unavailable=True)
        if self.config_error:
            logger.error("LDAP sign-in refused: %s", self.config_error)
            return AuthResult(success=False, error=LDAP_MISCONFIGURED, unavailable=True)
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

            entry = conn.entries[0]
            user_dn = str(entry.distinguishedName)
            user_groups = (
                list(entry.memberOf.values)
                if hasattr(entry, "memberOf")
                else []
            )
            email = str(entry.mail.value) if hasattr(entry, "mail") and entry.mail else ""
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
                email=email,
            )
        except ldap3.core.exceptions.LDAPBindError:
            return AuthResult(success=False, error="invalid credentials")
        except ldap3.core.exceptions.LDAPInvalidFilterError as exc:
            logger.error("LDAP sign-in refused: the search filter is invalid: %s", exc)
            return AuthResult(success=False, error=LDAP_MISCONFIGURED, unavailable=True)
        except (ldap3.core.exceptions.LDAPException, OSError) as exc:
            logger.warning("LDAP auth error: %s", exc)
            return AuthResult(success=False, error="authentication failed")
        except Exception as exc:  # noqa: BLE001 — final safety net for unexpected errors
            logger.warning("LDAP auth unexpected error: %s", exc)
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
