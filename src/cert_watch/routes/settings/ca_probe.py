"""TOFU CA capture / TLS chain probing helpers used by the LDAP CA trust flow."""

from __future__ import annotations

import ipaddress
import socket
import ssl
from typing import Any
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from cert_watch.certificate_model import Certificate, parse_certificate
from cert_watch.scan_conn import _get_chain_der
from cert_watch.scan_resolver import _is_blocked_ip, resolve_and_validate_host


def _parse_ldaps_url(url: str) -> tuple[str, int] | None:
    """Parse an ``ldaps://`` URL into (host, port). Returns None on parse failure."""
    lowered = url.lower()
    if not lowered.startswith("ldaps://"):
        return None
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if not host:
        return None
    port = parsed.port or 636
    return host, port


def _parse_ldap_url(url: str) -> tuple[str, int] | None:
    """Parse an ``ldap://`` URL into (host, port). Returns None on parse failure."""
    lowered = url.lower()
    if not lowered.startswith("ldap://"):
        return None
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if not host:
        return None
    port = parsed.port or 389
    return host, port


_BLOCKED = object()


def _resolve_and_pin(
    host: str, port: int, *, allow_private: bool, allowed_subnets: tuple[str, ...],
) -> Any:
    """Validate *host* and return the pinned IP, or a sentinel for blocked.

    Returns:
        - ``_BLOCKED`` if the host resolves to a blocked/SSRF address
        - A string IP to pin (prevents DNS rebinding) when resolution succeeds
        - ``None`` when DNS doesn't resolve (caller uses hostname directly;
          the connection will simply fail)
    """
    try:
        ip = ipaddress.ip_address(host)
        if _is_blocked_ip(ip, allow_private=allow_private, allowed_subnets=allowed_subnets):
            return _BLOCKED
        return host
    except ValueError:
        err, pinned_ip = resolve_and_validate_host(
            host, port, allow_private=allow_private, allowed_subnets=allowed_subnets,
        )
        if err:
            return _BLOCKED
        return pinned_ip


def _capture_ldaps_chain(
    url: str,
    timeout: int = 5,
    *,
    allow_private: bool = True,
    allowed_subnets: tuple[str, ...] = (),
) -> list[dict[str, Any]] | None:
    """Capture the certificate chain presented by an LDAPS server using a non-validating probe."""
    parsed = _parse_ldaps_url(url)
    if parsed is None:
        return None
    host, port = parsed
    return _probe_tls_chain(
        host, port, timeout,
        allow_private=allow_private, allowed_subnets=allowed_subnets,
    )


def _capture_starttls_chain(
    url: str,
    timeout: int = 5,
    *,
    allow_private: bool = True,
    allowed_subnets: tuple[str, ...] = (),
) -> list[dict[str, Any]] | None:
    """Capture the certificate chain presented by an LDAP server via StartTLS."""
    parsed = _parse_ldap_url(url)
    if parsed is None:
        return None
    host, port = parsed

    # SSRF guard — resolve and pin the IP to prevent DNS rebinding TOCTOU
    pinned_ip = _resolve_and_pin(
        host, port, allow_private=allow_private, allowed_subnets=allowed_subnets,
    )
    if pinned_ip is _BLOCKED:
        return None

    # Try ldap3 StartTLS first
    try:
        import ldap3
    except ImportError:
        return None

    der_chain: list[bytes] = []
    try:
        # Use the pinned IP for the connection to prevent DNS rebinding.
        # When DNS didn't resolve (pinned_ip is None), fall back to the
        # hostname — the connection will fail on its own.
        connect_target = pinned_ip if pinned_ip else host
        srv = ldap3.Server(
            connect_target, port=port, use_ssl=False,
            get_info=ldap3.NONE, connect_timeout=timeout,
        )
        conn = ldap3.Connection(srv, auto_bind=False, receive_timeout=timeout)
        conn.open()
        conn.start_tls()
        ssl_sock = conn.socket
        if ssl_sock is not None:
            der_chain = _get_chain_der(ssl_sock)
        conn.unbind()
    except Exception:  # noqa: BLE001 — LDAPS probe; failure must not crash settings save
        pass

    # Fallback: raw TLS probe on the same port (also uses pinned IP)
    if not der_chain:
        return _probe_tls_chain(
            host, port, timeout,
            allow_private=allow_private,
            allowed_subnets=allowed_subnets,
            _pinned_ip=pinned_ip,
        )

    return _der_chain_to_ca_dicts(der_chain)


def _probe_tls_chain(
    host: str,
    port: int,
    timeout: int = 5,
    *,
    allow_private: bool = True,
    allowed_subnets: tuple[str, ...] = (),
    _pinned_ip: str | None = None,
) -> list[dict[str, Any]] | None:
    """Non-validating TLS probe to capture the certificate chain from *host:port*.

    When ``_pinned_ip`` is provided (by a caller that already validated the
    hostname), the connection uses that IP directly to prevent DNS rebinding.
    Otherwise, the SSRF guard resolves and validates the hostname here.
    """
    if _pinned_ip is not None:
        pinned: str | None = _pinned_ip
    else:
        pinned = _resolve_and_pin(
            host, port, allow_private=allow_private, allowed_subnets=allowed_subnets,
        )
        if pinned is _BLOCKED:
            return None

    # When DNS didn't resolve (pinned is None), fall back to hostname.
    connect_target = pinned if pinned else host

    der_chain: list[bytes] = []
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Use the pinned IP for the connection to prevent DNS rebinding.
        # server_hostname is set to the original host for SNI.
        with (
            socket.create_connection((connect_target, port), timeout=timeout) as sock,
            ctx.wrap_socket(sock, server_hostname=host) as ssl_sock,
        ):
            der_chain = _get_chain_der(ssl_sock)
    except Exception:  # noqa: BLE001 — TLS probe; failure must not crash settings save
        pass

    # If we only have the leaf (or nothing), try openssl for the full chain
    if len(der_chain) <= 1:
        from cert_watch.scan_conn import _scan_via_openssl

        try:
            openssl_chain, _ = _scan_via_openssl(
                host, port, timeout,
                allow_private=allow_private, allowed_subnets=allowed_subnets,
            )
            if openssl_chain:
                der_chain = openssl_chain
        except Exception:  # noqa: BLE001 — openssl fallback; failure must not crash settings save
            pass

    return _der_chain_to_ca_dicts(der_chain)


def _der_chain_to_ca_dicts(der_chain: list[bytes]) -> list[dict[str, Any]] | None:
    """Convert a list of DER-encoded certificates to CA dicts (leaf excluded)."""
    if not der_chain:
        return None

    certs: list[Certificate] = []
    for der in der_chain:
        parsed = parse_certificate(der)
        if isinstance(parsed, Certificate):
            certs.append(parsed)

    if not certs:
        return None

    # Drop the leaf (first cert); keep issuing CAs and root
    ca_certs = certs[1:]
    if not ca_certs:
        return None

    result: list[dict[str, Any]] = []
    for cert in ca_certs:
        pem = (
            x509.load_der_x509_certificate(cert.raw_der)
            .public_bytes(Encoding.PEM)
            .decode("utf-8")
        )
        result.append(
            {
                "subject": cert.subject,
                "issuer": cert.issuer,
                "not_after": cert.not_after.isoformat() if cert.not_after else "",
                "sha256": cert.fingerprint_sha256,
                "pem": pem,
            }
        )
    return result


def _is_cert_verify_error(exc: Exception) -> bool:
    """Return True when *exc* is a TLS certificate verification failure."""
    msg = str(exc).lower()
    return any(
        phrase in msg
        for phrase in (
            "certificate_verify_failed",
            "certificate verify failed",
            "unable to get local issuer certificate",
            "self signed certificate",
            "self-signed certificate",
            "unable to verify leaf signature",
            "certificate chain too long",
            "invalid ca certificate",
        )
    )
