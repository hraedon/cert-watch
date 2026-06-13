"""TOFU CA capture / TLS chain probing helpers used by the LDAP CA trust flow."""

from __future__ import annotations

import contextlib
import ipaddress
import socket
import ssl

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from cert_watch.certificate_model import Certificate, parse_certificate
from cert_watch.scan import _is_blocked_ip
from cert_watch.scan_conn import _get_chain_der


def _capture_ldaps_chain(
    url: str,
    timeout: int = 5,
    *,
    allow_private: bool = True,
    allowed_subnets: tuple[str, ...] = (),
) -> list[dict] | None:
    """Capture the certificate chain presented by an LDAPS server using a non-validating probe."""
    lowered = url.lower()
    if not lowered.startswith("ldaps://"):
        return None
    rest = url[8:]
    host = rest.split(":")[0].split("/")[0]
    port = 636
    if ":" in rest:
        with contextlib.suppress(ValueError):
            port = int(rest.split(":")[1].split("/")[0])
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
) -> list[dict] | None:
    """Capture the certificate chain presented by an LDAP server via StartTLS."""
    lowered = url.lower()
    if not lowered.startswith("ldap://"):
        return None
    rest = url[7:]
    host = rest.split(":")[0].split("/")[0]
    port = 389
    if ":" in rest:
        with contextlib.suppress(ValueError):
            port = int(rest.split(":")[1].split("/")[0])

    # SSRF guard — resolve hostnames to catch DNS-based bypasses
    try:
        ip = ipaddress.ip_address(host)
        if _is_blocked_ip(ip, allow_private=allow_private, allowed_subnets=allowed_subnets):
            return None
    except ValueError:
        from cert_watch.scan_resolver import resolve_and_validate_host

        err, _ = resolve_and_validate_host(
            host, port, allow_private=allow_private, allowed_subnets=allowed_subnets,
        )
        if err:
            return None

    # Try ldap3 StartTLS first
    try:
        import ldap3
    except ImportError:
        return None

    der_chain: list[bytes] = []
    try:
        srv = ldap3.Server(url, get_info=ldap3.NONE, connect_timeout=timeout)
        conn = ldap3.Connection(srv, auto_bind=False, receive_timeout=timeout)
        conn.open()
        conn.start_tls()
        ssl_sock = conn.socket
        if ssl_sock is not None:
            der_chain = _get_chain_der(ssl_sock)
        conn.unbind()
    except Exception:  # noqa: BLE001 — LDAPS probe; failure must not crash settings save
        pass

    # Fallback: raw TLS probe on the same port
    if not der_chain:
        return _probe_tls_chain(
            host, port, timeout,
            allow_private=allow_private,
            allowed_subnets=allowed_subnets,
        )

    return _der_chain_to_ca_dicts(der_chain)


def _probe_tls_chain(
    host: str,
    port: int,
    timeout: int = 5,
    *,
    allow_private: bool = True,
    allowed_subnets: tuple[str, ...] = (),
) -> list[dict] | None:
    """Non-validating TLS probe to capture the certificate chain from *host:port*."""
    # SSRF guard — resolve hostnames to catch DNS-based bypasses
    try:
        ip = ipaddress.ip_address(host)
        if _is_blocked_ip(ip, allow_private=allow_private, allowed_subnets=allowed_subnets):
            return None
    except ValueError:
        from cert_watch.scan_resolver import resolve_and_validate_host

        err, _ = resolve_and_validate_host(
            host, port, allow_private=allow_private, allowed_subnets=allowed_subnets,
        )
        if err:
            return None

    der_chain: list[bytes] = []
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with (
            socket.create_connection((host, port), timeout=timeout) as sock,
            ctx.wrap_socket(sock, server_hostname=host) as ssl_sock,
        ):
            der_chain = _get_chain_der(ssl_sock)
    except Exception:  # noqa: BLE001 — TLS probe; failure must not crash settings save
        pass

    # If we only have the leaf (or nothing), try openssl for the full chain
    if len(der_chain) <= 1:
        from cert_watch.scan import _scan_via_openssl

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


def _der_chain_to_ca_dicts(der_chain: list[bytes]) -> list[dict] | None:
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

    result: list[dict] = []
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
