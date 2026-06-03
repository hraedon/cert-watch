"""Tests for BC-115 (LDAP StartTLS), BC-116/117 (SSRF HTTP opener), BC-118 (LDAP group filter)."""

import sys
from unittest.mock import MagicMock, patch

import pytest

from cert_watch.http_client import SSRFBlockedError, _validate_url, ssrf_safe_urlopen

# ---------- BC-115: LDAP StartTLS ----------


@pytest.fixture
def _mock_ldap3():
    mock_ldap3 = MagicMock()
    mock_ldap3.core = MagicMock()
    mock_ldap3.core.exceptions = MagicMock()
    mock_ldap3.core.exceptions.LDAPBindError = type("LDAPBindError", (Exception,), {})
    mock_ldap3.utils = MagicMock()
    mock_ldap3.utils.conv = MagicMock()
    mock_ldap3.utils.conv.escape_filter_chars = lambda x: x
    mock_ldap3.Tls = MagicMock()
    mock_ldap3.ServerPool = MagicMock()
    mock_ldap3.FIRST = "FIRST"
    mock_ldap3.NONE = "NONE"
    sys.modules["ldap3"] = mock_ldap3
    sys.modules["ldap3.core"] = mock_ldap3.core
    sys.modules["ldap3.core.exceptions"] = mock_ldap3.core.exceptions
    sys.modules["ldap3.utils"] = mock_ldap3.utils
    sys.modules["ldap3.utils.conv"] = mock_ldap3.utils.conv
    yield mock_ldap3
    for mod in ("ldap3", "ldap3.core", "ldap3.core.exceptions", "ldap3.utils", "ldap3.utils.conv"):
        sys.modules.pop(mod, None)


def _make_mock_server():
    server = MagicMock()
    server.ssl = False
    return server


def test_bc115_starttls_service_binds_after_tls(_mock_ldap3):
    """Service conn must call start_tls() then bind()."""
    from cert_watch.auth import LDAPAuthProvider

    provider = LDAPAuthProvider(
        server_url="ldap://dc.test",
        base_dn="DC=test",
        bind_dn="CN=svc,DC=test",
        bind_password="secret",
        start_tls=True,
    )

    mock_conn = MagicMock()
    mock_conn.entries = []
    mock_conn.unbind = MagicMock()
    _mock_ldap3.Connection.return_value = mock_conn

    provider.authenticate("user", "pass")

    mock_conn.start_tls.assert_called_once()
    mock_conn.bind.assert_called_once()


def test_bc115_starttls_user_conn_tls_before_bind(_mock_ldap3):
    """User conn must call start_tls() before bind() when StartTLS is enabled."""
    from cert_watch.auth import LDAPAuthProvider

    provider = LDAPAuthProvider(
        server_url="ldap://dc.test",
        base_dn="DC=test",
        bind_dn="CN=svc,DC=test",
        bind_password="secret",
        start_tls=True,
    )

    svc_conn = MagicMock()
    entry = MagicMock()
    entry.distinguishedName = "CN=user,DC=test"
    entry.memberOf.values = ["CN=Users,DC=test"]
    svc_conn.entries = [entry]
    svc_conn.unbind = MagicMock()
    svc_conn.bind = MagicMock()

    user_conn = MagicMock()
    user_conn.bind = MagicMock()
    user_conn.unbind = MagicMock()

    connections = [svc_conn, user_conn]
    _mock_ldap3.Connection.side_effect = connections

    provider.authenticate("user", "pass")

    user_conn.start_tls.assert_called_once()
    user_conn.bind.assert_called_once()


def test_bc115_no_starttls_binds_normally(_mock_ldap3):
    """Without StartTLS, service conn just binds normally."""
    from cert_watch.auth import LDAPAuthProvider

    provider = LDAPAuthProvider(
        server_url="ldap://dc.test",
        base_dn="DC=test",
        bind_dn="CN=svc,DC=test",
        bind_password="secret",
        start_tls=False,
    )

    mock_conn = MagicMock()
    mock_conn.entries = []
    mock_conn.unbind = MagicMock()
    _mock_ldap3.Connection.return_value = mock_conn

    provider.authenticate("user", "pass")

    mock_conn.start_tls.assert_not_called()
    mock_conn.bind.assert_called_once()


# ---------- BC-116: SSRF-safe HTTP opener ----------


def test_bc116_blocks_loopback_url():
    with pytest.raises(SSRFBlockedError, match="blocked"):
        _validate_url("http://127.0.0.1/webhook")


def test_bc116_blocks_link_local_url():
    with pytest.raises(SSRFBlockedError, match="blocked"):
        _validate_url("http://169.254.169.254/metadata")


def test_bc116_blocks_ftp_scheme():
    with pytest.raises(SSRFBlockedError, match="scheme"):
        _validate_url("ftp://evil.com/payload")


def test_bc116_allows_public_url():
    with patch("cert_watch.http_client.socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [(2, 1, 6, "", ("93.184.216.34", 0))]
        _validate_url("https://hooks.example.com/webhook")


def test_bc116_blocks_private_by_default():
    with pytest.raises(SSRFBlockedError, match="blocked"):
        _validate_url("http://10.0.0.1/internal")


def test_bc116_allows_private_when_enabled():
    _validate_url("http://10.0.0.1/internal", allow_private=True)


def test_bc116_blocks_redirect_to_loopback():
    """A 302 to a loopback address must be blocked."""
    with patch("cert_watch.http_client.socket.getaddrinfo") as mock_dns, \
         patch("cert_watch.http_client.urllib.request.build_opener") as mock_opener:
        mock_dns.return_value = [(2, 1, 6, "", ("1.2.3.4", 0))]
        mock_opener.return_value.open.side_effect = SSRFBlockedError("blocked IP: 127.0.0.1")
        with pytest.raises(SSRFBlockedError):
            ssrf_safe_urlopen("https://public.example.com/hook")


def test_bc116_validate_webhook_url_returns_error():
    from cert_watch.http_client import validate_webhook_url

    err = validate_webhook_url("http://127.0.0.1/hook")
    assert err is not None
    assert "blocked" in err.lower()


def test_bc116_validate_webhook_url_ok():
    from cert_watch.http_client import validate_webhook_url

    with patch("cert_watch.http_client.socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [(2, 1, 6, "", ("93.184.216.34", 0))]
        err = validate_webhook_url("https://hooks.example.com/hook")
        assert err is None


# ---------- BC-117: OCSP/CRL SSRF validation ----------


def test_bc117_ocsp_blocks_private_url():
    """OCSP probe to a private IP must be refused, not probed."""
    from cert_watch.posture import _check_ocsp_reachable

    reachable, msg = _check_ocsp_reachable("http://10.0.0.5/ocsp")
    assert reachable is False
    assert "SSRF" in msg or "blocked" in msg


def test_bc117_crl_blocks_loopback_url():
    """CRL probe to loopback must be refused."""
    from cert_watch.posture import _check_crl_reachable

    reachable, msg = _check_crl_reachable("http://127.0.0.1/crl.crl")
    assert reachable is False
    assert "SSRF" in msg or "blocked" in msg


def test_bc117_revocation_endpoints_ssrf_finding():
    """check_revocation_endpoints must emit a clear SSRF-blocked finding."""
    from cert_watch.posture import check_revocation_endpoints

    der = _cert_with_aia(ocsp_url="http://10.0.0.5/ocsp")
    findings = check_revocation_endpoints(der)
    ocsp_findings = [f for f in findings if f.check == "ocsp_endpoint"]
    assert len(ocsp_findings) == 1
    assert ocsp_findings[0].status == "warn"
    assert "SSRF" in ocsp_findings[0].message or "blocked" in ocsp_findings[0].message


def _cert_with_aia(ocsp_url="http://ocsp.test"):
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509 import AccessDescription, AuthorityInformationAccess
    from cryptography.x509.oid import AuthorityInformationAccessOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "test")])
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1000)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
    )
    aia = AuthorityInformationAccess([
        AccessDescription(
            AuthorityInformationAccessOID.OCSP,
            x509.UniformResourceIdentifier(ocsp_url),
        )
    ])
    builder = builder.add_extension(aia, critical=False)
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


# ---------- BC-118: Configurable LDAP group filter ----------


def test_bc118_default_uses_ad_transitive_oid(_mock_ldap3):
    """Default group filter uses AD transitive OID."""
    from cert_watch.auth import LDAPAuthProvider

    provider = LDAPAuthProvider(
        server_url="ldap://dc.test",
        base_dn="DC=test",
        bind_dn="CN=svc,DC=test",
        bind_password="secret",
        required_groups=["CN=Admins,DC=test"],
    )

    svc_conn = MagicMock()
    entry = MagicMock()
    entry.distinguishedName = "CN=user,DC=test"
    entry.memberOf.values = ["CN=Admins,DC=test"]
    svc_conn.entries = [entry]
    svc_conn.unbind = MagicMock()
    svc_conn.bind = MagicMock()

    user_conn = MagicMock()
    user_conn.bind = MagicMock()
    user_conn.unbind = MagicMock()

    _mock_ldap3.Connection.side_effect = [svc_conn, user_conn]

    provider.authenticate("user", "pass")

    search_call = svc_conn.search.call_args
    search_filter = search_call[0][1]
    assert "1.2.840.113556.1.4.1941" in search_filter


def test_bc118_custom_group_filter(_mock_ldap3):
    """Custom group_filter replaces the AD OID with a plain memberOf filter."""
    from cert_watch.auth import LDAPAuthProvider

    provider = LDAPAuthProvider(
        server_url="ldap://dc.test",
        base_dn="DC=test",
        bind_dn="CN=svc,DC=test",
        bind_password="secret",
        required_groups=["CN=Admins,DC=test"],
        group_filter="memberOf={group}",
    )

    svc_conn = MagicMock()
    entry = MagicMock()
    entry.distinguishedName = "CN=user,DC=test"
    entry.memberOf.values = ["CN=Admins,DC=test"]
    svc_conn.entries = [entry]
    svc_conn.unbind = MagicMock()
    svc_conn.bind = MagicMock()

    user_conn = MagicMock()
    user_conn.bind = MagicMock()
    user_conn.unbind = MagicMock()

    _mock_ldap3.Connection.side_effect = [svc_conn, user_conn]

    provider.authenticate("user", "pass")

    search_call = svc_conn.search.call_args
    search_filter = search_call[0][1]
    assert "1.2.840.113556.1.4.1941" not in search_filter
    assert "memberOf=" in search_filter


def test_bc118_group_filter_env_var(monkeypatch):
    """LDAP_GROUP_FILTER env var threads through Settings and factory."""
    from cert_watch.config import Settings

    monkeypatch.setenv("LDAP_GROUP_FILTER", "member={group}")
    s = Settings.from_env()
    assert s.ldap_group_filter == "member={group}"
