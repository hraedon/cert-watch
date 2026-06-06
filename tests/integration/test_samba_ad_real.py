"""End-to-end integration test with a real Samba-AD DC container.

This test spins up a Samba-AD DC using Docker, then drives
``LDAPAuthProvider`` and ``Settings.from_env`` against it over real LDAP.

Three bugs that previously escaped unit tests are caught here:
1. ``use_ssl=`` passed to ``ldap3.Connection`` (real ldap3 rejects it)
2. ``Path.is_file()`` on inline PEM raises ``OSError(ENAMETOOLONG)``
3. Comma-split on ``LDAP_REQUIRED_GROUPS`` shreds comma-bearing DNs

These tests are marked ``integration`` and are excluded from the fast unit run.
They require Docker and are run as a separate CI job.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import time

import pytest

from cert_watch.auth.ldap_provider import LDAPAuthProvider
from cert_watch.config import Settings

pytestmark = pytest.mark.integration

SKIPPED_REASON = "Docker unavailable or Samba-AD container not reachable"


def _docker_available() -> bool:
    """Check if Docker daemon is reachable."""
    try:
        subprocess.run(
            ["docker", "version"], capture_output=True, timeout=5, check=True
        )
        return True
    except Exception:
        return False


def _create_samba_container(image: str, realm: str, domain: str, adminpass: str) -> str:
    """Provision a Samba AD DC with SYS_ADMIN capability.

    Uses a custom inline entrypoint that provisions, seeds users/groups
    via samba-tool, configures 'ldap server require strong auth = no', then
    starts Samba in the foreground.
    """
    setup_script = f"""#!/bin/bash
set -e
if [ ! -f /var/lib/samba/private/sam.ldb ]; then
    echo "Provisioning domain..."
    samba-tool domain provision \
      --use-rfc2307 \
      --realm={realm} \
      --domain={domain} \
      --adminpass={adminpass} \
      --server-role=dc \
      --dns-backend=SAMBA_INTERNAL
    samba-tool domain passwordsettings set \\
      --complexity=off --min-pwd-age=0 --max-pwd-age=0 \\
      --min-pwd-length=6 --store-plaintext=on
    SMB_CONF="/etc/samba/smb.conf"
    sed -i '/^\\[global\\]/a\\        ldap server require strong auth = no' "$SMB_CONF" || true
fi
# Seed users/groups every start (idempotent -- samba-tool create fails if exists)
samba-tool user create cw-admin {adminpass} 2>/dev/null || true
samba-tool user create cw-user {adminpass} 2>/dev/null || true
samba-tool user create cw-outcast {adminpass} 2>/dev/null || true
samba-tool group add cert-watch-admins 2>/dev/null || true
samba-tool group add cert-watch-users 2>/dev/null || true
samba-tool group addmembers cert-watch-admins cw-admin 2>/dev/null || true
samba-tool group addmembers cert-watch-users cw-user 2>/dev/null || true
exec samba -i -M single
"""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
        f.write(setup_script)
        script_path = f.name

    cmd = [
        "docker", "run", "-d", "--rm",
        "--cap-add", "SYS_ADMIN",
        "--security-opt", "apparmor=unconfined",
        "-e", f"REALM={realm}",
        "-e", f"DOMAIN={domain}",
        "-e", f"ADMINPASS={adminpass}",
        "-p", "0:636", "-p", "0:389",
        "-v", f"{script_path}:/opt/run.sh:ro",
        "--entrypoint", "bash",
        image,
        "/opt/run.sh",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    container_id = result.stdout.strip()
    os.unlink(script_path)
    return container_id


def _get_container_ports(container_id: str) -> tuple[int, int]:
    """Return (ldap_port, ldaps_port) mapped to host."""
    result = subprocess.run(
        ["docker", "port", container_id],
        capture_output=True, text=True, check=True,
    )
    ports: dict[int, int] = {}
    for line in result.stdout.splitlines():
        parts = line.strip().split(" -> ")
        if len(parts) == 2:
            container_port = int(parts[0].split("/")[0])
            host_bind = parts[1].split(":")[-1]
            ports[container_port] = int(host_bind)
    return ports.get(389, 0), ports.get(636, 0)


def _stop_container(container_id: str) -> None:
    subprocess.run(["docker", "kill", container_id], capture_output=True)


def _wait_ldap(port: int, timeout: int = 120) -> bool:
    """Return True once an LDAP bind against Samba succeeds."""
    import socket

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
                # Send a minimal LDAP bind request to verify Samba is accepting binds
                sock.sendall(
                    b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00"
                )
                resp = sock.recv(1024)
                if b"\x02\x01\x01" in resp:
                    return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


@pytest.fixture(scope="module")
def samba_ad():
    """Yield a SambaADFixture with a running container.

    Skips cleanly when Docker is unavailable.
    """
    if not _docker_available():
        pytest.skip(SKIPPED_REASON)

    pytest.importorskip("cryptography")
    pytest.importorskip("ldap3")

    # Generate a self-signed CA for use in tests (wrong-ca test needs one)
    ca_pem, _, _ = _make_ca_cert()

    realm = "CW.TEST"
    domain = "CW"
    adminpass = "Test1234!"
    base_dn = "DC=CW,DC=TEST"

    image = (
        "docker.io/mnorsic/samba-ad"
        "@sha256:4a7f7cc221064d13a52fd5ce3ac665b2d72892fa070b1f73b9440bf62531e88f"
    )

    c_id = _create_samba_container(image, realm, domain, adminpass)
    ldap_port, ldaps_port = _get_container_ports(c_id)

    if not _wait_ldap(ldap_port, timeout=120):
        _stop_container(c_id)
        raise RuntimeError(f"LDAP on port {ldap_port} never became ready")

    bind_dn = f"CN=Administrator,CN=Users,{base_dn}"

    class _Fixture:
        def __init__(self):
            self.ldap_port = ldap_port
            self.ldaps_port = ldaps_port
            self.ca_cert_pem = ca_pem
            self.base_dn = base_dn
            self.admin_username = "Administrator"
            self.admin_password = adminpass
            self.bind_dn = bind_dn
            self._container_id = c_id

        @property
        def ldaps_uri(self) -> str:
            return f"ldaps://127.0.0.1:{self.ldaps_port}"

        @property
        def ldap_uri(self) -> str:
            return f"ldap://127.0.0.1:{self.ldap_port}"

    fixture = _Fixture()
    yield fixture
    _stop_container(c_id)


def _make_ca_cert() -> tuple[str, str, str]:
    """Generate a self-signed CA + key, return (ca_pem, key_pem, cert_pem).

    Returns inline PEM strings so tests exercise the ``ca_cert=`` inline path
    that previously broke with ``Path.is_file()`` → ``OSError(ENAMETOOLONG)``.
    """
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(x509.NameOID.COMMON_NAME, "cert-watch-test-ca")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=30))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    ca_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return ca_pem, key_pem, ca_pem


class Test_LDAPAuthProvider_Integration:
    def test_inline_pem_ca_plain_ldap_bind_succeeds(self, samba_ad):
        """Inline PEM CA with plain ldap:// must succeed (catches bug #2).

        The ``ca_cert`` argument triggers the ``_resolve_ca_cert`` path.
        When it contains inline PEM, a previous bug made ``Path.is_file()``
        raise ``OSError(ENAMETOOLONG)`` instead of returning None.

        Bug #1 (``use_ssl=``) is also implicitly guarded: real ``ldap3``
        rejects ``use_ssl`` on ``Connection``, while our code does not pass it.
        This test passes when the library boundary is correct.
        """
        provider = LDAPAuthProvider(
            server_url=samba_ad.ldap_uri,
            base_dn=samba_ad.base_dn,
            bind_dn=samba_ad.bind_dn,
            bind_password=samba_ad.admin_password,
            user_search_filter="(sAMAccountName={username})",
            start_tls=False,
            ca_cert=samba_ad.ca_cert_pem,
            required_groups=[],
        )
        result = provider.authenticate("cw-admin", "Test1234!")
        assert result.success, f"Expected success, got: {result.error}"

    def test_user_not_in_required_group_fails(self, samba_ad):
        """cw-user is not in cert-watch-admins → denied."""
        provider = LDAPAuthProvider(
            server_url=samba_ad.ldap_uri,
            base_dn=samba_ad.base_dn,
            bind_dn=samba_ad.bind_dn,
            bind_password=samba_ad.admin_password,
            user_search_filter="(sAMAccountName={username})",
            start_tls=False,
            ca_cert=samba_ad.ca_cert_pem,
            required_groups=[
                f"CN=cert-watch-admins,CN=Users,{samba_ad.base_dn}",
            ],
        )
        result = provider.authenticate("cw-user", "Test1234!")
        assert not result.success
        assert "group" in result.error.lower() or "not found" in result.error.lower()

    def test_wrong_ca_rejected(self, samba_ad):
        """A mismatched CA must fail TLS validation under STARTTLS."""
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        wrong_subj = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "other-ca")])
        wrong_ca = (
            x509.CertificateBuilder()
            .subject_name(wrong_subj)
            .issuer_name(wrong_subj)
            .public_key(wrong_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1))
            .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(wrong_key, hashes.SHA256())
            .public_bytes(serialization.Encoding.PEM)
            .decode()
        )
        provider = LDAPAuthProvider(
            server_url=samba_ad.ldap_uri,
            base_dn=samba_ad.base_dn,
            bind_dn=samba_ad.bind_dn,
            bind_password=samba_ad.admin_password,
            user_search_filter="(sAMAccountName={username})",
            start_tls=True,
            ca_cert=wrong_ca,
            required_groups=[],
        )
        result = provider.authenticate("cw-admin", "Test1234!")
        assert not result.success


class Test_LdapLoginViaSettings:
    def test_env_parse_to_successful_login(self, samba_ad, monkeypatch, tmp_path):
        """Full parse → provider → login via Settings.from_env."""
        monkeypatch.setenv("AUTH_PROVIDER", "ldap")
        monkeypatch.setenv("LDAP_SERVER", samba_ad.ldap_uri)
        monkeypatch.setenv("LDAP_BASE_DN", samba_ad.base_dn)
        monkeypatch.setenv("LDAP_BIND_DN", samba_ad.bind_dn)
        monkeypatch.setenv("LDAP_BIND_PASSWORD", samba_ad.admin_password)
        monkeypatch.setenv("LDAP_CA_CERT", samba_ad.ca_cert_pem)
        monkeypatch.setenv(
            "LDAP_REQUIRED_GROUPS",
            f"CN=cert-watch-admins,CN=Users,{samba_ad.base_dn}",
        )
        monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
        monkeypatch.setenv("CERT_WATCH_ALLOW_UNAUTH", "1")

        settings = Settings.from_env()
        provider = settings.build_auth_provider()
        result = provider.authenticate("cw-admin", "Test1234!")
        assert result.success, f"Expected success: {result.error}"

    def test_required_groups_semicolon_split(self, samba_ad, monkeypatch, tmp_path):
        """Semicolon-separated group DNs must be parsed correctly."""
        g1 = f"CN=cert-watch-admins,CN=Users,{samba_ad.base_dn}"
        g2 = f"CN=cert-watch-users,CN=Users,{samba_ad.base_dn}"
        monkeypatch.setenv("AUTH_PROVIDER", "ldap")
        monkeypatch.setenv("LDAP_SERVER", samba_ad.ldap_uri)
        monkeypatch.setenv("LDAP_BASE_DN", samba_ad.base_dn)
        monkeypatch.setenv("LDAP_BIND_DN", samba_ad.bind_dn)
        monkeypatch.setenv("LDAP_BIND_PASSWORD", samba_ad.admin_password)
        monkeypatch.setenv("LDAP_CA_CERT", samba_ad.ca_cert_pem)
        monkeypatch.setenv("LDAP_REQUIRED_GROUPS", f"{g1};{g2}")
        monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
        monkeypatch.setenv("CERT_WATCH_ALLOW_UNAUTH", "1")

        settings = Settings.from_env()
        provider = settings.build_auth_provider()

        # cw-user is in group2
        result = provider.authenticate("cw-user", "Test1234!")
        assert result.success, f"Semicolon split failed: {result.error}"

        # cw-outcast is in neither → denied
        r2 = provider.authenticate("cw-outcast", "Test1234!")
        assert not r2.success
        assert "group" in r2.error.lower() or "not found" in r2.error.lower()
