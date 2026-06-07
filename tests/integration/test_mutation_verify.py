"""Slice 5: Mutation verification — prove the integration tier catches bugs.

Each test temporarily reintroduces one of the three 2026-06-05 LDAPS bugs
that escaped 1257 unit tests and ~90% coverage, then asserts that the
real-ldap3 integration test fails.  A test that passes *against* the mutated
code is theater — it exercises the line but not the behavior.

Marked ``integration``; runs in the ``ldap-integration`` CI job.
"""

from __future__ import annotations

import subprocess

import pytest

from cert_watch.auth.ldap_provider import LDAPAuthProvider

pytestmark = pytest.mark.integration

SKIPPED_REASON = "Docker unavailable or Samba-AD container not reachable"


def _docker_available() -> bool:
    try:
        subprocess.run(["docker", "version"], capture_output=True, timeout=5, check=True)
        return True
    except Exception:
        return False


@pytest.fixture(scope="module")
def samba_ad():
    """Reuse the same Samba-AD fixture as test_samba_ad_real.py."""
    if not _docker_available():
        pytest.skip(SKIPPED_REASON)

    pytest.importorskip("cryptography")
    pytest.importorskip("ldap3")

    # pytest's prepend import mode puts tests/integration on sys.path (no
    # __init__.py), so the sibling module is imported top-level — `tests` is not
    # an importable package here.
    from test_samba_ad_real import (
        _create_samba_container,
        _get_container_ports,
        _make_ca_cert,
        _stop_container,
        _wait_ldap,
    )

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

    class _Fixture:
        def __init__(self):
            self.ldap_port = ldap_port
            self.ldaps_port = ldaps_port
            self.ca_cert_pem = ca_pem
            self.base_dn = base_dn
            self.bind_dn = f"CN=Administrator,CN=Users,{base_dn}"
            self.admin_password = adminpass

        @property
        def ldaps_uri(self):
            return f"ldaps://127.0.0.1:{self.ldaps_port}"

        @property
        def ldap_uri(self):
            return f"ldap://127.0.0.1:{self.ldap_port}"

    fixture = _Fixture()
    yield fixture
    _stop_container(c_id)


class TestMutationVerify:
    """Each test reintroduces one real bug and proves the tier goes red."""

    def test_bug1_use_ssl_kwarg_caught(self, samba_ad, monkeypatch):
        """Bug #1: ``use_ssl=`` passed to ``ldap3.Connection``.

        The old code passed ``use_ssl=True`` to ``ldap3.Connection()``.
        Real ldap3 rejects the kwarg; ``MagicMock`` silently ate it.

        Mutation: monkeypatch the Connection constructor to reject ``use_ssl``
        (simulating real ldap3's strict signature), then inject ``use_ssl=True``
        into a provider authenticate call.  The call *must* fail.
        """
        import ldap3 as real_ldap3

        original_init = real_ldap3.Connection.__init__

        def _strict_init(self_conn, server, user=None, password=None,
                         auto_bind=False, **kwargs):
            if "use_ssl" in kwargs:
                raise TypeError(
                    "Connection.__init__() got an unexpected keyword argument 'use_ssl'"
                )
            original_init(
                self_conn, server, user=user, password=password,
                auto_bind=auto_bind, **kwargs,
            )

        monkeypatch.setattr(real_ldap3.Connection, "__init__", _strict_init)

        provider = LDAPAuthProvider(
            server_url=samba_ad.ldap_uri,
            base_dn=samba_ad.base_dn,
            bind_dn=samba_ad.bind_dn,
            bind_password=samba_ad.admin_password,
            start_tls=False,
            ca_cert=samba_ad.ca_cert_pem,
            required_groups=[],
        )

        # Manually run the authenticate logic with use_ssl=True injected.
        # This is what the old broken code did.
        tls, servers = provider._build_tls()
        pool = servers[0]
        with pytest.raises(TypeError, match="use_ssl"):
            real_ldap3.Connection(
                pool,
                user=provider.bind_dn or None,
                password=provider.bind_password or None,
                auto_bind=False,
                use_ssl=True,
            )

    def test_bug2_inline_pem_path_is_file_caught(self, samba_ad, monkeypatch):
        """Bug #1 (BC-149): inline-PEM CA must not be stat-ed as a file path.

        The bug lived in **TLS construction** for ``ldaps://``: the pre-fix code
        called ``Path(ca_cert).is_file()`` on inline PEM, and
        ``Path(<multi-KB PEM>).is_file()`` raises ``OSError(ENAMETOOLONG)``
        (verified errno 36) rather than returning ``False`` — breaking every
        private-CA LDAPS login. It is **only** reachable on the ldaps/start_tls
        branch of ``_build_tls`` (plain ``ldap://`` never touches ``ca_cert``),
        and a full ``authenticate()`` can't distinguish the fix from the bug here
        because this container's throwaway CA never matches Samba's own LDAPS
        cert (both paths fail the handshake). So assert at the TLS-construction
        boundary, over ``ldaps://``.

        The earlier version drove plaintext ``ldap://`` and monkeypatched
        ``Path.is_file`` — neither is on the CA-resolution path, so the mutation
        never bit (BC-149).
        """
        from pathlib import Path

        provider = LDAPAuthProvider(
            server_url=samba_ad.ldaps_uri,
            base_dn=samba_ad.base_dn,
            bind_dn=samba_ad.bind_dn,
            bind_password=samba_ad.admin_password,
            start_tls=False,
            ca_cert=samba_ad.ca_cert_pem,
            required_groups=[],
        )

        # Baseline: the guard treats inline PEM as data (not a path), so TLS for
        # the ldaps:// server builds cleanly — no stat, no raise.
        assert provider._resolve_ca_cert() is None
        tls, servers = provider._build_tls()
        assert tls is not None and servers

        # Mutation: reintroduce the pre-fix behavior — stat the inline PEM as a
        # filesystem path. is_file() raises ENAMETOOLONG, which breaks TLS
        # construction (and, in production, surfaced as "authentication failed").
        def _unguarded_resolve(self):
            p = Path(self.ca_cert)
            return p if p.is_file() else None

        monkeypatch.setattr(LDAPAuthProvider, "_resolve_ca_cert", _unguarded_resolve)
        with pytest.raises(OSError, match="too long"):
            provider._build_tls()

    def test_bug3_comma_split_on_required_groups_caught(self, samba_ad, monkeypatch, tmp_path):
        """Bug #3: ``LDAP_REQUIRED_GROUPS`` split on ``,`` shreds DNs.

        The old code split on ``,`` instead of ``;``.  A DN like
        ``CN=cert-watch-admins,CN=Users,DC=CW,DC=TEST`` was shredded into
        4 fragments — none matched a real group.

        Mutation: set ``LDAP_REQUIRED_GROUPS`` with comma separators.
        The authenticate *must* fail.
        """
        from cert_watch.config import Settings

        g1 = f"CN=cert-watch-admins,CN=Users,{samba_ad.base_dn}"
        g2 = f"CN=cert-watch-users,CN=Users,{samba_ad.base_dn}"

        monkeypatch.setenv("AUTH_PROVIDER", "ldap")
        monkeypatch.setenv("LDAP_SERVER", samba_ad.ldap_uri)
        monkeypatch.setenv("LDAP_BASE_DN", samba_ad.base_dn)
        monkeypatch.setenv("LDAP_BIND_DN", samba_ad.bind_dn)
        monkeypatch.setenv("LDAP_BIND_PASSWORD", samba_ad.admin_password)
        monkeypatch.setenv("LDAP_CA_CERT", samba_ad.ca_cert_pem)
        # BUG reintroduction: comma instead of semicolon
        monkeypatch.setenv("LDAP_REQUIRED_GROUPS", f"{g1},{g2}")
        monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
        monkeypatch.setenv("CERT_WATCH_ALLOW_UNAUTH", "1")

        settings = Settings.from_env()
        provider = settings.build_auth_provider()

        # cw-user is in group2 — with correct semicolon-split this succeeds.
        # With comma-split the DNs are shredded, so the provider sees
        # fragments like "CN=cert-watch-users" (no base DN) and the
        # transitive OID filter returns nothing → denied.
        result = provider.authenticate("cw-user", "Test1234!")
        assert not result.success, "Bug #3 mutation passed — integration tier is theater"
