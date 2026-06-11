"""E2E: Synthetic LDAP login via Samba-AD container (WI-A.3, Plan 047).

Spins up a Samba-AD DC in Docker (same image as the integration tests),
then boots cert-watch with ``AUTH_PROVIDER=ldap`` and drives the login
form through Playwright.

Marked ``@pytest.mark.integration`` so they run in the integration CI job
but not the default e2e job.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import time
from types import SimpleNamespace

import pytest

pytest.importorskip("playwright")
from playwright.sync_api import expect  # noqa: E402

pytestmark = [pytest.mark.e2e, pytest.mark.integration]

SKIPPED_REASON = "Docker unavailable or Samba-AD container not reachable"


def _docker_available() -> bool:
    try:
        subprocess.run(
            ["docker", "version"], capture_output=True, timeout=5, check=True,
        )
        return True
    except Exception:
        return False


def _create_samba_container(image: str, realm: str, domain: str, adminpass: str) -> str:
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
    sed -i '/^\\[global\\]/a\\        ldap server require strong auth = no' "$SMB_CONF"
fi
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
        "-p", "0:389",
        "-v", f"{script_path}:/opt/run.sh:ro",
        "--entrypoint", "bash",
        image,
        "/opt/run.sh",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    container_id = result.stdout.strip()
    os.unlink(script_path)
    return container_id


def _get_ldap_port(container_id: str) -> int:
    result = subprocess.run(
        ["docker", "port", container_id, "389/tcp"],
        capture_output=True, text=True, check=True,
    )
    host_bind = result.stdout.strip().split(":")[-1]
    return int(host_bind)


def _wait_ldap(port: int, timeout: int = 120) -> bool:
    import socket

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
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


def _stop_container(container_id: str) -> None:
    subprocess.run(["docker", "kill", container_id], capture_output=True)


@pytest.fixture(scope="module")
def samba_ldap_e2e():
    if not _docker_available():
        pytest.skip(SKIPPED_REASON)

    pytest.importorskip("ldap3")

    realm = "CW.TEST"
    domain = "CW"
    adminpass = "Test1234!"
    base_dn = "DC=CW,DC=TEST"
    bind_dn = f"CN=Administrator,CN=Users,{base_dn}"

    image = (
        "docker.io/mnorsic/samba-ad"
        "@sha256:4a7f7cc221064d13a52fd5ce3ac665b2d72892fa070b1f73b9440bf62531e88f"
    )

    c_id = _create_samba_container(image, realm, domain, adminpass)
    try:
        ldap_port = _get_ldap_port(c_id)
        if not _wait_ldap(ldap_port):
            raise RuntimeError(f"LDAP on port {ldap_port} never became ready")

        # NB: a plain class body can't self-assign from enclosing-function
        # locals (`ldap_port = ldap_port` raises NameError — class scopes skip
        # the function scope on the RHS), so build the fixture object instead.
        yield SimpleNamespace(
            ldap_port=ldap_port,
            base_dn=base_dn,
            bind_dn=bind_dn,
            admin_password=adminpass,
            ldap_uri=f"ldap://127.0.0.1:{ldap_port}",
        )
    finally:
        _stop_container(c_id)


@pytest.fixture(scope="module")
def ldap_cert_watch_server(samba_ldap_e2e, tmp_path_factory):
    from _helpers import boot_server

    data_dir = tmp_path_factory.mktemp("cw-ldap-e2e-data")
    proc, base = boot_server(data_dir, env_extra={
        "AUTH_PROVIDER": "ldap",
        "LDAP_SERVER": samba_ldap_e2e.ldap_uri,
        "LDAP_BASE_DN": samba_ldap_e2e.base_dn,
        "LDAP_BIND_DN": samba_ldap_e2e.bind_dn,
        "LDAP_BIND_PASSWORD": samba_ldap_e2e.admin_password,
        "LDAP_USER_SEARCH_FILTER": "(sAMAccountName={username})",
        "LDAP_REQUIRED_GROUPS": (
            "CN=cert-watch-admins,CN=Users,DC=CW,DC=TEST;"
            "CN=cert-watch-users,CN=Users,DC=CW,DC=TEST"
        ),
        "CERT_WATCH_ALLOW_UNAUTH": "0",
        "CERT_WATCH_COOKIE_SECURE": "0",
    })
    try:
        yield base
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_valid_ldap_login(
    page, ldap_cert_watch_server: str, samba_ldap_e2e,
) -> None:
    page.goto(f"{ldap_cert_watch_server}/login")
    page.get_by_test_id("login-username").fill("cw-admin")
    page.get_by_test_id("login-password").fill(samba_ldap_e2e.admin_password)
    page.get_by_test_id("login-submit-btn").click()
    page.wait_for_url("**/*", timeout=10000)
    assert "Certificates" in page.inner_text("body") or "dashboard-heading" in page.content()


def test_wrong_password_shows_error(
    page, ldap_cert_watch_server: str, samba_ldap_e2e,
) -> None:
    page.goto(f"{ldap_cert_watch_server}/login")
    page.get_by_test_id("login-username").fill("cw-admin")
    page.get_by_test_id("login-password").fill("wrong-password")
    page.get_by_test_id("login-submit-btn").click()
    expect(page.locator("body")).to_contain_text("invalid credentials", timeout=5000)


def test_user_not_in_group_rejected(
    page, ldap_cert_watch_server: str, samba_ldap_e2e,
) -> None:
    page.goto(f"{ldap_cert_watch_server}/login")
    page.get_by_test_id("login-username").fill("cw-outcast")
    page.get_by_test_id("login-password").fill(samba_ldap_e2e.admin_password)
    page.get_by_test_id("login-submit-btn").click()
    expect(page.locator("body")).to_contain_text(
        "user not found or not in required group(s)", timeout=5000
    )
