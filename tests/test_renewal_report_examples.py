"""Run the documented renewal hook examples against a live local app."""

from __future__ import annotations

import os
import socket
import subprocess
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
import uvicorn
from cryptography.hazmat.primitives import hashes

from cert_watch.auth import NoAuthProvider
from cert_watch.certificate_model import parse_certificate
from cert_watch.config import Settings
from cert_watch.database import SqliteHostRepository, init_schema
from cert_watch.database.api_keys import SqliteApiKeyRepository
from cert_watch.database.connection import _connect
from cert_watch.security import SecurityContext
from tests._helpers import seed_scanned
from tests.conftest import GeneratedCert, _make_cert

EXAMPLES = Path(__file__).parents[1] / "docs" / "examples" / "renewal-reports"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture
def renewal_report_server(tmp_path: Path) -> Iterator[tuple[str, Path, str]]:
    from cert_watch.app import create_app

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    repo = SqliteHostRepository(db)
    for hostname in ("plain.example.test", "certbot.example.test", "acme.example.test"):
        repo.add(hostname, 443, tags="production")
        leaf = _make_cert(hostname, days_valid=30)
        seed_scanned(db, hostname, 443, parse_certificate(leaf.der))

    secret = "renewal-hook-example-test-secret"
    security = SecurityContext(signing_key=secret, csrf_secret=f"{secret}-csrf")
    _entry, raw_key = SqliteApiKeyRepository(db, security=security).create_key(
        "hook-examples", "renewal-report", binding="all"
    )
    settings = Settings(
        db_path=db,
        data_dir=tmp_path,
        allow_unauth=True,
        bind_host="127.0.0.1",
        auth_secret=secret,
        csrf_secret=f"{secret}-csrf",
        cookie_secure=False,
    )
    app = create_app(
        settings=settings,
        security=security,
        auth_provider=NoAuthProvider(),
    )
    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.01)
    if not server.started:
        server.should_exit = True
        thread.join(timeout=2)
        pytest.fail("local cert-watch server did not start")
    try:
        yield f"http://127.0.0.1:{port}", db, raw_key
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        assert not thread.is_alive()


def _run(script: str, env: dict[str, str], *args: str, check: bool = True):
    return subprocess.run(
        [str(EXAMPLES / script), *args],
        check=check,
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )


def test_documented_hook_examples_store_expected_reports(
    renewal_report_server: tuple[str, Path, str],
    tmp_path: Path,
    self_signed_leaf: GeneratedCert,
) -> None:
    base_url, db, raw_key = renewal_report_server
    key_file = tmp_path / "renewal-report.key"
    key_file.write_text(f"{raw_key}\n", encoding="utf-8")
    key_file.chmod(0o600)
    pem = tmp_path / "renewed.pem"
    pem.write_bytes(self_signed_leaf.pem)

    env = {
        **os.environ,
        "CW_BASE_URL": base_url,
        "CW_RENEWAL_REPORT_KEY_FILE": str(key_file),
        "CW_REPORT_SCRIPT": str(EXAMPLES / "cw-report.sh"),
    }

    # The reusable helper covers all outcomes and derives the replacement
    # fingerprint from a PEM leaf.
    for outcome, extra in (
        ("started", ()),
        ("succeeded", ("--new-pem", str(pem))),
        ("failed", ("--message", "plain renewal failed")),
    ):
        _run(
            "cw-report.sh",
            env,
            outcome,
            "--host",
            "plain.example.test",
            "--port",
            "443",
            "--tool",
            "plain-hook",
            "--correlation",
            "plain-run",
            *extra,
        )

    refused = _run(
        "cw-report.sh",
        env,
        "started",
        "--host",
        "missing.example.test",
        "--port",
        "443",
        check=False,
    )
    assert refused.returncode != 0
    assert '"error":"endpoint not found"' in refused.stdout

    # Simulate Certbot invoking its hooks with RENEWED_LINEAGE and
    # RENEWED_DOMAINS, then simulate a failed renewal for the wrapper path.
    fake_certbot = tmp_path / "fake-certbot"
    fake_certbot.write_text(
        """#!/bin/sh
set -eu
pre=
deploy=
while [ \"$#\" -gt 0 ]; do
  case $1 in
    --pre-hook) pre=$2; shift 2 ;;
    --deploy-hook) deploy=$2; shift 2 ;;
    *) shift ;;
  esac
done
\"$pre\"
if [ \"${FAKE_CERTBOT_FAIL:-0}\" = 1 ]; then exit 9; fi
RENEWED_LINEAGE=$FAKE_LINEAGE RENEWED_DOMAINS=$FAKE_DOMAINS \"$deploy\"
""",
        encoding="utf-8",
    )
    fake_certbot.chmod(0o755)
    certbot_env = {
        **env,
        "CW_HOST": "certbot.example.test",
        "CW_PORT": "443",
        "CERTBOT_CERT_NAME": "certbot.example.test",
        "CERTBOT_BIN": str(fake_certbot),
        "FAKE_LINEAGE": str(tmp_path),
        "FAKE_DOMAINS": "certbot.example.test www.example.test",
    }
    (tmp_path / "cert.pem").write_bytes(self_signed_leaf.pem)
    _run("certbot-renew.sh", certbot_env)
    failed_certbot = _run(
        "certbot-renew.sh", {**certbot_env, "FAKE_CERTBOT_FAIL": "1"}, check=False
    )
    assert failed_certbot.returncode == 9

    # Simulate the variables acme.sh exports to pre/renew hooks. Its failure
    # wrapper must report an error, while exit 2 (not due) must report nothing.
    acme_env = {
        **env,
        "Le_Domain": "acme.example.test",
        "CERT_PATH": str(pem),
        "CW_PORT": "443",
        "CW_CORRELATION_ID": "acme-success",
    }
    _run("acme-pre-hook.sh", acme_env)
    _run("acme-renew-hook.sh", acme_env)
    fake_acme = tmp_path / "fake-acme"
    fake_acme.write_text("#!/bin/sh\nexit \"${FAKE_ACME_STATUS:-0}\"\n", encoding="utf-8")
    fake_acme.chmod(0o755)
    wrapper_env = {
        **env,
        "ACME_DOMAIN": "acme.example.test",
        "ACME_SH_BIN": str(fake_acme),
        "FAKE_ACME_STATUS": "7",
    }
    failed_acme = _run("acme-renew.sh", wrapper_env, check=False)
    assert failed_acme.returncode == 7
    _run("acme-renew.sh", {**wrapper_env, "FAKE_ACME_STATUS": "2"})

    with _connect(db) as conn:
        reports = [
            tuple(row)
            for row in conn.execute(
                """SELECT hostname_snapshot,outcome,tool,correlation_id,new_fingerprint
                   FROM renewal_reports ORDER BY seq"""
            )
        ]

    assert len(reports) == 10
    assert [row[1] for row in reports[:3]] == ["started", "succeeded", "failed"]
    assert reports[1][4] == self_signed_leaf.cert.fingerprint(hashes.SHA256()).hex()
    certbot_reports = [row for row in reports if row[0] == "certbot.example.test"]
    assert [row[1] for row in certbot_reports] == [
        "started",
        "succeeded",
        "started",
        "failed",
    ]
    assert {row[2] for row in certbot_reports} == {"certbot"}
    assert certbot_reports[0][3] == certbot_reports[1][3]
    assert certbot_reports[2][3] == certbot_reports[3][3]
    acme_reports = [row for row in reports if row[0] == "acme.example.test"]
    assert [row[1] for row in acme_reports] == ["started", "succeeded", "failed"]
    assert [row[2] for row in acme_reports] == ["acme.sh", "acme.sh", "acme.sh"]
