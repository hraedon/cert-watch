"""Run the documented renewal hook examples against a live local app."""

from __future__ import annotations

import os
import socket
import subprocess
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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
from cert_watch.renewal_verification import evaluate_after_scan
from cert_watch.security import SecurityContext
from tests._helpers import seed_scanned
from tests.conftest import GeneratedCert, _make_cert

EXAMPLES = Path(__file__).parents[1] / "docs" / "examples" / "renewal-reports"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture
def renewal_report_server(tmp_path: Path) -> Iterator[tuple[str, Path, str, Settings]]:
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
        yield f"http://127.0.0.1:{port}", db, raw_key, settings
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


@contextmanager
def _http_status(status: int) -> Iterator[str]:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            body = b'{"error":"simulated rejection"}'
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            with suppress(BrokenPipeError, ConnectionResetError):
                self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_documented_hook_examples_store_expected_reports(
    renewal_report_server: tuple[str, Path, str, Settings],
    tmp_path: Path,
    self_signed_leaf: GeneratedCert,
) -> None:
    base_url, db, raw_key, _settings = renewal_report_server
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
    skipped_acme = _run("acme-renew.sh", {**wrapper_env, "FAKE_ACME_STATUS": "2"})
    assert "ACME_DOMAIN may not exactly name an issued certificate" in skipped_acme.stderr

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


@pytest.mark.parametrize("client", ["certbot", "acme"])
def test_saved_hooks_create_a_new_correlation_for_each_cycle(
    renewal_report_server: tuple[str, Path, str, Settings],
    tmp_path: Path,
    self_signed_leaf: GeneratedCert,
    client: str,
) -> None:
    base_url, db, raw_key, settings = renewal_report_server
    key_file = tmp_path / f"{client}-report.key"
    key_file.write_text(f"{raw_key}\n", encoding="utf-8")
    key_file.chmod(0o600)
    state_dir = tmp_path / f"{client}-state"
    pem = tmp_path / f"{client}-renewed.pem"
    pem.write_bytes(self_signed_leaf.pem)
    env = {
        **os.environ,
        "CW_BASE_URL": base_url,
        "CW_RENEWAL_REPORT_KEY_FILE": str(key_file),
        "CW_REPORT_SCRIPT": str(EXAMPLES / "cw-report.sh"),
        "CW_RENEWAL_STATE_DIR": str(state_dir),
        "CW_HOST": f"{client}.example.test",
        "CW_PORT": "443",
    }
    env.pop("CW_CORRELATION_ID", None)
    if client == "certbot":
        env.update(
            RENEWED_LINEAGE=str(tmp_path),
            RENEWED_DOMAINS="certbot.example.test",
        )
        (tmp_path / "cert.pem").write_bytes(self_signed_leaf.pem)
        pre_hook, terminal_hook = "certbot-pre-hook.sh", "certbot-deploy-hook.sh"
    else:
        env.update(Le_Domain="acme.example.test", CERT_PATH=str(pem))
        pre_hook, terminal_hook = "acme-pre-hook.sh", "acme-renew-hook.sh"

    def run_cycle() -> None:
        _run(pre_hook, env)
        state_files = list(state_dir.glob("*.correlation"))
        assert state_dir.stat().st_mode & 0o777 == 0o700
        assert len(state_files) == 1
        assert state_files[0].stat().st_mode & 0o777 == 0o600
        _run(terminal_hook, env)
        assert list(state_dir.glob("*.correlation")) == []

    run_cycle()
    with _connect(db) as conn:
        first = conn.execute(
            """SELECT attempt_id,correlation_id,new_fingerprint,
                      success_received_at
               FROM renewal_attempts a
               JOIN renewal_attempt_correlations c USING (attempt_id)
               WHERE a.host_id=(SELECT id FROM hosts WHERE hostname=? AND port=443)""",
            (f"{client}.example.test",),
        ).fetchone()
    assert first is not None
    first_success = datetime.fromisoformat(str(first["success_received_at"]))
    evaluate_after_scan(
        db,
        f"{client}.example.test",
        443,
        str(first["new_fingerprint"]),
        started_at=first_success + timedelta(minutes=1),
        settings=settings,
    )

    run_cycle()
    with _connect(db) as conn:
        attempts = conn.execute(
            """SELECT a.attempt_id,a.state,a.baseline_fingerprint,
                      a.success_received_at,c.correlation_id
               FROM renewal_attempts a
               JOIN renewal_attempt_correlations c USING (attempt_id)
               WHERE a.host_id=(SELECT id FROM hosts WHERE hostname=? AND port=443)
               ORDER BY a.opened_seq""",
            (f"{client}.example.test",),
        ).fetchall()
    assert len(attempts) == 2
    assert attempts[0]["attempt_id"] != attempts[1]["attempt_id"]
    assert attempts[0]["correlation_id"] != attempts[1]["correlation_id"]
    second_success = datetime.fromisoformat(str(attempts[1]["success_received_at"]))
    result = evaluate_after_scan(
        db,
        f"{client}.example.test",
        443,
        str(attempts[1]["baseline_fingerprint"]),
        started_at=second_success + timedelta(hours=25),
        settings=settings,
    )
    assert result is not None and result.state == "not_deployed"


@pytest.mark.parametrize("response", ["unreachable", "429", "422"])
@pytest.mark.parametrize("renewal_status", [0, 7])
def test_acme_reporting_failure_never_changes_renewal_outcome(
    tmp_path: Path,
    self_signed_leaf: GeneratedCert,
    response: str,
    renewal_status: int,
) -> None:
    key_file = tmp_path / "report.key"
    key_file.write_text("cwk_test-only\n", encoding="utf-8")
    pem = tmp_path / "renewed.pem"
    pem.write_bytes(self_signed_leaf.pem)
    fake_acme = tmp_path / "fake-acme"
    fake_acme.write_text(
        """#!/bin/sh
"$FAKE_PRE_HOOK"
status=${FAKE_ACME_STATUS:-0}
if [ "$status" -eq 0 ]; then "$FAKE_RENEW_HOOK"; fi
exit "$status"
""",
        encoding="utf-8",
    )
    fake_acme.chmod(0o755)

    def exercise(base_url: str) -> None:
        env = {
            **os.environ,
            "CW_BASE_URL": base_url,
            "CW_REPORT_TIMEOUT_SECONDS": "1",
            "CW_RENEWAL_REPORT_KEY_FILE": str(key_file),
            "CW_REPORT_SCRIPT": str(EXAMPLES / "cw-report.sh"),
            "CW_RENEWAL_STATE_DIR": str(tmp_path / "state"),
            "ACME_DOMAIN": "acme.example.test",
            "ACME_SH_BIN": str(fake_acme),
            "Le_Domain": "acme.example.test",
            "CERT_PATH": str(pem),
            "FAKE_PRE_HOOK": str(EXAMPLES / "acme-pre-hook.sh"),
            "FAKE_RENEW_HOOK": str(EXAMPLES / "acme-renew-hook.sh"),
            "FAKE_ACME_STATUS": str(renewal_status),
        }
        completed = _run("acme-renew.sh", env, check=False)
        assert completed.returncode == renewal_status
        assert "renewal continues" in completed.stderr

    if response == "unreachable":
        exercise(f"http://127.0.0.1:{_free_port()}")
    else:
        with _http_status(int(response)) as base_url:
            exercise(base_url)


@pytest.mark.parametrize("renewal_status", [0, 9])
def test_certbot_reporting_failure_never_changes_renewal_outcome(
    tmp_path: Path,
    renewal_status: int,
) -> None:
    fake_certbot = tmp_path / "fake-certbot"
    fake_certbot.write_text(
        """#!/bin/sh
set -u
pre=
deploy=
while [ "$#" -gt 0 ]; do
  case $1 in
    --pre-hook) pre=$2; shift 2 ;;
    --deploy-hook) deploy=$2; shift 2 ;;
    *) shift ;;
  esac
done
"$pre"
status=${FAKE_CERTBOT_STATUS:-0}
if [ "$status" -eq 0 ]; then
  RENEWED_LINEAGE=$FAKE_LINEAGE RENEWED_DOMAINS=certbot.example.test "$deploy"
fi
exit "$status"
""",
        encoding="utf-8",
    )
    fake_certbot.chmod(0o755)
    env = {
        **os.environ,
        "CW_REPORT_SCRIPT": "/bin/false",
        "CW_RENEWAL_STATE_DIR": str(tmp_path / "state"),
        "CERTBOT_CERT_NAME": "certbot.example.test",
        "CERTBOT_BIN": str(fake_certbot),
        "FAKE_CERTBOT_STATUS": str(renewal_status),
        "FAKE_LINEAGE": str(tmp_path),
    }
    completed = _run("certbot-renew.sh", env, check=False)
    assert completed.returncode == renewal_status
    assert "renewal continues" in completed.stderr


def test_helper_escapes_config_key_and_unsets_its_environment_copy(
    tmp_path: Path,
) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    capture = tmp_path / "curl.conf"
    fake_curl = fake_bin / "curl"
    fake_curl.write_text(
        """#!/bin/sh
set -eu
config=
output=
while [ "$#" -gt 0 ]; do
  case $1 in
    --config) config=$2; shift 2 ;;
    --output) output=$2; shift 2 ;;
    --write-out) shift 2 ;;
    *) shift ;;
  esac
done
[ -z "${CW_RENEWAL_REPORT_KEY:-}" ]
cp "$config" "$FAKE_CURL_CAPTURE"
printf '%s' '{}' >"$output"
printf '%s' 202
""",
        encoding="utf-8",
    )
    fake_curl.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "CW_BASE_URL": "https://unused.example.test",
        "CW_RENEWAL_REPORT_KEY": 'cwk_a"b\\c',
        "FAKE_CURL_CAPTURE": str(capture),
    }
    _run(
        "cw-report.sh",
        env,
        "started",
        "--host",
        "plain.example.test",
        "--port",
        "443",
    )
    assert capture.read_text(encoding="utf-8") == (
        'header = "Authorization: Bearer cwk_a\\"b\\\\c"\n'
    )
