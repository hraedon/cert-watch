"""Docker smoke test: build the image, run it, verify /healthz and /readyz."""

from __future__ import annotations

import subprocess
import time

import pytest

pytestmark = pytest.mark.deploy


@pytest.fixture()
def docker_container(docker_image, waiter):
    """Start the container; yield (container_id, port, waiter); stop on teardown."""
    host_port = 18888
    run = subprocess.run(
        [
            "docker", "run", "-d",
            "--name", "cw-deploy-smoke",
            "-p", f"127.0.0.1:{host_port}:8000",
            "-e", "CERT_WATCH_ALLOW_UNAUTH=1",
            docker_image,
        ],
        capture_output=True,
        text=True,
    )
    if run.returncode != 0:
        pytest.fail(f"docker run failed:\n{run.stderr}")
    cid = run.stdout.strip()
    w = waiter(f"http://127.0.0.1:{host_port}", timeout=60)
    yield cid, w
    subprocess.run(["docker", "logs", cid], capture_output=True, text=True)
    subprocess.run(["docker", "rm", "-f", cid], capture_output=True)


def test_healthz_returns_ok(docker_container):
    cid, w = docker_container
    body = w.poll_healthy()
    assert body["status"] == "ok", f"unexpected healthz body: {body}"


def test_readyz_returns_ok(docker_container):
    cid, w = docker_container
    body = w.poll_ready()
    assert body["status"] == "ok", f"unexpected readyz body: {body}"
    assert body.get("checks", {}).get("database") == "ok"
    assert body.get("checks", {}).get("scheduler") in ("running", "not running")


def test_docker_healthcheck_passes(docker_container):
    cid, w = docker_container
    w.poll_healthy()
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        check = subprocess.run(
            ["docker", "inspect",
             "--format", "{{.State.Health.Status}}", cid],
            capture_output=True, text=True,
        )
        status = check.stdout.strip()
        if status == "healthy":
            return
        if status == "unhealthy":
            logs = subprocess.run(
                ["docker", "inspect", "--format",
                 "{{range .State.Health.Log}}{{.Output}}{{end}}", cid],
                capture_output=True, text=True,
            )
            pytest.fail(f"Container unhealthy: {logs.stdout}")
        time.sleep(5)
    pytest.fail("Container did not become healthy within 90s")
