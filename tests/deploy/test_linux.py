"""Linux/systemd smoke test: run the entrypoint directly in the built container.

This validates the ``cert-watch`` CLI entrypoint, the Python package install
inside the container, and the uvicorn startup path — without Docker networking
(host network mode) and without the Dockerfile HEALTHCHECK wrapper.
"""

from __future__ import annotations

import subprocess

import pytest

pytestmark = pytest.mark.deploy


@pytest.fixture()
def linux_container(docker_image, waiter):
    """Run cert-watch with host network (simulates bare-metal / systemd launch)."""
    port = 18891
    run = subprocess.run(
        [
            "docker", "run", "-d",
            "--name", "cw-linux-smoke",
            "--network", "host",
            "-e", f"CERT_WATCH_PORT={port}",
            "-e", "CERT_WATCH_ALLOW_UNAUTH=1",
            docker_image,
            "--host", "127.0.0.1",
            "--port", str(port),
        ],
        capture_output=True,
        text=True,
    )
    if run.returncode != 0:
        pytest.fail(f"docker run failed:\n{run.stderr}")
    cid = run.stdout.strip()
    w = waiter(f"http://127.0.0.1:{port}", timeout=60)
    yield cid, w
    subprocess.run(["docker", "logs", cid], capture_output=True, text=True)
    subprocess.run(["docker", "rm", "-f", cid], capture_output=True)


def test_entrypoint_serves_healthz(linux_container):
    cid, w = linux_container
    body = w.poll_healthy()
    assert body["status"] == "ok"


def test_entrypoint_serves_readyz(linux_container):
    cid, w = linux_container
    body = w.poll_ready()
    assert body["status"] == "ok"
    assert body.get("checks", {}).get("database") == "ok"
    assert body.get("checks", {}).get("scheduler") in ("running", "not running")


def test_cli_help(docker_image):
    """``cert-watch --help`` should print usage and exit 0."""
    r = subprocess.run(
        ["docker", "run", "--rm", docker_image, "--help"],
        capture_output=True, text=True,
    )
    assert r.returncode == 0
    assert "cert-watch" in r.stdout.lower()
