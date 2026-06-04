"""Shared fixtures for deploy smoke tests.

Builds the Docker image once per session and provides helpers for polling
the health endpoints.  All three platforms (Docker, k8s, Linux entrypoint)
share the same image-build fixture so the total session cost is one build.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
import urllib.error
import urllib.request

import pytest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
IMAGE_NAME = "cert-watch-deploy-test"
HEALTHZ_PATH = "/healthz"
READYZ_PATH = "/readyz"


@pytest.fixture(scope="session")
def docker_image():
    """Build the Docker image from the project root; returns the image tag.

    Skips the session if Docker is unavailable or the build fails.
    """
    try:
        subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        pytest.skip(f"Docker not available: {exc}")

    tag = f"{IMAGE_NAME}:smoke-{os.getpid()}"
    print(f"\n[deploy] Building image {tag} ...")
    result = subprocess.run(
        [
            "docker", "build",
            "-t", tag,
            "--build-arg", "GIT_TAG=0.0.0-smoke",
            "--build-arg", "GIT_COMMIT=smoke",
            PROJECT_ROOT,
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.fail(f"docker build failed:\n{result.stderr}")
    print(f"[deploy] Image {tag} built successfully.")
    yield tag

    subprocess.run(
        ["docker", "rmi", "-f", tag],
        capture_output=True,
    )


class ServiceWaiter:
    """Poll /healthz (and optionally /readyz) on an HTTP endpoint."""

    def __init__(self, base_url: str, timeout: float = 60, interval: float = 2):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.interval = interval

    def poll(self, path: str = HEALTHZ_PATH) -> dict:
        deadline = time.monotonic() + self.timeout
        last_err: Exception | None = None
        while time.monotonic() < deadline:
            try:
                resp = urllib.request.urlopen(self.base_url + path, timeout=5)
                body = json.loads(resp.read())
                if resp.status == 200:
                    return body
            except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
                last_err = exc
            time.sleep(self.interval)
        raise AssertionError(
            f"Endpoint {self.base_url + path} did not return 200 within "
            f"{self.timeout}s: {last_err}"
        )

    def poll_healthy(self) -> dict:
        return self.poll(HEALTHZ_PATH)

    def poll_ready(self) -> dict:
        return self.poll(READYZ_PATH)


@pytest.fixture()
def waiter():
    return ServiceWaiter
