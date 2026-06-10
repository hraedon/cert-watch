"""E2E fixtures: spin up uvicorn against a temp data dir, yield base URL."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    for item in items:
        if "e2e" in str(item.fspath):
            item.add_marker(pytest.mark.e2e)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def cert_watch_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    data_dir: Path = tmp_path_factory.mktemp("cw-data")
    port = _free_port()
    env = {
        **os.environ,
        "CERT_WATCH_DATA_DIR": str(data_dir),
        "CERT_WATCH_PORT": str(port),
        "CERT_WATCH_ALLOW_UNAUTH": "1",
    }
    proc = subprocess.Popen(
        [sys.executable, "-m", "cert_watch"],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(50):
            try:
                with urllib.request.urlopen(f"{base}/healthz", timeout=0.5) as r:
                    if r.status == 200:
                        break
            except Exception:
                time.sleep(0.1)
        else:
            proc.kill()
            out = proc.stdout.read().decode() if proc.stdout else ""
            raise RuntimeError(f"cert-watch did not become ready:\n{out}")
        yield base
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
