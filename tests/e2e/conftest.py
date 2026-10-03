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

from tests.e2e._seed import seed_detail_estate


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
            except Exception:  # noqa: BLE001 — startup polling tolerates transient HTTP failures
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


@pytest.fixture(scope="session")
def detail_estate_server(
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[tuple[str, dict[str, str]]]:
    """A scanned estate covering every Detail A status branch."""
    data_dir: Path = tmp_path_factory.mktemp("cw-detail-data")
    ids = seed_detail_estate(data_dir)
    # Reconstruct the surviving duplicate left by an old alias merge (#156).
    # Timestamp order deliberately disagrees with the explicit successor.
    from cert_watch.certificate_model import parse_certificate
    from cert_watch.database.connection import _connect
    from tests._helpers import seed_certificate
    from tests.conftest import _make_cert

    db = data_dir / "cert-watch.sqlite3"
    ids["superseded"] = seed_certificate(
        db,
        parse_certificate(_make_cert("current.detail.test", days_valid=3).der),
        source="scanned", hostname="current.detail.test", port=443,
    )
    with _connect(db) as conn:
        conn.execute(
            "UPDATE certificates SET replaces_cert_id=? WHERE id=?",
            (ids["superseded"], ids["current"]),
        )
        conn.commit()
    port = _free_port()
    env = {
        **os.environ,
        "CERT_WATCH_DATA_DIR": str(data_dir),
        "CERT_WATCH_PORT": str(port),
        "CERT_WATCH_ALLOW_UNAUTH": "1",
        "SMTP_HOST": "smtp.example.test",
        "ALERT_FROM": "alerts@example.test",
    }
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "tests.e2e._detail_app:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=Path(__file__).parents[2],
    )
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(50):
            try:
                with urllib.request.urlopen(f"{base}/healthz", timeout=0.5) as response:
                    if response.status == 200:
                        break
            except Exception:  # noqa: BLE001 - startup polling is transient
                time.sleep(0.1)
        else:
            raise RuntimeError("Detail A e2e server did not become ready")
        yield base, ids
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
