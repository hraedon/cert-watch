"""Shared helpers for the E2E Playwright suite.

Keeps selectors centralised on the stable ``data-testid`` hooks (BC-132) so a
markup change only needs updating in one place.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

from playwright.sync_api import Page

# Top-level nav → destination heading. The 2026-08 redesign collapsed the
# 7-item nav into 4 domains (scan history and the audit log as tabs inside
# Activity; Insights' trends as Posture); attention-home then added Home in
# front and moved the inventory table to Browse.
PAGES = {
    "nav-home": "home-heading",
    "nav-browse": "dashboard-heading",
    "nav-posture": "insights-heading",
    "nav-activity": "alerts-heading",
}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def boot_server(
    data_dir: Path,
    env_extra: dict[str, str] | None = None,
    host: str = "127.0.0.1",
) -> tuple[subprocess.Popen, str]:
    """Start a uvicorn subprocess and poll healthz until ready.

    Returns ``(proc, base_url)``. The caller is responsible for terminating
    *proc* (typically in a fixture teardown). Output is retained in
    ``data_dir/server.log`` and included in startup failures.
    """
    port = _free_port()
    env = {
        **os.environ,
        "CERT_WATCH_DATA_DIR": str(data_dir),
        "CERT_WATCH_HOST": host,
        "CERT_WATCH_PORT": str(port),
        **(env_extra or {}),
    }
    log_path = data_dir / "server.log"
    with log_path.open("wb") as log_file:
        proc = subprocess.Popen(
            [sys.executable, "-m", "cert_watch", "--host", host, "--port", str(port)],
            env=env,
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
    base = f"http://{host}:{port}"
    deadline = time.monotonic() + 8
    startup_wait = threading.Event()
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            break
        try:
            with urllib.request.urlopen(f"{base}/healthz", timeout=0.5) as r:
                if r.status == 200:
                    return proc, base
        except Exception:
            # Unit-test fixtures patch time.sleep globally to remove retry
            # backoff. Startup still needs a real wait in function fixtures.
            startup_wait.wait(0.1)
    if proc.poll() is None:
        proc.kill()
    proc.wait(timeout=5)
    output = log_path.read_text(encoding="utf-8", errors="replace")
    raise RuntimeError(
        f"cert-watch server did not become ready (exit {proc.returncode}; log: {log_path}):\n"
        f"{output[-8192:]}"
    )


def login(page: Page, base_url: str, username: str, password: str) -> None:
    """Fill the login form and submit, waiting for redirect away from /login."""
    page.goto(f"{base_url}/login")
    page.get_by_test_id("login-username").fill(username)
    page.get_by_test_id("login-password").fill(password)
    page.get_by_test_id("login-submit-btn").click()
    page.wait_for_url("**/*", timeout=5000)


def inject_session(page: Page, base_url: str, token: str) -> None:
    """Inject a crafted ``cw_auth`` session cookie."""
    page.context.add_cookies([{"name": "cw_auth", "value": token, "url": base_url}])


def open_add_slide(page: Page) -> None:
    """Open the dashboard Add-certificates drawer."""
    page.get_by_test_id("add-host-btn").click()
    page.locator(".cw-drawer.on").wait_for()


def switch_add_tab(page: Page, tab: str) -> None:
    """Switch the drawer tab (scan | upload | bulk)."""
    page.get_by_test_id(f"tab-{tab}-btn").click()
    page.locator(f'[data-tab-pane="{tab}"]:not(.cw-hidden)').wait_for()
