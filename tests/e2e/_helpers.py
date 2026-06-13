"""Shared helpers for the E2E Playwright suite.

Keeps selectors centralised on the stable ``data-testid`` hooks (BC-132) so a
markup change only needs updating in one place.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from playwright.sync_api import Page

PAGES = {
    "nav-dashboard": "dashboard-heading",
    "nav-alerts": "alerts-heading",
    "nav-scans": "scans-heading",
    "nav-insights": "insights-heading",
    "nav-audit": "audit-heading",
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
    *proc* (typically in a fixture teardown).
    """
    port = _free_port()
    env = {
        **os.environ,
        "CERT_WATCH_DATA_DIR": str(data_dir),
        "CERT_WATCH_HOST": host,
        "CERT_WATCH_PORT": str(port),
        **(env_extra or {}),
    }
    proc = subprocess.Popen(
        [sys.executable, "-m", "cert_watch", "--host", host, "--port", str(port)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    base = f"http://{host}:{port}"
    for _ in range(80):
        try:
            with urllib.request.urlopen(f"{base}/healthz", timeout=0.5) as r:
                if r.status == 200:
                    return proc, base
        except Exception:
            time.sleep(0.1)
    proc.kill()
    raise RuntimeError("cert-watch server did not become ready (see stderr above)")


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
    """Open the dashboard Add-host slide-over."""
    page.get_by_test_id("add-host-btn").click()
    page.locator(".cw-slide.on").wait_for()


def switch_add_tab(page: Page, tab: str) -> None:
    """Switch the slide-over tab (scan | upload | bulk)."""
    page.get_by_test_id(f"tab-{tab}-btn").click()
    page.locator(f"#tab-{tab}").wait_for()
