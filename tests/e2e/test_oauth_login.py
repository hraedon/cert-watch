"""E2E: OIDC sign-in lands on the app, not back on /login (#98).

cert-watch runs as ``http://localhost:<port>`` and its IdP (a mock, see
``_mock_oidc``) as ``http://127.0.0.1:<port>``, so the IdP's redirect to
``/auth/callback`` is a genuinely cross-site navigation. The session cookie is
``SameSite=Strict``. A browser withholds a Strict cookie from a navigation
whose initiator (or, in engines that track it, any hop of whose redirect
chain) is cross-site, so if the callback answered with a plain redirect the
first request into the app would arrive without ``cw_auth`` and bounce to
``/login``. Each engine drives both IdP behaviours: a silent 302 (IdP session
already live) and an interactive page the user clicks through.
"""

from __future__ import annotations

import secrets
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlsplit

import pytest

pytest.importorskip("playwright")
pytest.importorskip("joserfc")
pytest.importorskip("authlib")
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import Playwright, Request, expect

from tests.e2e._helpers import _free_port, boot_server
from tests.e2e._mock_oidc import MockOIDC, mock_oidc_server

REPO_ROOT = Path(__file__).resolve().parents[2]
ENGINES = ("chromium", "firefox", "webkit")


@pytest.fixture(scope="module")
def oidc_app(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[str, MockOIDC]]:
    client_id = "cw-e2e-client"
    with mock_oidc_server(client_id) as idp:
        port = _free_port()
        # The browser addresses the app as localhost and the IdP as 127.0.0.1:
        # two different sites.
        app_base = f"http://localhost:{port}"
        data_dir = tmp_path_factory.mktemp("cw-oidc")
        proc, _ = boot_server(
            data_dir,
            env_extra={
                "PYTHONPATH": str(REPO_ROOT),
                "AUTH_PROVIDER": "oidc",
                "OAUTH_CLIENT_ID": client_id,
                "OAUTH_CLIENT_SECRET": secrets.token_urlsafe(16),
                "OAUTH_ISSUER_URL": idp.issuer,
                "CERT_WATCH_BASE_URL": app_base,
                "CERT_WATCH_ALLOW_PRIVATE_IPS": "1",
                # Plain http in the test; Secure is orthogonal to SameSite.
                "CERT_WATCH_COOKIE_SECURE": "0",
            },
            module="tests.e2e._oauth_app",
            port=port,
        )
        try:
            yield app_base, idp
        finally:
            proc.terminate()
            proc.wait(timeout=10)


def _sent_session_cookie(req: Request) -> bool:
    cookie = req.all_headers().get("cookie", "")
    return any(part.strip().startswith("cw_auth=") for part in cookie.split(";"))


@pytest.mark.parametrize("mode", ["silent", "interactive"])
@pytest.mark.parametrize("engine", ENGINES)
def test_oidc_sign_in_lands_signed_in(
    playwright: Playwright, oidc_app: tuple[str, MockOIDC], engine: str, mode: str,
) -> None:
    app_base, idp = oidc_app
    idp.mode = mode
    try:
        browser = getattr(playwright, engine).launch()
    except PlaywrightError as exc:
        pytest.skip(f"{engine} is not installed: {str(exc).splitlines()[0]}")
    try:
        context = browser.new_context()
        page = context.new_page()
        requests: list[Request] = []
        page.on("request", lambda r: requests.append(r))

        page.goto(f"{app_base}/login")
        with page.expect_response(lambda r: urlsplit(r.url).path == "/auth/callback") as cb:
            page.get_by_role("link", name="Sign in with OIDC").click()
            if mode == "interactive":
                page.locator("#idp-continue").click()
        # Wherever the callback sends the browser, it settles on / or /login.
        page.wait_for_url(lambda u: urlsplit(u).path in ("/", "/login"))
        page.wait_for_load_state("load")

        paths = [urlsplit(r.url).path for r in requests]
        callback = cb.value.request
        jar = {c["name"]: c for c in context.cookies()}
        assert "cw_auth" in jar, f"{engine}/{mode}: no session cookie; chain={paths}"
        assert jar["cw_auth"]["sameSite"] == "Strict"

        # The first document request into the app after the callback must
        # carry the session cookie the callback just set, and the user must
        # end up on the app rather than on /login.
        after = requests[requests.index(callback) + 1:]
        first_app = next(
            r for r in after
            if urlsplit(r.url).netloc == urlsplit(app_base).netloc
            and r.resource_type == "document"
        )
        assert urlsplit(page.url).path == "/", (
            f"{engine}/{mode}: landed on {page.url}; chain={paths}"
        )
        assert _sent_session_cookie(first_app), (
            f"{engine}/{mode}: {first_app.url} sent without cw_auth; chain={paths}"
        )
        expect(page.get_by_test_id("home-heading")).to_be_visible()
    finally:
        browser.close()
