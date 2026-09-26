"""The HTML 404 page is for browsers only; API clients keep JSON (#126 S2)."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(reload_app) -> Iterator[TestClient]:
    with TestClient(reload_app().app) as c:
        yield c


def test_browser_gets_html_404(client: TestClient) -> None:
    r = client.get("/no-such-page", headers={"Accept": "text/html"})
    assert r.status_code == 404
    assert r.headers["content-type"].startswith("text/html")
    assert '<html lang="en"' in r.text
    assert "<title>cert-watch — page not found</title>" in r.text
    assert r.text.count("<main") == 1


def test_api_and_non_browser_clients_keep_json_404(client: TestClient) -> None:
    for path, accept in (("/no-such-page", "application/json"), ("/api/nope", "text/html")):
        r = client.get(path, headers={"Accept": accept})
        assert r.status_code == 404
        assert r.json() == {"detail": "Not Found"}
