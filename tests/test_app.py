from fastapi.testclient import TestClient

from cert_watch.app import app

client = TestClient(app)


def test_healthz() -> None:
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_dashboard_empty_state() -> None:
    r = client.get("/")
    assert r.status_code == 200
    assert "No certificates tracked yet" in r.text
