"""Credential inventory adapters reject secret values and share one service."""

from fastapi.testclient import TestClient

from cert_watch.database.application_secrets import list_application_secrets
from tests.test_application_secrets import metadata


def test_json_create_read_retire(reload_app, tmp_path):
    with TestClient(reload_app().app) as client:
        response = client.post("/api/application-secrets", json=metadata())
        assert response.status_code == 201
        identifier = response.json()["id"]
        rows = client.get("/api/application-secrets").json()
        assert len(rows) == 1
        assert rows[0]["id"] == identifier
        endpoint = f"/api/application-secrets/{identifier}/retire"
        assert client.post(endpoint, json={}).status_code == 200
        assert client.post(endpoint, json={}).status_code == 404
    assert list_application_secrets(tmp_path / "cert-watch.sqlite3")[0].retired_at


def test_html_create_is_escaped_and_retire(reload_app, tmp_path):
    with TestClient(reload_app().app) as client:
        response = client.post("/application-secrets", data=metadata(
            application_name="<script>example</script>", expires_at="2027-01-31T12:30",
        ))
        assert response.status_code == 200
        assert "&lt;script&gt;example&lt;/script&gt;" in response.text
        assert "<script>example</script>" not in response.text
        identifier = list_application_secrets(tmp_path / "cert-watch.sqlite3")[0].id
        response = client.post(f"/application-secrets/{identifier}/retire", data={})
        assert "Retired" in response.text


def test_unknown_secret_field_not_reflected_or_persisted(reload_app, tmp_path):
    with TestClient(reload_app().app) as client:
        for path, kwargs in [
            ("/api/application-secrets", {"json": metadata(secretText="VALUE_NEVER_ECHOED")}),
            ("/application-secrets", {"data": metadata(secretText="VALUE_NEVER_ECHOED")}),
        ]:
            response = client.post(path, **kwargs)
            assert "VALUE_NEVER_ECHOED" not in response.text
            assert "never submit secret values" in response.text
        assert not list_application_secrets(tmp_path / "cert-watch.sqlite3")


def test_json_shape_and_size_validation(reload_app):
    with TestClient(reload_app().app) as client:
        for content in ("{", "[]", '"text"'):
            assert client.post("/api/application-secrets", content=content,
                               headers={"Content-Type": "application/json"}).status_code == 422
        assert client.post("/api/application-secrets", json={"application_name": "x" * 17000}
                           ).status_code == 413
