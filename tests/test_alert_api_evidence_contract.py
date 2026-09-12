"""Internal historical/delivery presentation must not change the public alert row."""
from fastapi.testclient import TestClient

from cert_watch.database import Alert, SqliteAlertRepository, init_schema


def test_delivery_ui_marker_does_not_escape_into_alert_api(reload_app, tmp_path):
    app = reload_app().app
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    SqliteAlertRepository(db).create(Alert(
        cert_id="historical-certificate", alert_type="expiry_warning", status="sent",
        message="Recorded threshold", subject="historical.example.test",
    ))
    with TestClient(app) as client:
        response = client.get("/api/alerts")
    assert response.status_code == 200
    [row] = response.json()["alerts"]
    assert set(row) == {"id", "cert_id", "created_at", "alert_type", "status",
                        "threshold_days", "sent_at", "error_message", "message", "read", "subject"}
    assert row["subject"] == "historical.example.test"
