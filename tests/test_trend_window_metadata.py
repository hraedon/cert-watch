"""Trend responses describe the actual window used to select observations."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from starlette.testclient import TestClient

from cert_watch.certificate_model import Certificate
from cert_watch.database import list_tls_version_trends, record_cert_history


@pytest.fixture
def client(tmp_path, reload_app):
    app_mod = reload_app(CERT_WATCH_HISTORY_RETENTION_DAYS="0")
    db = tmp_path / "cert-watch.sqlite3"
    now = datetime.now(UTC)
    cert = Certificate(
        subject="CN=trend.example.test",
        issuer="CN=Synthetic Trend CA",
        not_before=now - timedelta(days=500),
        not_after=now + timedelta(days=90),
        san_dns_names=["trend.example.test"],
        fingerprint_sha256="synthetic-trend-window",
        raw_der=b"",
    )
    # Stay away from cutoff instants and use distinct endpoints, so neither
    # clock drift nor per-endpoint/day grouping can change these counts.
    for index, age in enumerate([0.5, 2, 60, 364, 366]):
        record_cert_history(
            db,
            f"observation-{index}.example.test",
            443,
            cert,
            posture_grade="A",
            protocol_version="TLSv1.3",
            scanned_at=(now - timedelta(days=age)).isoformat(),
        )
    with TestClient(app_mod.app) as test_client:
        # The API's upper bound must exclude available old observations,
        # rather than merely rely on the scheduler having purged them.
        assert sum(row["count"] for row in list_tls_version_trends(db, days=1000)) == 5
        yield test_client


@pytest.mark.parametrize("endpoint", ["tls-versions", "grades"])
@pytest.mark.parametrize(
    ("requested", "effective", "observations"),
    [
        (None, 30, 2),
        (-500, 1, 1),
        (0, 1, 1),
        (1, 1, 1),
        (30, 30, 2),
        (365, 365, 4),
        (366, 365, 4),
        (1000, 365, 4),
        (2**128, 365, 4),
        (-(2**128), 1, 1),
    ],
    ids=[
        "default",
        "negative",
        "zero",
        "one",
        "thirty",
        "maximum",
        "over",
        "thousand",
        "large-positive",
        "large-negative",
    ],
)
def test_metadata_matches_the_effective_window(
    client, endpoint, requested, effective, observations
):
    params = {} if requested is None else {"days": str(requested)}

    response = client.get(f"/api/trends/{endpoint}", params=params)

    assert response.status_code == 200
    data = response.json()
    assert data["days"] == effective
    assert sum(row["count"] for row in data["trends"]) == observations
    column, value = (
        ("protocol_version", "TLSv1.3") if endpoint == "tls-versions" else ("posture_grade", "A")
    )
    assert {row[column] for row in data["trends"]} == {value}


@pytest.mark.parametrize("endpoint", ["tls-versions", "grades"])
@pytest.mark.parametrize("value", ["", "invalid", "1.5", "1e3"])
def test_invalid_window_keeps_validation_response(client, endpoint, value):
    response = client.get(f"/api/trends/{endpoint}", params={"days": value})

    assert response.status_code == 422
