"""Calendar date bounds cover whole UTC days, including hostless uploads."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from starlette.testclient import TestClient

from cert_watch.certificate_model import Certificate
from cert_watch.database import list_calendar
from tests._helpers import seed_certificate


def _seed(db, cert_id: str, expires: str, *, tags: str = "team-a") -> str:
    return seed_certificate(
        db,
        Certificate(
            subject=f"CN={cert_id}.example.test",
            issuer="CN=Synthetic Calendar CA",
            not_before=datetime(2025, 1, 1, tzinfo=UTC),
            not_after=datetime.fromisoformat(expires),
            san_dns_names=[f"{cert_id}.example.test"],
            fingerprint_sha256=cert_id,
            raw_der=b"",
        ),
        cert_id=cert_id,
        source="uploaded",
        tags=tags,
    )


def _ids(rows) -> set[str]:
    return {cert_id for row in rows for cert_id in row["cert_ids"]}


@pytest.mark.parametrize("bucket", ["day", "week", "month"])
@pytest.mark.parametrize("scope", [None, ("team-a",)])
def test_same_date_includes_the_whole_day(db, bucket, scope):
    expected = {
        _seed(db, "start", "2026-10-25T00:00:00+00:00"),
        _seed(db, "noon", "2026-10-25T12:00:00+00:00"),
        _seed(db, "end", "2026-10-25T23:59:59+00:00"),
    }
    _seed(db, "before", "2026-10-24T23:59:59+00:00")
    _seed(db, "after", "2026-10-26T00:00:00+00:00")
    foreign = _seed(db, "foreign", "2026-10-25T12:00:00+00:00", tags="team-b")
    if scope is None:
        expected.add(foreign)

    rows = list_calendar(
        db, from_date="2026-10-25", to_date="2026-10-25", bucket=bucket, scope_tags=scope
    )

    assert _ids(rows) == expected
    assert sum(row["count"] for row in rows) == len(expected)


def test_date_boundaries_use_the_same_utc_day_as_calendar_buckets(db):
    _seed(db, "previous-utc", "2026-10-25T00:30:00+02:00")
    _seed(db, "next-utc", "2026-10-25T23:30:00-02:00")
    included = _seed(db, "inside-utc", "2026-10-26T00:30:00+02:00")

    rows = list_calendar(db, from_date="2026-10-25", to_date="2026-10-25", bucket="day")

    assert rows == [{"bucket_start": "2026-10-25", "count": 1, "cert_ids": [included]}]


@pytest.mark.parametrize(
    ("from_date", "to_date", "expected"),
    [
        (None, "2026-10-25", {"before", "start", "noon", "end"}),
        ("2026-10-25", None, {"start", "noon", "end", "after"}),
        ("2026-10-26", "2026-10-25", set()),
        ("2026-10-25T12:00:00+00:00", "2026-10-25T12:00:00+00:00", {"noon"}),
        ("2026-10-25T12:00:00+00:00", "2026-10-25", {"noon", "end"}),
        ("2026-10-25", "2026-10-25T12:00:00+00:00", {"start", "noon"}),
    ],
)
def test_date_and_precise_timestamp_bounds(db, from_date, to_date, expected):
    for name, expires in [
        ("before", "2026-10-24T23:59:59+00:00"),
        ("start", "2026-10-25T00:00:00+00:00"),
        ("noon", "2026-10-25T12:00:00+00:00"),
        ("end", "2026-10-25T23:59:59+00:00"),
        ("after", "2026-10-26T00:00:00+00:00"),
    ]:
        _seed(db, name, expires)

    assert _ids(list_calendar(db, from_date=from_date, to_date=to_date)) == expected


@pytest.mark.parametrize("bucket", ["day", "week", "month"])
def test_maximum_date_needs_no_next_day_arithmetic(db, bucket):
    included = _seed(db, "maximum", "9999-12-31T12:00:00+00:00")

    assert _ids(list_calendar(db, from_date="9999-12-31", to_date="9999-12-31", bucket=bucket)) == {
        included
    }


@pytest.mark.parametrize("bucket", ["day", "week", "month"])
def test_api_date_range_includes_uploaded_certificate(tmp_path, reload_app, bucket):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    included = _seed(db, "api-noon", "2026-10-25T12:00:00+00:00")
    _seed(db, "api-next-day", "2026-10-26T00:00:00+00:00")

    with TestClient(app_mod.app) as client:
        response = client.get(
            "/api/calendar",
            params={"bucket": bucket, "from_date": "2026-10-25", "to_date": "2026-10-25"},
        )

    assert response.status_code == 200
    assert response.json()["bucket"] == bucket
    assert _ids(response.json()["buckets"]) == {included}
