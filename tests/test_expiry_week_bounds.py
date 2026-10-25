"""A complete expiry-week interval must fit in Python's date range."""

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from cert_watch.certificate_model import parse_certificate
from cert_watch.database import SqliteCertificateRepository, init_schema, list_dashboard_page
from cert_watch.database.connection import _connect

_IGNORED_WEEKS = ["9999-12-25", "9999-12-31", "99991231", "9999-W52-5", "not-a-date"]
_VALID_EXTREMES = ["0001-01-01", "9999-12-24", "99991224", "9999-W51-5"]


def _seed(db, leaves):
    init_schema(db)
    repo = SqliteCertificateRepository(db, source="uploaded")
    certs = [parse_certificate(leaf.der) for leaf in leaves]
    ids = [repo.add(cert) for cert in certs]
    with _connect(db) as conn:
        for cert_id, tag in zip(ids, ("blue", "red"), strict=True):
            conn.execute("UPDATE certificates SET tags = ? WHERE id = ?", (tag, cert_id))
        conn.commit()
    return ids, certs[1].not_after.date()


@pytest.mark.parametrize("populated", [False, True], ids=["empty", "populated"])
@pytest.mark.parametrize("week", [*_IGNORED_WEEKS, *_VALID_EXTREMES])
def test_browse_validates_the_end_of_the_expiry_week(
    tmp_path,
    reload_app,
    self_signed_leaf,
    expiring_soon_leaf,
    populated,
    week,
):
    app = reload_app().app
    if populated:
        _seed(tmp_path / "cert-watch.sqlite3", (self_signed_leaf, expiring_soon_leaf))
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/browse", params={"expiry_week": week})
    assert response.status_code == 200
    if week in _IGNORED_WEEKS:
        assert f"Ignored invalid expiry week: {week}" in response.text
        if populated:
            assert self_signed_leaf.subject_cn in response.text
            assert expiring_soon_leaf.subject_cn in response.text
    else:
        assert "Ignored invalid expiry week" not in response.text


@pytest.mark.parametrize("scoped", [False, True])
@pytest.mark.parametrize("week", _IGNORED_WEEKS)
def test_unrepresentable_week_is_ignored_without_losing_scope(
    db,
    self_signed_leaf,
    expiring_soon_leaf,
    scoped,
    week,
):
    ids, _day = _seed(db, (self_signed_leaf, expiring_soon_leaf))
    rows, total = list_dashboard_page(
        db,
        expiry_week=week,
        scope_tags=("blue",) if scoped else (),
    )
    expected = {ids[0]} if scoped else set(ids)
    assert {row["id"] for row in rows} == expected
    assert total == len(expected)


@pytest.mark.parametrize("week", _VALID_EXTREMES)
def test_representable_extreme_weeks_remain_valid(
    db,
    self_signed_leaf,
    expiring_soon_leaf,
    week,
):
    _seed(db, (self_signed_leaf, expiring_soon_leaf))
    rows, total = list_dashboard_page(db, expiry_week=week)
    assert rows == []
    assert total == 0


@pytest.mark.parametrize("date_format", ["iso", "compact", "iso-week"])
def test_valid_week_formats_preserve_the_exclusive_end(
    db,
    self_signed_leaf,
    expiring_soon_leaf,
    date_format,
):
    ids, day = _seed(db, (self_signed_leaf, expiring_soon_leaf))
    start = day - timedelta(days=6)
    if date_format == "iso":
        value = start.isoformat()
    elif date_format == "compact":
        value = start.isoformat().replace("-", "")
    else:
        year, week, weekday = start.isocalendar()
        value = f"{year:04}-W{week:02}-{weekday}"
    rows, total = list_dashboard_page(db, expiry_week=value)
    assert {row["id"] for row in rows} == {ids[1]}
    assert total == 1

    # Ending at the certificate's date excludes it, as the existing filter does.
    rows, total = list_dashboard_page(db, expiry_week=(day - timedelta(days=7)).isoformat())
    assert rows == []
    assert total == 0
