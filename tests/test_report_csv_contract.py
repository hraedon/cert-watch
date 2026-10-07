"""CSV exports keep a rectangular schema and report the expiry requiring action."""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from zoneinfo import ZoneInfo

import pytest
from fastapi import Request
from fastapi.testclient import TestClient
from freezegun import freeze_time

from cert_watch.auth.guards import require_auth
from cert_watch.certificate_model import Certificate, parse_certificate
from cert_watch.database import SqliteHostRepository
from cert_watch.status_rule import effective_days, effective_not_after
from cert_watch.upload import UploadedEntry, store_uploaded, upload_certificate
from tests.conftest import _make_cert


def test_certificate_csv_chain_rows_match_the_header(tmp_path, reload_app, chain_pem_file):
    app_mod = reload_app()
    entry = upload_certificate(chain_pem_file)
    assert isinstance(entry, UploadedEntry)
    store_uploaded(entry, tmp_path / "cert-watch.sqlite3")

    with TestClient(app_mod.app) as client:
        response = client.get("/api/export/certificates.csv")

    assert response.status_code == 200
    rows = list(csv.reader(io.StringIO(response.text)))
    header, *data = rows
    assert len(header) == 12
    assert len(data) == 3
    assert all(len(row) == len(header) for row in data)
    by_subject = {row["subject"]: row for row in csv.DictReader(io.StringIO(response.text))}
    leaf = by_subject[entry.leaf.subject]
    assert leaf["condition"] == "ok"
    assert leaf["monitoring"] == "not_monitored"
    for certificate in entry.chain:
        chain = by_subject[certificate.subject]
        assert chain["issuer"] == certificate.issuer
        assert chain["not_after"] == certificate.not_after.isoformat()
        assert chain["overall_status"] == "healthy"
        assert all(
            chain[field] == ""
            for field in ("chain_valid", "condition", "monitoring", "renewal", "delivery")
        )


@pytest.mark.parametrize("scoped", [False, True])
@freeze_time("2026-10-02T12:00:00+00:00")
def test_expiring_csv_uses_the_limiting_certificate(
    tmp_path, reload_app, monkeypatch, scoped
):
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.start", lambda self: None)
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    root = _make_cert("Report Root", days_valid=400, ca=True)
    expected = {}
    cases = (
        ("leaf-first", 5, 60, "team-a"),
        ("chain-first", 60, 5, "team-a"),
        ("expired-chain", 99, -3, "team-a"),
        ("outside-window", 60, 45, "team-a"),
        ("leaf-only", 5, None, "team-a"),
        ("window-boundary", 30, 90, "team-a"),
        ("other-team", 60, 5, "team-b"),
    )
    for name, leaf_days, chain_days, tags in cases:
        intermediate = (
            _make_cert(
                f"{name} CA", issuer_cert=root.cert, issuer_key=root.key,
                days_valid=chain_days, not_before_days_ago=365, ca=True,
            )
            if chain_days is not None else None
        )
        issuer = intermediate or root
        leaf = _make_cert(
            f"{name}.example.test", issuer_cert=issuer.cert, issuer_key=issuer.key,
            days_valid=leaf_days,
        )
        parsed_leaf = parse_certificate(leaf.der)
        assert isinstance(parsed_leaf, Certificate)
        chain = []
        for generated in (intermediate, root) if intermediate else ():
            parsed = parse_certificate(generated.der)
            assert isinstance(parsed, Certificate)
            chain.append(parsed)
        store_uploaded(UploadedEntry(f"{name}.pem", parsed_leaf, chain), db, tags=tags)
        effective_days = min(leaf_days, chain_days) if chain_days is not None else leaf_days
        if effective_days <= 30 and (not scoped or tags == "team-a"):
            expected[parsed_leaf.subject] = effective_days

    SqliteHostRepository(db).add("pending.example.test", 443, tags="team-a")
    if scoped:
        def scoped_auth(request: Request):
            request.state.auth_context = SimpleNamespace(is_admin=False, scope_tag="team-a")
            return "report-viewer"

        app_mod.app.dependency_overrides[require_auth] = scoped_auth

    with TestClient(app_mod.app) as client:
        response = client.get("/api/reports/expiring.csv?days=30")

    assert response.status_code == 200
    rows = list(csv.DictReader(io.StringIO(response.text)))
    assert {row["subject"] for row in rows} == set(expected)
    for row in rows:
        days = expected[row["subject"]]
        # Keep the existing spreadsheet-safe prefix on negative CSV cells.
        assert row["days_remaining"] == (f"'{days}" if days < 0 else str(days))
        assert datetime.fromisoformat(row["not_after"]) == (
            datetime.now(UTC) + timedelta(days=days)
        )
        if days < 0:
            assert row["overall_status"] == "expired"


@pytest.mark.parametrize(
    ("leaf", "chain", "expected"),
    [
        (
            "2026-10-03T12:00:00+00:00",
            ("2026-10-03T13:00:00+02:00",),
            "2026-10-03T13:00:00+02:00",
        ),
        (
            "2026-10-03T12:00:00",
            ("2026-10-03T11:00:00+00:00",),
            "2026-10-03T11:00:00+00:00",
        ),
        ("2026-10-03T12:00:00", (), "2026-10-03T12:00:00"),
        (
            datetime(2026, 10, 3, 12, tzinfo=UTC),
            (datetime(2026, 10, 3, 11),),
            datetime(2026, 10, 3, 11),
        ),
    ],
)
def test_effective_expiry_selects_the_instant_before_rounding_days(leaf, chain, expected):
    now = datetime(2026, 10, 2, tzinfo=UTC)
    assert effective_not_after(leaf, iter(chain)) == expected
    assert effective_days(leaf, iter(chain), now) == 1


@pytest.mark.parametrize("invalid", ["not-a-date", ""])
def test_effective_expiry_does_not_ignore_malformed_chain_dates(invalid):
    leaf = "2026-10-03T12:00:00+00:00"
    with pytest.raises(ValueError):
        effective_not_after(leaf, [invalid])
    with pytest.raises(ValueError):
        effective_days(leaf, [invalid], datetime(2026, 10, 2, tzinfo=UTC))


def test_effective_expiry_distinguishes_repeated_daylight_saving_times():
    eastern = ZoneInfo("America/New_York")
    leaf = datetime(2026, 11, 1, 1, 30, tzinfo=eastern, fold=1)
    intermediate = datetime(2026, 11, 1, 1, 30, tzinfo=eastern, fold=0)
    now = datetime(2026, 10, 31, 6, tzinfo=UTC)

    assert effective_not_after(leaf, [intermediate]) is intermediate
    assert effective_days(leaf, [intermediate], now) == 0
