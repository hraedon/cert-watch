"""Regression tests for the dashboard pivot urgency stats and fleet urgency.

Both paths historically compared ``not_after`` against ``datetime('now')`` with
a lexicographic string compare.  ``not_after`` is stored as a T-separated ISO
timestamp (e.g. ``2026-06-16T17:00:00+00:00``) while ``datetime('now')`` is
space-separated, so ``'…T17:00…' < '… 20:00'`` is *false* for a cert that
expired earlier the same UTC day — it was misbucketed as not-expired.  The fix
uses ``julianday()`` for the boundary.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cert_watch.certificate_model import Certificate
from cert_watch.database import (
    SqliteCertificateRepository,
    SqliteHostRepository,
    init_schema,
    list_fleet_pivot,
    pivot_urgency_stats,
    replace_scanned,
)


def _add_leaf(db, subject, *, not_after):
    cert = Certificate(
        subject=subject,
        issuer="Test CA",
        not_before=datetime.now(UTC) - timedelta(days=1),
        not_after=not_after,
        fingerprint_sha256=subject,
    )
    SqliteCertificateRepository(db, source="uploaded").add(cert)


def test_pivot_stats_counts_same_day_expiry_as_expired(tmp_path):
    """A cert that expired a few hours ago today must count as expired.

    This is the exact case the old string compare missed: same UTC date, so the
    'T' (0x54) vs ' ' (0x20) separator made the stored value sort *after* now.
    """
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    now = datetime.now(UTC)
    _add_leaf(db, "expired-today.example.com", not_after=now - timedelta(hours=3))
    _add_leaf(db, "healthy.example.com", not_after=now + timedelta(days=90))

    stats = pivot_urgency_stats(db)
    assert stats["expired"] == 1
    assert stats["healthy"] == 1
    assert stats["critical"] == 0
    assert stats["warning"] == 0


def test_pivot_stats_bucket_boundaries(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    now = datetime.now(UTC)
    _add_leaf(db, "exp.example.com", not_after=now - timedelta(days=2))
    _add_leaf(db, "crit.example.com", not_after=now + timedelta(days=3))
    _add_leaf(db, "warn.example.com", not_after=now + timedelta(days=20))
    _add_leaf(db, "ok.example.com", not_after=now + timedelta(days=200))

    stats = pivot_urgency_stats(db)
    assert stats == {"expired": 1, "critical": 1, "warning": 1, "healthy": 1}


def test_fleet_pivot_surfaces_expired_urgency(tmp_path):
    """An expired scanned cert must raise the group's worst_urgency to 'expired'.

    Previously the ``WHEN expired THEN 0`` sentinel (plus CAST-toward-zero on
    small negative day deltas) clamped min_days to 0, so expired certs were
    reported as 'critical' and the 'expired' urgency was unreachable.
    """
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    hosts = SqliteHostRepository(db)
    now = datetime.now(UTC)

    hosts.add("expired.example.com", 443)
    expired = Certificate(
        subject="expired.example.com",
        issuer="Test CA",
        not_before=now - timedelta(days=400),
        not_after=now - timedelta(hours=2),  # expired earlier today
        fingerprint_sha256="expired.example.com",
    )
    replace_scanned(db, "expired.example.com", 443, expired, [], True)

    groups = list_fleet_pivot(db, "issuer")
    assert len(groups) == 1
    assert groups[0]["worst_urgency"] == "expired"
    assert groups[0]["earliest_expiry"] is not None
    assert groups[0]["earliest_expiry"] < 0


def test_fleet_pivot_healthy_unaffected(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    hosts = SqliteHostRepository(db)
    now = datetime.now(UTC)
    hosts.add("ok.example.com", 443)
    cert = Certificate(
        subject="ok.example.com",
        issuer="Test CA",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=90),
        fingerprint_sha256="ok.example.com",
    )
    replace_scanned(db, "ok.example.com", 443, cert, [], True)

    groups = list_fleet_pivot(db, "issuer")
    assert groups[0]["worst_urgency"] == "healthy"
    assert groups[0]["earliest_expiry"] >= 0
