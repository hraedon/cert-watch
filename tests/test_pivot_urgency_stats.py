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
from cert_watch.database.connection import _connect


def _earlier_same_utc_day(now: datetime) -> datetime:
    """A timestamp on the *same UTC date* as ``now`` but strictly earlier.

    The same-day bug only reproduces when the cert's not_after shares ``now``'s
    calendar date, so the ``T`` (0x54) vs space (0x20) separator — not a date
    difference — decides the lexicographic compare.  ``now - timedelta(hours=N)``
    rolls back to the previous date in the first N hours after UTC midnight,
    masking the bug and giving a false pass.  Anchoring to half-way between
    midnight and now keeps the same date and stays strictly < now at any
    wall-clock time.
    """
    midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
    return midnight + (now - midnight) / 2


def _add_leaf(db, subject, *, not_after):
    """Add a scanned leaf cert (with its host) — the population the pivot counts."""
    host, port = subject, 443
    SqliteHostRepository(db).add(host, port)
    cert = Certificate(
        subject=subject,
        issuer="Test CA",
        not_before=datetime.now(UTC) - timedelta(days=1),
        not_after=not_after,
        fingerprint_sha256=subject,
    )
    replace_scanned(db, host, port, cert, [], True)


def test_pivot_stats_counts_same_day_expiry_as_expired(tmp_path):
    """A cert that expired a few hours ago today must count as expired.

    This is the exact case the old string compare missed: same UTC date, so the
    'T' (0x54) vs ' ' (0x20) separator made the stored value sort *after* now.
    """
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    now = datetime.now(UTC)
    _add_leaf(db, "expired-today.example.com", not_after=_earlier_same_utc_day(now))
    _add_leaf(db, "healthy.example.com", not_after=now + timedelta(days=90))

    stats = pivot_urgency_stats(db)
    assert stats["expired"] == 1
    assert stats["healthy"] == 1
    assert stats["critical"] == 0
    assert stats["warning"] == 0


def test_pivot_stats_are_tag_scoped(tmp_path):
    """A scoped user's summary cards must count only certs in their tag scope.

    Mirrors list_fleet_pivot's scoped population so the cards agree with the
    grouped rows; previously the cards aggregated every leaf cert globally,
    leaking out-of-scope counts to tag-scoped (non-admin) users.
    """
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    hosts = SqliteHostRepository(db)
    now = datetime.now(UTC)

    def scanned(host, *, not_after, tag):
        host_id = hosts.add(host, 443)
        cert = Certificate(
            subject=host,
            issuer="Test CA",
            not_before=now - timedelta(days=1),
            not_after=not_after,
            fingerprint_sha256=host,
        )
        replace_scanned(db, host, 443, cert, [], True)
        hosts.set_tags(host_id, tag)  # host tag → effective tag of its certs

    scanned("team-a.example.com", not_after=now - timedelta(hours=2), tag="team-a")
    scanned("team-b.example.com", not_after=now - timedelta(hours=2), tag="team-b")
    scanned("team-b-2.example.com", not_after=now + timedelta(days=90), tag="team-b")

    # A cert tagged on the *cert* itself, with its host left untagged — exercises
    # the cert-tag branch of the effective-tag filter (the others use host tags).
    host_id = hosts.add("team-c.example.com", 443)  # noqa: F841 — host untagged
    cert = Certificate(
        subject="team-c.example.com",
        issuer="Test CA",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=5),  # critical
        fingerprint_sha256="team-c.example.com",
    )
    replace_scanned(db, "team-c.example.com", 443, cert, [], True)
    repo = SqliteCertificateRepository(db, source="scanned")
    with _connect(db) as conn:
        cert_id = conn.execute(
            "SELECT id FROM certificates WHERE subject = ?", ("team-c.example.com",)
        ).fetchone()[0]
    repo.set_tags(cert_id, "team-c")

    # Admin (no scope) sees everything.
    assert pivot_urgency_stats(db) == {
        "expired": 2, "critical": 1, "warning": 0, "healthy": 1
    }
    # Scoped to team-a: only the one expired team-a cert.
    assert pivot_urgency_stats(db, scope_tags=["team-a"]) == {
        "expired": 1, "critical": 0, "warning": 0, "healthy": 0
    }
    # Scoped to team-b: one expired + one healthy.
    assert pivot_urgency_stats(db, scope_tags=["team-b"]) == {
        "expired": 1, "critical": 0, "warning": 0, "healthy": 1
    }
    # Scoped to team-c: matched via the cert's own tag (host untagged).
    assert pivot_urgency_stats(db, scope_tags=["team-c"]) == {
        "expired": 0, "critical": 1, "warning": 0, "healthy": 0
    }


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
        not_after=_earlier_same_utc_day(now),  # expired earlier the same UTC day
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
