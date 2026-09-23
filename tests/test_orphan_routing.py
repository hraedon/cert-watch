"""Tests for orphan alert routing (Plan 050, decision pinned 2026-06-20).

Covers the shared routing resolver (``resolve_cert_recipients``), orphan
detection (``find_orphan_certs``), admin-email resolution, and the admin orphan
notice folded into the weekly digest run.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from cert_watch.alerting import (
    AlertConfig,
    DigestEngine,
    find_orphan_certs,
    resolve_cert_recipients,
)
from cert_watch.alerting.digest.orphan import OrphanDigestKind, _admin_emails
from cert_watch.certificate_model import Certificate
from cert_watch.database import (
    Role,
    SqliteAlertGroupRepository,
    SqliteCertificateRepository,
    SqliteHostRepository,
    SqliteRoleRepository,
)
from cert_watch.database.digest_deliveries import digest_period_key
from cert_watch.database.users_roles import SqliteUserRepository, User


def _add_leaf(db: Path, hostname: str, *, port: int = 443, tags: str = "",
              owner_email: str = "", subject: str | None = None) -> str:
    SqliteHostRepository(db).add(
        hostname, port, tags=tags, owner_name="O" if owner_email else "",
        owner_email=owner_email,
    )
    cert = Certificate(
        subject=subject or f"CN={hostname}",
        issuer="CN=issuer",
        not_before=datetime.now(UTC) - timedelta(days=300),
        not_after=datetime.now(UTC) + timedelta(days=5),
        san_dns_names=[hostname],
        fingerprint_sha256=(hostname.encode().hex() * 32)[:64],
        raw_der=b"\x00" * 10,
        is_leaf=True,
    )
    return SqliteCertificateRepository(db, hostname=hostname, port=port).add(cert)


def _make_admin(db: Path, email: str, *, tier: str = "admin") -> None:
    rid = SqliteRoleRepository(db).add(Role(name=f"role-{email}", permission_tier=tier))
    SqliteUserRepository(db).add(
        User(username=email.split("@")[0], email=email, password_hash="h", role_id=rid)
    )


# ---------- resolve_cert_recipients (the shared resolver) ----------


def test_resolve_groups_only():
    assert resolve_cert_recipients(["a@co", "b@co"], None, {}) == ["a@co", "b@co"]


def test_resolve_appends_owner_then_role_members():
    out = resolve_cert_recipients(
        ["grp@co"], {"owner_email": "own@co"}, {"own@co": ["m1@co", "m2@co"]}
    )
    assert out == ["grp@co", "own@co", "m1@co", "m2@co"]


def test_resolve_dedups_owner_already_in_group():
    out = resolve_cert_recipients(["own@co"], {"owner_email": "own@co"}, {})
    assert out == ["own@co"]


def test_resolve_role_lookup_is_casefolded():
    out = resolve_cert_recipients([], {"owner_email": "Own@CO"}, {"own@co": ["m@co"]})
    assert out == ["Own@CO", "m@co"]


def test_resolve_empty_is_empty():
    assert resolve_cert_recipients([], None, {}) == []
    assert resolve_cert_recipients([], {"owner_email": ""}, {}) == []


# ---------- find_orphan_certs ----------


def test_orphan_when_no_group_no_owner(db: Path):
    cid = _add_leaf(db, "lonely.example.com")
    orphans = find_orphan_certs(db)
    assert [o["cert_id"] for o in orphans] == [cid]
    assert orphans[0]["hostname"] == "lonely.example.com"


def test_not_orphan_with_owner(db: Path):
    _add_leaf(db, "owned.example.com", owner_email="owner@co.com")
    assert find_orphan_certs(db) == []


def test_not_orphan_with_matching_group(db: Path):
    _add_leaf(db, "tagged.example.com", tags="prod")
    SqliteAlertGroupRepository(db).create("prod-oncall", ["oncall@co.com"], ["prod"])
    assert find_orphan_certs(db) == []


def test_not_orphan_when_routed_via_role_linked_group(db: Path):
    # No group match_tags include 'epic' and no owner — routing only happens via
    # the role→group link. find_orphan_certs must use the real resolver and see it.
    _add_leaf(db, "epic.example.com", tags="epic")
    gid = SqliteAlertGroupRepository(db).create("g", ["oncall@co.com"], ["unrelated"])
    SqliteRoleRepository(db).add(
        Role(name="epic-team", permission_tier="viewer", scope_tag="epic", alert_group_id=gid)
    )
    assert find_orphan_certs(db) == []


def test_orphans_sorted_by_host_then_subject(db: Path):
    _add_leaf(db, "zeta.example.com")
    _add_leaf(db, "alpha.example.com")
    orphans = find_orphan_certs(db)
    assert [o["hostname"] for o in orphans] == ["alpha.example.com", "zeta.example.com"]


# ---------- _admin_emails ----------


def test_admin_emails_only_admins(db: Path):
    _make_admin(db, "boss@co.com", tier="admin")
    _make_admin(db, "viewer@co.com", tier="viewer")
    _make_admin(db, "op@co.com", tier="operator")
    assert _admin_emails(db) == ["boss@co.com"]


def test_admin_emails_empty_when_none(db: Path):
    assert _admin_emails(db) == []


def test_orphan_digest_is_claimed_once_per_period(db: Path, fake_transport) -> None:
    _make_admin(db, "boss@co.com")
    _add_leaf(db, "lonely.example.com", subject="CN=lonely")
    config = AlertConfig(
        smtp_host="smtp.example",
        smtp_user="u",
        smtp_password="p",
        from_addr="cert-watch@co.com",
        recipients=["fallback@co.com"],
    )
    smtp = fake_transport(channel="smtp")
    engine = DigestEngine(db, [smtp])
    period = digest_period_key("orphan", 7)

    assert engine.run(OrphanDigestKind(config), period).sent == 1
    assert engine.run(OrphanDigestKind(config), period).sent == 0

    assert len(smtp.messages) == 1
    message = smtp.messages[0]
    assert message.recipients == ("boss@co.com",)
    assert "[orphan] lonely.example.com:443 — CN=lonely" in message.body
