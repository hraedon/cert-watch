"""Tests for orphan alert routing (Plan 050, decision pinned 2026-06-20).

Covers the shared routing resolver (``resolve_cert_recipients``), orphan
detection (``find_orphan_certs``), admin-email resolution, and the admin orphan
notice folded into the weekly digest run.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cert_watch.alerts import (
    AlertConfig,
    find_orphan_certs,
    resolve_cert_recipients,
)
from cert_watch.certificate_model import Certificate
from cert_watch.database import (
    Role,
    SqliteAlertGroupRepository,
    SqliteCertificateRepository,
    SqliteHostRepository,
    SqliteRoleRepository,
    init_schema,
)
from cert_watch.database.users_roles import SqliteUserRepository, User
from cert_watch.digest import _admin_emails, send_orphan_notice, send_renewal_digest


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    db = tmp_path / "orphan.sqlite3"
    init_schema(db)
    return db


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


def test_orphan_when_no_group_no_owner(db_path: Path):
    cid = _add_leaf(db_path, "lonely.example.com")
    orphans = find_orphan_certs(db_path)
    assert [o["cert_id"] for o in orphans] == [cid]
    assert orphans[0]["hostname"] == "lonely.example.com"


def test_not_orphan_with_owner(db_path: Path):
    _add_leaf(db_path, "owned.example.com", owner_email="owner@co.com")
    assert find_orphan_certs(db_path) == []


def test_not_orphan_with_matching_group(db_path: Path):
    _add_leaf(db_path, "tagged.example.com", tags="prod")
    SqliteAlertGroupRepository(db_path).create("prod-oncall", ["oncall@co.com"], ["prod"])
    assert find_orphan_certs(db_path) == []


def test_not_orphan_when_routed_via_role_linked_group(db_path: Path):
    # No group match_tags include 'epic' and no owner — routing only happens via
    # the role→group link. find_orphan_certs must use the real resolver and see it.
    _add_leaf(db_path, "epic.example.com", tags="epic")
    gid = SqliteAlertGroupRepository(db_path).create("g", ["oncall@co.com"], ["unrelated"])
    SqliteRoleRepository(db_path).add(
        Role(name="epic-team", permission_tier="viewer", scope_tag="epic", alert_group_id=gid)
    )
    assert find_orphan_certs(db_path) == []


def test_orphans_sorted_by_host_then_subject(db_path: Path):
    _add_leaf(db_path, "zeta.example.com")
    _add_leaf(db_path, "alpha.example.com")
    orphans = find_orphan_certs(db_path)
    assert [o["hostname"] for o in orphans] == ["alpha.example.com", "zeta.example.com"]


# ---------- _admin_emails ----------


def test_admin_emails_only_admins(db_path: Path):
    _make_admin(db_path, "boss@co.com", tier="admin")
    _make_admin(db_path, "viewer@co.com", tier="viewer")
    _make_admin(db_path, "op@co.com", tier="operator")
    assert _admin_emails(db_path) == ["boss@co.com"]


def test_admin_emails_empty_when_none(db_path: Path):
    assert _admin_emails(db_path) == []


# ---------- send_orphan_notice ----------


def _patch_smtp() -> MagicMock:
    """Return a recording fake connection for _open_smtp_connection."""
    conn = MagicMock()
    conn.send_message = MagicMock()
    conn.quit = MagicMock()
    return conn


def _cfg() -> AlertConfig:
    return AlertConfig(
        smtp_host="smtp.example", smtp_user="u", smtp_password="p",
        from_addr="cert-watch@co.com", recipients=["fallback@co.com"],
    )


def test_orphan_notice_none_when_no_orphans(db_path: Path):
    _make_admin(db_path, "boss@co.com")
    _add_leaf(db_path, "owned.example.com", owner_email="owner@co.com")
    assert send_orphan_notice(db_path, _cfg()) is None


def test_orphan_notice_none_when_no_admins(db_path: Path):
    _add_leaf(db_path, "lonely.example.com")  # an orphan, but no admins
    assert send_orphan_notice(db_path, _cfg()) is None


def test_orphan_notice_none_when_config_not_alertconfig(db_path: Path):
    _make_admin(db_path, "boss@co.com")
    _add_leaf(db_path, "lonely.example.com")
    assert send_orphan_notice(db_path, None) is None


def test_orphan_notice_sends_to_admins_and_flags(db_path: Path):
    _make_admin(db_path, "boss@co.com")
    _add_leaf(db_path, "lonely.example.com", subject="CN=lonely")
    conn = _patch_smtp()
    with patch("cert_watch.alerts._open_smtp_connection", return_value=conn):
        assert send_orphan_notice(db_path, _cfg()) is True
    conn.send_message.assert_called_once()
    sent = conn.send_message.call_args[0][0]
    assert sent["To"] == "boss@co.com"
    assert "orphan" in sent["Subject"].lower()
    body = sent.get_content()
    assert "lonely.example.com" in body
    assert "[orphan]" in body


def test_orphan_notice_smtp_failure_returns_false(db_path: Path):
    _make_admin(db_path, "boss@co.com")
    _add_leaf(db_path, "lonely.example.com")
    with patch("cert_watch.alerts._open_smtp_connection", return_value=None):
        assert send_orphan_notice(db_path, _cfg()) is False


# ---------- integration: digest run triggers the orphan notice ----------


def test_send_renewal_digest_invokes_orphan_notice(db_path: Path):
    _make_admin(db_path, "boss@co.com")
    _add_leaf(db_path, "lonely.example.com")  # orphan, no renewal activity
    with patch("cert_watch.digest.send_orphan_notice") as spy:
        send_renewal_digest(db_path, _cfg(), None, days=7)
    spy.assert_called_once()
    assert spy.call_args[0][0] == db_path
