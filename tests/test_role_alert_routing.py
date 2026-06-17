"""Tests for WI-061 Role→AlertGroup link — role scope_tags route alerts to linked groups.

A cert tagged ``epic`` triggers an alert to a role's linked alert_group
recipients when the role has ``scope_tags=epic`` + a linked alert_group,
even with NO alert_group whose ``match_tags`` contains ``epic``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from cert_watch.alerts import evaluate_all_certs, resolve_group_recipients
from cert_watch.certificate_model import Certificate
from cert_watch.database import (
    Role,
    SqliteAlertGroupRepository,
    SqliteAlertRepository,
    SqliteCertificateRepository,
    SqliteHostRepository,
    SqliteRoleRepository,
    init_schema,
)

# ---------- helpers ----------


def _make_cert(
    repo: SqliteCertificateRepository,
    *,
    fingerprint: str = "aa" * 32,
    not_after: datetime | None = None,
    subject: str = "CN=test.example.com",
) -> str:
    cert = Certificate(
        subject=subject,
        issuer="CN=issuer",
        not_before=datetime.now(UTC) - timedelta(days=360),
        not_after=not_after or (datetime.now(UTC) + timedelta(days=5)),
        san_dns_names=["test.example.com"],
        fingerprint_sha256=fingerprint,
        raw_der=b"\x00" * 10,
        is_leaf=True,
    )
    return repo.add(cert)


# ---------- fixtures ----------


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    db = tmp_path / "test.sqlite3"
    init_schema(db)
    return db


# ---------- Role→AlertGroup routing ----------


class TestRoleAlertGroupRouting:
    def test_role_scope_tag_routes_to_linked_group(self, db_path: Path):
        """A cert tagged 'epic' triggers an alert to a role's linked alert_group
        recipients when the role has scope_tags=epic + a linked alert_group,
        even with NO alert_group whose match_tags contains epic.
        """
        # Set up a host + cert tagged "epic"
        host_repo = SqliteHostRepository(db_path)
        host_repo.add("h.example.com", 443, tags="epic")
        cert_repo = SqliteCertificateRepository(
            db_path, hostname="h.example.com", port=443
        )
        cert_id = _make_cert(cert_repo)

        # Create an alert_group with match_tags that do NOT include "epic"
        group_repo = SqliteAlertGroupRepository(db_path)
        gid = group_repo.create(
            "epic-oncall", ["oncall@co.com"], ["unrelated-tag"]
        )

        # Create a role with scope_tag=epic linked to that alert_group
        role_repo = SqliteRoleRepository(db_path)
        role_repo.add(Role(
            name="epic-team",
            permission_tier="viewer",
            scope_tag="epic",
            alert_group_id=gid,
        ))

        # resolve_group_recipients should include the linked group's recipients
        recipients = resolve_group_recipients(db_path, cert_id)
        assert "oncall@co.com" in recipients

    def test_role_routing_no_link_does_not_fire(self, db_path: Path):
        """A role with scope_tag=epic but NO linked alert_group does not route."""
        host_repo = SqliteHostRepository(db_path)
        host_repo.add("h.example.com", 443, tags="epic")
        cert_repo = SqliteCertificateRepository(
            db_path, hostname="h.example.com", port=443
        )
        cert_id = _make_cert(cert_repo)

        group_repo = SqliteAlertGroupRepository(db_path)
        group_repo.create("other", ["other@co.com"], ["unrelated"])

        role_repo = SqliteRoleRepository(db_path)
        role_repo.add(Role(
            name="epic-team",
            permission_tier="viewer",
            scope_tag="epic",
            alert_group_id=None,
        ))

        recipients = resolve_group_recipients(db_path, cert_id)
        assert recipients == []

    def test_role_routing_no_scope_tag_does_not_fire(self, db_path: Path):
        """A role with a linked alert_group but NO scope_tag does not route via role."""
        host_repo = SqliteHostRepository(db_path)
        host_repo.add("h.example.com", 443, tags="epic")
        cert_repo = SqliteCertificateRepository(
            db_path, hostname="h.example.com", port=443
        )
        cert_id = _make_cert(cert_repo)

        group_repo = SqliteAlertGroupRepository(db_path)
        gid = group_repo.create("oncall", ["oncall@co.com"], ["unrelated"])

        role_repo = SqliteRoleRepository(db_path)
        role_repo.add(Role(
            name="team",
            permission_tier="viewer",
            scope_tag="",
            alert_group_id=gid,
        ))

        recipients = resolve_group_recipients(db_path, cert_id)
        assert recipients == []

    def test_role_routing_tag_mismatch_does_not_fire(self, db_path: Path):
        """A role with scope_tag=other does not route for a cert tagged epic."""
        host_repo = SqliteHostRepository(db_path)
        host_repo.add("h.example.com", 443, tags="epic")
        cert_repo = SqliteCertificateRepository(
            db_path, hostname="h.example.com", port=443
        )
        cert_id = _make_cert(cert_repo)

        group_repo = SqliteAlertGroupRepository(db_path)
        gid = group_repo.create("oncall", ["oncall@co.com"], ["unrelated"])

        role_repo = SqliteRoleRepository(db_path)
        role_repo.add(Role(
            name="other-team",
            permission_tier="viewer",
            scope_tag="other",
            alert_group_id=gid,
        ))

        recipients = resolve_group_recipients(db_path, cert_id)
        assert recipients == []

    def test_role_routing_multi_tag_scope(self, db_path: Path):
        """A role with comma-separated scope tags routes for any matching tag."""
        host_repo = SqliteHostRepository(db_path)
        host_repo.add("h.example.com", 443, tags="monitoring")
        cert_repo = SqliteCertificateRepository(
            db_path, hostname="h.example.com", port=443
        )
        cert_id = _make_cert(cert_repo)

        group_repo = SqliteAlertGroupRepository(db_path)
        gid = group_repo.create("oncall", ["oncall@co.com"], ["unrelated"])

        role_repo = SqliteRoleRepository(db_path)
        role_repo.add(Role(
            name="sre-team",
            permission_tier="viewer",
            scope_tag="epic, infra, monitoring",
            alert_group_id=gid,
        ))

        recipients = resolve_group_recipients(db_path, cert_id)
        assert "oncall@co.com" in recipients

    def test_evaluate_all_certs_includes_role_linked_recipients(self, db_path: Path):
        """evaluate_all_certs includes role-linked alert_group recipients in extra_recipients."""
        host_repo = SqliteHostRepository(db_path)
        host_repo.add(
            "h.example.com", 443,
            tags="epic",
            owner_name="Alice",
            owner_email="alice@co.com",
        )
        cert_repo = SqliteCertificateRepository(
            db_path, hostname="h.example.com", port=443
        )
        _make_cert(cert_repo)

        group_repo = SqliteAlertGroupRepository(db_path)
        gid = group_repo.create("epic-oncall", ["oncall@co.com"], ["unrelated"])

        role_repo = SqliteRoleRepository(db_path)
        role_repo.add(Role(
            name="epic-team",
            permission_tier="viewer",
            scope_tag="epic",
            alert_group_id=gid,
        ))

        alert_repo = SqliteAlertRepository(db_path)
        alerts = evaluate_all_certs(db_path, alert_repo)
        assert len(alerts) > 0
        for a in alerts:
            assert "oncall@co.com" in a.extra_recipients
            assert "alice@co.com" in a.extra_recipients

    def test_role_routing_deduped_with_group_match(self, db_path: Path):
        """When both an alert_group match_tags AND a role scope_tag match the
        same cert, the linked group's recipients are deduped.
        """
        host_repo = SqliteHostRepository(db_path)
        host_repo.add("h.example.com", 443, tags="epic")
        cert_repo = SqliteCertificateRepository(
            db_path, hostname="h.example.com", port=443
        )
        cert_id = _make_cert(cert_repo)

        group_repo = SqliteAlertGroupRepository(db_path)
        # Group matches via match_tags=epic
        gid = group_repo.create("epic-group", ["shared@co.com"], ["epic"])

        role_repo = SqliteRoleRepository(db_path)
        # Role also links to the same group with scope_tag=epic
        role_repo.add(Role(
            name="epic-team",
            permission_tier="viewer",
            scope_tag="epic",
            alert_group_id=gid,
        ))

        recipients = resolve_group_recipients(db_path, cert_id)
        assert recipients.count("shared@co.com") == 1

    def test_role_routing_inherited_host_tag(self, db_path: Path):
        """Role scope_tag matches a tag inherited from the host (not cert's own tags)."""
        host_repo = SqliteHostRepository(db_path)
        host_repo.add("h.example.com", 443, tags="team-infra")
        cert_repo = SqliteCertificateRepository(
            db_path, hostname="h.example.com", port=443
        )
        cert_id = _make_cert(cert_repo)
        # Cert has no own tags, but inherits team-infra from host

        group_repo = SqliteAlertGroupRepository(db_path)
        gid = group_repo.create("infra-oncall", ["infra@co.com"], ["unrelated"])

        role_repo = SqliteRoleRepository(db_path)
        role_repo.add(Role(
            name="infra-team",
            permission_tier="viewer",
            scope_tag="team-infra",
            alert_group_id=gid,
        ))

        recipients = resolve_group_recipients(db_path, cert_id)
        assert "infra@co.com" in recipients

    def test_deleting_linked_alert_group_clears_role_link(self, db_path: Path):
        """Deleting an alert_group NULLs roles.alert_group_id (WI-061 orphan cleanup).

        SQLite does not enforce ON DELETE SET NULL without PRAGMA foreign_keys=ON
        (which the app does not set), so the repo must clear the link explicitly.
        Otherwise a stale reference would silently stop the role's alert routing
        (group_by_id.get returns None) and leave orphan data in the roles table.
        """
        group_repo = SqliteAlertGroupRepository(db_path)
        gid = group_repo.create("doomed", ["oncall@co.com"], ["unrelated"])

        role_repo = SqliteRoleRepository(db_path)
        role_repo.add(Role(
            name="epic-team",
            permission_tier="viewer",
            scope_tag="epic",
            alert_group_id=gid,
        ))
        assert role_repo.get_by_name("epic-team").alert_group_id == gid

        # Delete the linked group; the role link must be cleared, not orphaned.
        assert group_repo.delete(gid) is True
        refreshed = role_repo.get_by_name("epic-team")
        assert refreshed.alert_group_id is None
