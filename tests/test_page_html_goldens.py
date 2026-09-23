"""Characterize the server-rendered page contract before presenter refactors.

The snapshots deliberately retain template whitespace and markup.  Only values
that cannot be stable across independent demo-estate seeds are replaced: CSP
nonces, CSRF tokens, generated database IDs, certificate fingerprints, and
certificate serial numbers.  Time remains part of the contract; freezegun makes
all relative dates and generated-at values deterministic.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterator
from datetime import UTC, datetime
from difflib import unified_diff
from pathlib import Path

import pytest
from cryptography import x509
from fastapi.testclient import TestClient
from freezegun import freeze_time

from cert_watch.database import SqliteHostRepository, _connect
from cert_watch.scheduler import ScanHistory, record_scan_history
from tests.e2e._seed import seed_demo_certs

_GOLDEN_DIR = Path(__file__).with_name("golden") / "pages"
_FROZEN_NOW = "2026-09-22 12:00:00+00:00"

_PAGES = {
    "home": "/",
    "browse_grouped": "/browse?grouped=1",
    "browse_ungrouped": "/browse?grouped=0",
    "browse_by_issuer": "/browse?view=issuer",
    "browse_by_owner": "/browse?view=owner",
    "browse_by_renewal_method": "/browse?view=renewal_method",
    "browse_calendar": "/browse?view=calendar",
    "posture": "/posture",
    "readiness": "/readiness",
    "activity_alerts": "/alerts",
    "activity_scans": "/scan-history",
    "activity_audit": "/audit",
    "settings_auth": "/settings/auth",
    "settings_roles": "/settings/roles",
    "settings_users": "/settings/users",
    "settings_api_keys": "/settings/api-keys",
    "settings_tags": "/settings/tags",
    "settings_channels": "/settings/channels",
    "settings_alert_groups": "/settings/alert-groups",
    "settings_events": "/settings/events",
    "settings_policy": "/settings/policy",
    "settings_trust_anchors": "/settings/trust-anchors",
}


def _seed_characterization_estate(data_dir: Path, *, now: datetime) -> tuple[str, str]:
    """Seed the shared demo estate plus scanned and pending-host variants."""
    seed_demo_certs(data_dir, now=now)
    db = data_dir / "cert-watch.sqlite3"
    hosts = SqliteHostRepository(db)
    hosts.add(
        "mail.demo.test",
        tags="production, mail",
        scan_interval_hours=12,
        owner_name="Messaging Team",
        owner_email="messaging@example.test",
        renewal_status="in_progress",
        renewal_method="manual",
        runbook_url="https://runbooks.example.test/mail-tls",
        notes="Renew through the messaging runbook.",
    )
    pending_host_id = hosts.add(
        "pending.demo.test",
        port=8443,
        threshold_days=21,
        tags="staging, edge",
        owner_name="Edge Team",
        renewal_method="cert-manager",
        notes="Waiting for the first successful observation.",
    )
    with _connect(db) as conn:
        scanned = conn.execute(
            "SELECT id FROM certificates WHERE subject LIKE ?",
            ("%mail.demo.test%",),
        ).fetchone()
        assert scanned is not None
        conn.execute(
            "UPDATE certificates SET source = 'scanned', hostname = ?, port = ?, "
            "tags = ? WHERE id = ?",
            ("mail.demo.test", 443, "leaf-tag", scanned["id"]),
        )
        conn.commit()
    record_scan_history(
        db,
        ScanHistory(
            hostname="mail.demo.test",
            port=443,
            status="success",
            scanned_at=now,
        ),
    )
    record_scan_history(
        db,
        ScanHistory(
            hostname="pending.demo.test",
            port=8443,
            status="failure",
            error_message="TLS handshake failed",
            scanned_at=now,
        ),
    )
    return str(scanned["id"]), pending_host_id


def _dynamic_replacements(db: Path) -> list[tuple[str, str]]:
    replacements: list[tuple[str, str]] = []
    with _connect(db) as conn:
        certs = conn.execute(
            "SELECT id, subject, fingerprint_sha256, raw_der FROM certificates ORDER BY subject, id"
        ).fetchall()
        hosts = conn.execute("SELECT id, hostname FROM hosts ORDER BY hostname, id").fetchall()

    for index, row in enumerate(certs, 1):
        label = f"CERT_{index}"
        replacements.append((row["id"], f"{{{{{label}_ID}}}}"))
        fingerprint = row["fingerprint_sha256"]
        replacements.append((fingerprint, f"{{{{{label}_FINGERPRINT}}}}"))
        replacements.append((fingerprint[:8], f"{{{{{label}_FINGERPRINT_SHORT}}}}"))
        replacements.append(
            (
                ":".join(fingerprint[i : i + 2] for i in range(0, len(fingerprint), 2)).upper(),
                f"{{{{{label}_FINGERPRINT_COLON}}}}",
            )
        )
        parsed = x509.load_der_x509_certificate(bytes(row["raw_der"]))
        serial_hex = format(parsed.serial_number, "X")
        serial = ":".join(serial_hex[i : i + 2] for i in range(0, len(serial_hex), 2))
        replacements.append((serial, f"{{{{{label}_SERIAL}}}}"))

    for index, row in enumerate(hosts, 1):
        replacements.append((row["id"], f"{{{{HOST_{index}_ID}}}}"))
    return sorted(replacements, key=lambda item: len(item[0]), reverse=True)


def _normalize_html(html: str, replacements: list[tuple[str, str]]) -> str:
    normalized = html.replace("\r\n", "\n")
    normalized = re.sub(r'(\bnonce=")[^"]*(")', r"\1{{CSP_NONCE}}\2", normalized)
    normalized = re.sub(
        r'(<input\b[^>]*\bname="_csrf_token"[^>]*\bvalue=")[^"]*(")',
        r"\1{{CSRF_TOKEN}}\2",
        normalized,
    )
    normalized = re.sub(r'(\bdata-csrf=")[^"]*(")', r"\1{{CSRF_TOKEN}}\2", normalized)
    for value, placeholder in replacements:
        normalized = normalized.replace(value, placeholder)
    return "\n".join(line.rstrip() for line in normalized.splitlines()).rstrip() + "\n"


@pytest.fixture
def characterized_pages(tmp_path: Path, reload_app) -> Iterator[dict[str, str]]:
    # Import/build FastAPI before freezegun swaps ``datetime.date``.  Pydantic's
    # v1 compatibility module defines date subclasses lazily and cannot be
    # imported while freezegun's date metaclass is active on Python 3.13.
    app_mod = reload_app()
    frozen_now = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)
    cert_id, pending_host_id = _seed_characterization_estate(tmp_path, now=frozen_now)
    replacements = _dynamic_replacements(tmp_path / "cert-watch.sqlite3")
    with freeze_time(_FROZEN_NOW, ignore=["cryptography"]), TestClient(app_mod.app) as client:
        pages = {
            **_PAGES,
            "certificate_detail": f"/certificates/{cert_id}",
            "pending_host_detail": f"/certificates/{pending_host_id}",
        }
        rendered: dict[str, str] = {}
        for name, path in pages.items():
            response = client.get(path)
            assert response.status_code == 200, (name, path, response.status_code)
            assert response.headers["content-type"].startswith("text/html")
            rendered[name] = _normalize_html(response.text, replacements)
        yield rendered


def test_all_page_html_matches_characterization_goldens(
    characterized_pages: dict[str, str],
) -> None:
    update = os.environ.get("UPDATE_PAGE_GOLDENS") == "1"
    if update:
        _GOLDEN_DIR.mkdir(parents=True, exist_ok=True)

    assert set(characterized_pages) == set(_PAGES) | {
        "certificate_detail",
        "pending_host_detail",
    }
    for name, actual in characterized_pages.items():
        golden = _GOLDEN_DIR / f"{name}.html"
        if update:
            golden.write_text(actual, encoding="utf-8")
        expected = golden.read_text(encoding="utf-8")
        assert expected == actual, "".join(
            unified_diff(
                expected.splitlines(keepends=True),
                actual.splitlines(keepends=True),
                fromfile=f"golden/{name}.html",
                tofile=f"rendered/{name}.html",
            )
        )
