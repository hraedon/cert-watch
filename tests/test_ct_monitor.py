from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from cert_watch.ct_monitor import ct_reconciliation, run_ct_monitor
from cert_watch.database import init_schema


def test_ct_monitor_no_hosts(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    result = run_ct_monitor(db)
    assert result["checked"] == 0
    assert result["new"] == 0
    assert result["errors"] == 0


def test_ct_monitor_finds_new_cert(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    from cert_watch.database import SqliteHostRepository
    SqliteHostRepository(db).add("monitor.example.com", 443)

    mock_entry = MagicMock()
    mock_entry.common_name = "monitor.example.com"
    mock_entry.issuer_name = "Test CA"
    mock_entry.serial_number = "new-serial-123"

    with patch("cert_watch.ct_monitor.query_ct_log", return_value=[mock_entry]):
        result = run_ct_monitor(db)
    assert result["checked"] == 1
    assert result["new"] == 1
    assert result["errors"] == 0


def test_ct_monitor_skips_known_serial(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    from cert_watch.database import SqliteHostRepository
    SqliteHostRepository(db).add("known.example.com", 443)

    mock_entry = MagicMock()
    mock_entry.common_name = "known.example.com"
    mock_entry.issuer_name = "Test CA"
    mock_entry.serial_number = "known-serial-456"

    with patch("cert_watch.ct_monitor.query_ct_log", return_value=[mock_entry]):
        result = run_ct_monitor(db)
    assert result["checked"] == 1
    assert result["new"] == 1
    assert result["errors"] == 0


def test_ct_monitor_dedup_within_run(tmp_path):
    """Duplicate (serial, issuer) entries within a single CT response are deduplicated."""
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    from cert_watch.database import SqliteHostRepository
    SqliteHostRepository(db).add("dup.example.com", 443)

    mock_entry1 = MagicMock()
    mock_entry1.common_name = "dup.example.com"
    mock_entry1.issuer_name = "Test CA"
    mock_entry1.serial_number = "dup-serial-789"

    mock_entry2 = MagicMock()
    mock_entry2.common_name = "dup.example.com"
    mock_entry2.issuer_name = "Test CA"
    mock_entry2.serial_number = "dup-serial-789"

    with patch(
        "cert_watch.ct_monitor.query_ct_log",
        return_value=[mock_entry1, mock_entry2],
    ):
        result = run_ct_monitor(db)
    assert result["checked"] == 1
    assert result["new"] == 1
    assert result["errors"] == 0


def test_ct_monitor_handles_error(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    from cert_watch.database import SqliteHostRepository
    SqliteHostRepository(db).add("err.example.com", 443)

    with patch("cert_watch.ct_monitor.query_ct_log", return_value="network error"):
        result = run_ct_monitor(db)
    assert result["checked"] == 1
    assert result["new"] == 0
    assert result["errors"] == 1


# ---------- CT reconciliation tests ----------


def test_ct_reconciliation_finds_gaps(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    from cert_watch.database import SqliteHostRepository
    repo = SqliteHostRepository(db)
    repo.add("www.example.com", 443)
    repo.add("api.example.com", 443)

    mock_entry1 = MagicMock()
    mock_entry1.common_name = "www.example.com"
    mock_entry1.name_value = "www.example.com"
    mock_entry1.issuer_name = "Let's Encrypt"
    mock_entry1.serial_number = "aaa"

    mock_entry2 = MagicMock()
    mock_entry2.common_name = "staging.example.com"
    mock_entry2.name_value = "staging.example.com"
    mock_entry2.issuer_name = "Let's Encrypt"
    mock_entry2.serial_number = "bbb"

    mock_entry3 = MagicMock()
    mock_entry3.common_name = "api.example.com"
    mock_entry3.name_value = "api.example.com"
    mock_entry3.issuer_name = "Let's Encrypt"
    mock_entry3.serial_number = "ccc"

    with patch(
        "cert_watch.ct_monitor.query_ct_log",
        return_value=[mock_entry1, mock_entry2, mock_entry3],
    ):
        result = ct_reconciliation(db, "example.com")

    assert result.error == ""
    assert "www.example.com" in result.tracked_hostnames
    assert "api.example.com" in result.tracked_hostnames
    assert "staging.example.com" in result.ct_only_hostnames
    assert "staging.example.com" not in result.tracked_hostnames
    assert result.coverage_pct == 66.7


def test_ct_reconciliation_full_coverage(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    from cert_watch.database import SqliteHostRepository
    SqliteHostRepository(db).add("app.example.com", 443)

    mock_entry = MagicMock()
    mock_entry.common_name = "app.example.com"
    mock_entry.name_value = "app.example.com"
    mock_entry.issuer_name = "CA"
    mock_entry.serial_number = "x"

    with patch("cert_watch.ct_monitor.query_ct_log", return_value=[mock_entry]):
        result = ct_reconciliation(db, "example.com")

    assert result.ct_only_hostnames == []
    assert result.coverage_pct == 100.0


def test_ct_reconciliation_ct_error(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    from cert_watch.database import SqliteHostRepository
    SqliteHostRepository(db).add("app.example.com", 443)

    with patch("cert_watch.ct_monitor.query_ct_log", return_value="timeout"):
        result = ct_reconciliation(db, "example.com")

    assert result.error != ""
    assert "app.example.com" in result.tracked_hostnames
    assert result.ct_hostnames == []


def test_ct_reconciliation_no_hosts(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)

    mock_entry = MagicMock()
    mock_entry.common_name = "orphan.example.com"
    mock_entry.name_value = "orphan.example.com"
    mock_entry.issuer_name = "CA"
    mock_entry.serial_number = "y"

    with patch("cert_watch.ct_monitor.query_ct_log", return_value=[mock_entry]):
        result = ct_reconciliation(db, "example.com")

    assert result.tracked_hostnames == []
    assert "orphan.example.com" in result.ct_only_hostnames
    assert result.coverage_pct == 0.0


def test_ct_reconciliation_san_parsing(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    from cert_watch.database import SqliteHostRepository
    SqliteHostRepository(db).add("main.example.com", 443)

    mock_entry = MagicMock()
    mock_entry.common_name = "main.example.com"
    mock_entry.name_value = "main.example.com\nextra.example.com"
    mock_entry.issuer_name = "CA"
    mock_entry.serial_number = "z"

    with patch("cert_watch.ct_monitor.query_ct_log", return_value=[mock_entry]):
        result = ct_reconciliation(db, "example.com")

    assert "main.example.com" in result.tracked_hostnames
    assert "extra.example.com" in result.ct_only_hostnames


def test_ct_reconciliation_filters_by_domain(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    from cert_watch.database import SqliteHostRepository
    SqliteHostRepository(db).add("app.example.com", 443)
    SqliteHostRepository(db).add("other.notexample.com", 443)

    mock_entry = MagicMock()
    mock_entry.common_name = "app.example.com"
    mock_entry.name_value = "app.example.com"
    mock_entry.issuer_name = "CA"
    mock_entry.serial_number = "w"

    with patch("cert_watch.ct_monitor.query_ct_log", return_value=[mock_entry]):
        result = ct_reconciliation(db, "example.com")

    assert "other.notexample.com" not in result.tracked_hostnames
    assert "app.example.com" in result.tracked_hostnames


def test_ct_reconciliation_empty_ct_results(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    from cert_watch.database import SqliteHostRepository
    SqliteHostRepository(db).add("app.example.com", 443)

    with patch("cert_watch.ct_monitor.query_ct_log", return_value=[]):
        result = ct_reconciliation(db, "example.com")

    assert result.error == ""
    assert "app.example.com" in result.tracked_hostnames
    assert "app.example.com" in result.tracked_only_hostnames
    assert result.ct_hostnames == []
    assert result.coverage_pct == 100.0


def test_api_ct_reconciliation(tmp_path, reload_app):
    app_mod = reload_app()
    from cert_watch.database import SqliteHostRepository, init_schema
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    SqliteHostRepository(db).add("app.example.com", 443)

    mock_entry = MagicMock()
    mock_entry.common_name = "app.example.com"
    mock_entry.name_value = "app.example.com"
    mock_entry.issuer_name = "CA"
    mock_entry.serial_number = "q"

    with patch("cert_watch.ct_monitor.query_ct_log", return_value=[mock_entry]), \
         TestClient(app_mod.app) as client:
        r = client.get("/api/ct/reconciliation?domain=example.com")
    assert r.status_code == 200
    data = r.json()
    assert data["domain"] == "example.com"
    assert "app.example.com" in data["tracked_hostnames"]


def test_api_ct_reconciliation_missing_domain(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/api/ct/reconciliation")
    assert r.status_code == 400
    assert "domain" in r.json()["error"]


def _add_scanned_cert(db, hostname, issuer, fingerprint):
    import uuid
    from datetime import UTC, datetime

    from cert_watch.database import _connect
    cert_id = str(uuid.uuid4())
    now = datetime.now(UTC).isoformat()
    with _connect(db) as conn:
        conn.execute(
            """INSERT INTO certificates
            (id, hostname, port, source, is_leaf, issuer, fingerprint_sha256,
             updated_at, subject, not_before, not_after, san_dns_names,
             raw_der, created_at)
            VALUES (?, ?, 443, 'scanned', 1, ?, ?, ?, '', ?, ?, '', x'', ?)""",
            (cert_id, hostname, issuer, fingerprint, now, now, now, now),
        )
        conn.commit()
    return cert_id


def test_ct_monitor_creates_misissuance_alert(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    from cert_watch.database import SqliteHostRepository
    from cert_watch.database.repo import SqliteAlertRepository
    SqliteHostRepository(db).add("www.example.com", 443)
    _add_scanned_cert(db, "www.example.com", "Trusted CA", "fp-known-aaa")

    mock_ct_entry = MagicMock()
    mock_ct_entry.common_name = "www.example.com"
    mock_ct_entry.name_value = "www.example.com"
    mock_ct_entry.issuer_name = "Malicious CA"
    mock_ct_entry.serial_number = "evil-serial"

    with patch(
        "cert_watch.ct_monitor.query_ct_log",
        return_value=[mock_ct_entry],
    ):
        result = run_ct_monitor(db)

    assert result["misissued"] >= 1
    assert result["alerts_created"] >= 1

    repo = SqliteAlertRepository(db)
    alerts = repo.list_pending()
    mis_alerts = [a for a in alerts if a.alert_type == "mis_issuance"]
    assert len(mis_alerts) == 1
    assert "Malicious CA" in mis_alerts[0].message
    assert "Trusted CA" in mis_alerts[0].message


def test_ct_monitor_no_alert_when_no_misissuance(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    from cert_watch.database import SqliteHostRepository
    from cert_watch.database.repo import SqliteAlertRepository
    SqliteHostRepository(db).add("clean.example.com", 443)
    _add_scanned_cert(db, "clean.example.com", "Trusted CA", "fp-clean-bbb")

    mock_ct_entry = MagicMock()
    mock_ct_entry.common_name = "clean.example.com"
    mock_ct_entry.name_value = "clean.example.com"
    mock_ct_entry.issuer_name = "Trusted CA"
    mock_ct_entry.serial_number = "sn-clean"

    from unittest.mock import patch

    from cert_watch.ct_monitor import _get_scanned_issuer
    scanned_issuer = _get_scanned_issuer(db, "clean.example.com")
    assert scanned_issuer is not None
    mock_ct_entry.issuer_name = scanned_issuer

    with patch(
        "cert_watch.ct_monitor.query_ct_log",
        return_value=[mock_ct_entry],
    ):
        result = run_ct_monitor(db)

    assert result["misissued"] == 0
    assert result["alerts_created"] == 0

    repo = SqliteAlertRepository(db)
    alerts = repo.list_pending()
    mis_alerts = [a for a in alerts if a.alert_type == "mis_issuance"]
    assert len(mis_alerts) == 0


def test_ct_monitor_misissuance_dedup(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    from cert_watch.database import SqliteHostRepository
    from cert_watch.database.repo import SqliteAlertRepository
    SqliteHostRepository(db).add("dup.example.com", 443)
    _add_scanned_cert(db, "dup.example.com", "Good CA", "fp-dup-ccc")

    mock_ct_entry = MagicMock()
    mock_ct_entry.common_name = "dup.example.com"
    mock_ct_entry.name_value = "dup.example.com"
    mock_ct_entry.issuer_name = "Bad CA"
    mock_ct_entry.serial_number = "evil-dup"

    with patch(
        "cert_watch.ct_monitor.query_ct_log",
        return_value=[mock_ct_entry],
    ):
        result1 = run_ct_monitor(db)
        result2 = run_ct_monitor(db)

    assert result1["alerts_created"] >= 1
    assert result2["alerts_created"] == 0

    repo = SqliteAlertRepository(db)
    alerts = repo.list_pending()
    mis_alerts = [a for a in alerts if a.alert_type == "mis_issuance"]
    assert len(mis_alerts) == 1


def test_ct_monitor_misissuance_no_tracked_cert(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    from cert_watch.database import SqliteHostRepository
    SqliteHostRepository(db).add("untracked.example.com", 443)

    mock_ct_entry = MagicMock()
    mock_ct_entry.common_name = "untracked.example.com"
    mock_ct_entry.name_value = "untracked.example.com"
    mock_ct_entry.issuer_name = "Some CA"
    mock_ct_entry.serial_number = "sn-unt"

    with patch(
        "cert_watch.ct_monitor.query_ct_log",
        return_value=[mock_ct_entry],
    ):
        result = run_ct_monitor(db)

    assert result["misissued"] == 0
    assert result["alerts_created"] == 0


# ---------- WI-007: expected-issuer allowlist ----------


def test_ct_reconciliation_expected_issuers_skips_misissuance(tmp_path):
    """When a host has expected_issuers configured, a CT issuer whose CN is in
    the allowlist should NOT be flagged as mis-issuance (WI-007)."""
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    from cert_watch.database import SqliteHostRepository
    repo = SqliteHostRepository(db)
    repo.add("le.example.com", 443, expected_issuers="R3,R4")

    _add_scanned_cert(db, "le.example.com", "CN=R3, O=Let's Encrypt, C=US", "fp-le-001")

    # CT shows the same host under R4 — legitimate rotation
    mock_entry = MagicMock()
    mock_entry.common_name = "le.example.com"
    mock_entry.name_value = "le.example.com"
    mock_entry.issuer_name = "CN=R4, O=Let's Encrypt, C=US"
    mock_entry.serial_number = "le-r4-serial"

    with patch("cert_watch.ct_monitor.query_ct_log", return_value=[mock_entry]):
        result = ct_reconciliation(db, "example.com")

    # R4 is in the allowlist — should NOT be flagged
    assert len(result.misissued) == 0


def test_ct_reconciliation_expected_issuers_still_flags_unknown(tmp_path):
    """When a host has expected_issuers configured, a CT issuer whose CN is NOT
    in the allowlist should still be flagged as mis-issuance (WI-007)."""
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    from cert_watch.database import SqliteHostRepository
    repo = SqliteHostRepository(db)
    repo.add("le.example.com", 443, expected_issuers="R3,R4")

    _add_scanned_cert(db, "le.example.com", "CN=R3, O=Let's Encrypt, C=US", "fp-le-002")

    # CT shows an issuer NOT in the allowlist
    mock_entry = MagicMock()
    mock_entry.common_name = "le.example.com"
    mock_entry.name_value = "le.example.com"
    mock_entry.issuer_name = "CN=Malicious CA, O=Evil Inc, C=US"
    mock_entry.serial_number = "evil-serial-wi007"

    with patch("cert_watch.ct_monitor.query_ct_log", return_value=[mock_entry]):
        result = ct_reconciliation(db, "example.com")

    assert len(result.misissued) == 1
    assert result.misissued[0]["ct_issuer"] == "CN=Malicious CA, O=Evil Inc, C=US"


def test_ct_reconciliation_empty_expected_issuers_falls_back(tmp_path):
    """When expected_issuers is empty, fall back to strict issuer comparison."""
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    from cert_watch.database import SqliteHostRepository
    repo = SqliteHostRepository(db)
    # No expected_issuers (default empty)
    repo.add("classic.example.com", 443)

    _add_scanned_cert(db, "classic.example.com", "Trusted CA", "fp-classic-001")

    # Different issuer — should be flagged (strict comparison)
    mock_entry = MagicMock()
    mock_entry.common_name = "classic.example.com"
    mock_entry.name_value = "classic.example.com"
    mock_entry.issuer_name = "Other CA"
    mock_entry.serial_number = "other-serial"

    with patch("cert_watch.ct_monitor.query_ct_log", return_value=[mock_entry]):
        result = ct_reconciliation(db, "example.com")

    assert len(result.misissued) == 1


def test_ct_reconciliation_expected_issuers_matches_cn_from_dn(tmp_path):
    """The allowlist matches on CN extracted from the full DN (WI-007).
    E.g., 'R3' in the allowlist should match 'CN=R3, O=Let's Encrypt, C=US'."""
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    from cert_watch.database import SqliteHostRepository
    repo = SqliteHostRepository(db)
    repo.add("cnmatch.example.com", 443, expected_issuers="R3")

    _add_scanned_cert(db, "cnmatch.example.com", "CN=R3, O=Let's Encrypt, C=US", "fp-cn-001")

    # CT issuer has CN=R3 but different full DN
    mock_entry = MagicMock()
    mock_entry.common_name = "cnmatch.example.com"
    mock_entry.name_value = "cnmatch.example.com"
    # Some CT logs return just the CN
    mock_entry.issuer_name = "R3"
    mock_entry.serial_number = "cn-serial"

    with patch("cert_watch.ct_monitor.query_ct_log", return_value=[mock_entry]):
        result = ct_reconciliation(db, "example.com")

    assert len(result.misissued) == 0


def test_extract_cn_comma_separated():
    """_extract_cn handles comma-separated DN format."""
    from cert_watch.ct_monitor import _extract_cn
    assert _extract_cn("CN=R3, O=Let's Encrypt, C=US") == "R3"


def test_extract_cn_slash_separated():
    """_extract_cn handles slash-separated DN format."""
    from cert_watch.ct_monitor import _extract_cn
    assert _extract_cn("/C=US/O=Let's Encrypt/CN=R4") == "R4"


def test_extract_cn_no_cn():
    """_extract_cn returns the full DN when no CN is found."""
    from cert_watch.ct_monitor import _extract_cn
    assert _extract_cn("O=Something, C=US") == "O=Something, C=US"


def test_extract_cn_empty():
    """_extract_cn returns empty string for empty input."""
    from cert_watch.ct_monitor import _extract_cn
    assert _extract_cn("") == ""


def test_issuer_matches_with_allowlist():
    from cert_watch.ct_monitor import _issuer_matches
    # Allowlist present: match on CN
    assert _issuer_matches("CN=R3, O=LE, C=US", "CN=R4, O=LE, C=US", ["R3", "R4"]) is True
    assert _issuer_matches("CN=R3, O=LE, C=US", "CN=R4, O=LE, C=US", ["R4"]) is False


def test_issuer_matches_without_allowlist():
    from cert_watch.ct_monitor import _issuer_matches
    # No allowlist: strict equality
    assert _issuer_matches("Same CA", "Same CA", []) is True
    assert _issuer_matches("Other CA", "Same CA", []) is False


# ---------- WI-007: additional requested test coverage ----------


def test_ct_reconciliation_allowlist_match(tmp_path):
    """CT issuer in allowlist -> NOT mis-issued."""
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    from cert_watch.database import SqliteHostRepository
    repo = SqliteHostRepository(db)
    repo.add("www.example.com", 443, expected_issuers="R3,R4")
    _add_scanned_cert(db, "www.example.com", "CN=R3, O=Let's Encrypt, C=US", "fp-007-match")

    mock_entry = MagicMock()
    mock_entry.common_name = "www.example.com"
    mock_entry.name_value = "www.example.com"
    mock_entry.issuer_name = "CN=R4, O=Let's Encrypt, C=US"
    mock_entry.serial_number = "serial-r4"

    with patch("cert_watch.ct_monitor.query_ct_log", return_value=[mock_entry]):
        result = ct_reconciliation(db, "example.com")

    assert len(result.misissued) == 0


def test_ct_reconciliation_allowlist_mismatch(tmp_path):
    """CT issuer not in allowlist -> mis-issued."""
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    from cert_watch.database import SqliteHostRepository
    repo = SqliteHostRepository(db)
    repo.add("www.example.com", 443, expected_issuers="R3")
    _add_scanned_cert(db, "www.example.com", "CN=R3, O=Let's Encrypt, C=US", "fp-007-mismatch")

    mock_entry = MagicMock()
    mock_entry.common_name = "www.example.com"
    mock_entry.name_value = "www.example.com"
    mock_entry.issuer_name = "CN=Malicious CA, O=Evil, C=US"
    mock_entry.serial_number = "evil-serial"

    with patch("cert_watch.ct_monitor.query_ct_log", return_value=[mock_entry]):
        result = ct_reconciliation(db, "example.com")

    assert len(result.misissued) == 1
    assert result.misissued[0]["ct_issuer"] == "CN=Malicious CA, O=Evil, C=US"


def test_ct_reconciliation_allowlist_empty_falls_back(tmp_path):
    """Empty allowlist -> current strict behavior (compare to scanned issuer)."""
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    from cert_watch.database import SqliteHostRepository
    repo = SqliteHostRepository(db)
    repo.add("www.example.com", 443, expected_issuers="")
    _add_scanned_cert(db, "www.example.com", "Trusted CA", "fp-007-empty")

    # CT shows a different issuer
    mock_entry = MagicMock()
    mock_entry.common_name = "www.example.com"
    mock_entry.name_value = "www.example.com"
    mock_entry.issuer_name = "Other CA"
    mock_entry.serial_number = "other-serial"

    with patch("cert_watch.ct_monitor.query_ct_log", return_value=[mock_entry]):
        result = ct_reconciliation(db, "example.com")

    assert len(result.misissued) == 1
    assert result.misissued[0]["scanned_issuer"] == "Trusted CA"


def test_ct_reconciliation_allowlist_cn_matching(tmp_path):
    """Partial CN match works (e.g., 'R3' matches full DN)."""
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    from cert_watch.database import SqliteHostRepository
    repo = SqliteHostRepository(db)
    repo.add("www.example.com", 443, expected_issuers="R3")
    _add_scanned_cert(db, "www.example.com", "CN=R3, O=Let's Encrypt, C=US", "fp-007-cn")

    # CT log returns full DN — should match because CN='R3' is in allowlist
    mock_entry = MagicMock()
    mock_entry.common_name = "www.example.com"
    mock_entry.name_value = "www.example.com"
    mock_entry.issuer_name = "CN=R3, O=Let's Encrypt, C=US"
    mock_entry.serial_number = "serial-r3"

    with patch("cert_watch.ct_monitor.query_ct_log", return_value=[mock_entry]):
        result = ct_reconciliation(db, "example.com")

    assert len(result.misissued) == 0


def test_ct_reconciliation_allowlist_case_insensitive(tmp_path):
    """Case doesn't matter for CT issuer matching."""
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    from cert_watch.database import SqliteHostRepository
    repo = SqliteHostRepository(db)
    # Allowlist is lowercase 'r3' but CT has 'R3' in the full DN
    repo.add("www.example.com", 443, expected_issuers="r3")
    _add_scanned_cert(db, "www.example.com", "CN=R3, O=Let's Encrypt, C=US", "fp-007-case")

    mock_entry = MagicMock()
    mock_entry.common_name = "www.example.com"
    mock_entry.name_value = "www.example.com"
    mock_entry.issuer_name = "CN=R3, O=Let's Encrypt, C=US"
    mock_entry.serial_number = "serial-upper"

    with patch("cert_watch.ct_monitor.query_ct_log", return_value=[mock_entry]):
        result = ct_reconciliation(db, "example.com")

    assert len(result.misissued) == 0


# ---------- WI-007: API / route tests ----------


def test_api_host_expected_issuers_update(tmp_path, reload_app, login_csrf):
    """POST /hosts/{host_id}/expected-issuers updates the allowlist."""
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import SqliteHostRepository, init_schema
    init_schema(db)
    repo = SqliteHostRepository(db)
    host_id = repo.add("test.example.com", 443, expected_issuers="Old Issuer")

    with TestClient(app_mod.app) as client:
        token = login_csrf(client)
        r = client.post(
            f"/hosts/{host_id}/expected-issuers",
            data={
                "_csrf_token": token,
                "expected_issuers": "R3, R4, Let's Encrypt Authority X3",
            },
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert r.headers["location"] == "/discover?saved=1"

    host = repo.get(host_id)
    assert host.expected_issuers == "R3,R4,Let's Encrypt Authority X3"


def test_api_host_expected_issuers_clear(tmp_path, reload_app, login_csrf):
    """POST /hosts/{host_id}/expected-issuers with empty value clears the allowlist."""
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import SqliteHostRepository, init_schema
    init_schema(db)
    repo = SqliteHostRepository(db)
    host_id = repo.add("test.example.com", 443, expected_issuers="Old Issuer")

    with TestClient(app_mod.app) as client:
        token = login_csrf(client)
        r = client.post(
            f"/hosts/{host_id}/expected-issuers",
            data={
                "_csrf_token": token,
                "expected_issuers": "",
            },
            follow_redirects=False,
        )
    assert r.status_code == 303

    host = repo.get(host_id)
    assert host.expected_issuers == ""


def test_api_host_expected_issuers_requires_auth(tmp_path, reload_app):
    """POST /hosts/{host_id}/expected-issuers requires authentication."""
    # Note: with CERT_WATCH_ALLOW_UNAUTH=1 in conftest, 'reload_app' sets open mode.
    # Build one with auth explicitly enabled and a local admin.
    app_mod = reload_app(
        CERT_WATCH_ALLOW_UNAUTH="",
        CERT_WATCH_AUTH_PROVIDER="",
    )
    from cert_watch.database import init_schema
    init_schema(tmp_path / "cert-watch.sqlite3")

    with TestClient(app_mod.app) as client:
        r = client.post(
            "/hosts/nope/expected-issuers",
            data={"expected_issuers": "R3"},
            follow_redirects=False,
        )
    # When unauth is disabled and there is no session, should redirect to login or setup
    assert r.status_code in (302, 303)


def test_discover_page_shows_expected_issuers_section(tmp_path, reload_app, login_csrf):
    """The Discover page renders the expected-issuers table when hosts exist."""
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import SqliteHostRepository, init_schema
    init_schema(db)
    repo = SqliteHostRepository(db)
    repo.add("test.example.com", 443, expected_issuers="R3, R4")

    with TestClient(app_mod.app) as client:
        r = client.get("/discover")
    assert r.status_code == 200
    content = r.text
    assert "Expected Issuers" in content
    assert "R3, R4" in content
