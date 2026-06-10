"""Tests for policy violation alerts (Plan 042 / WI-4)."""

from __future__ import annotations

from cert_watch.alerts import evaluate_policy_alerts
from cert_watch.database import SqliteAlertRepository, init_schema
from cert_watch.policy import PolicyViolation


def test_critical_violation_creates_pending_alert(tmp_path):
    db = str(tmp_path / "cert-watch.sqlite3")
    init_schema(db)
    violations = [
        PolicyViolation(
            "key_size_rsa", "critical",
            "RSA key size 1024 < 2048 bits",
            "Replace certificate",
        ),
    ]
    created = evaluate_policy_alerts(
        "cert-1", "host.example.com", violations, db, subject="CN=example.com",
    )
    assert len(created) == 1
    assert created[0].alert_type == "policy_violation"
    assert created[0].status == "pending"
    assert "key_size_rsa" in created[0].message
    assert "(critical)" in created[0].message
    assert created[0].subject == "CN=example.com"
    repo = SqliteAlertRepository(db)
    pending = repo.list_pending()
    assert any(a.alert_type == "policy_violation" for a in pending)


def test_warning_violation_creates_pending_alert(tmp_path):
    db = str(tmp_path / "cert-watch.sqlite3")
    init_schema(db)
    violations = [
        PolicyViolation("chain_completeness", "warning", "Incomplete chain", "Fix chain"),
    ]
    created = evaluate_policy_alerts(
        "cert-2", "host2.example.com", violations, db, subject="CN=host2",
    )
    assert len(created) == 1
    assert created[0].alert_type == "policy_violation"
    assert "chain_completeness" in created[0].message
    assert "(warning)" in created[0].message


def test_info_violation_does_not_create_alert(tmp_path):
    db = str(tmp_path / "cert-watch.sqlite3")
    init_schema(db)
    violations = [
        PolicyViolation("hsts_required", "info", "HSTS not detected", "Enable HSTS"),
    ]
    created = evaluate_policy_alerts("cert-3", "host3.example.com", violations, db)
    assert len(created) == 0


def test_disabled_rule_produces_no_alerts(tmp_path):
    db = str(tmp_path / "cert-watch.sqlite3")
    init_schema(db)
    evaluate_policy_alerts("cert-4", "host4.example.com", [], db)
    repo = SqliteAlertRepository(db)
    pending = [a for a in repo.list_pending() if a.alert_type == "policy_violation"]
    assert len(pending) == 0


def test_mixed_severity_only_critical_and_warning_create_alerts(tmp_path):
    db = str(tmp_path / "cert-watch.sqlite3")
    init_schema(db)
    violations = [
        PolicyViolation("key_size_rsa", "critical", "RSA key too small", "Replace"),
        PolicyViolation("hsts_required", "info", "No HSTS", "Enable"),
        PolicyViolation("chain_completeness", "warning", "Incomplete chain", "Fix"),
    ]
    created = evaluate_policy_alerts("cert-5", "host5.example.com", violations, db)
    assert len(created) == 2


def test_dedup_prevents_duplicate_policy_alerts(tmp_path):
    db = str(tmp_path / "cert-watch.sqlite3")
    init_schema(db)
    violations = [
        PolicyViolation("key_size_rsa", "critical", "RSA key too small", "Replace"),
    ]
    created1 = evaluate_policy_alerts("cert-6", "host6.example.com", violations, db)
    assert len(created1) == 1
    created2 = evaluate_policy_alerts("cert-6", "host6.example.com", violations, db)
    assert len(created2) == 0
    repo = SqliteAlertRepository(db)
    pending = [a for a in repo.list_pending() if a.alert_type == "policy_violation"]
    assert len(pending) == 1


def test_dedup_allows_different_rules_for_same_cert(tmp_path):
    db = str(tmp_path / "cert-watch.sqlite3")
    init_schema(db)
    violations1 = [
        PolicyViolation("key_size_rsa", "critical", "RSA key too small", "Replace"),
    ]
    evaluate_policy_alerts("cert-7", "host7.example.com", violations1, db)
    violations2 = [
        PolicyViolation("chain_completeness", "warning", "Incomplete chain", "Fix"),
    ]
    created2 = evaluate_policy_alerts("cert-7", "host7.example.com", violations2, db)
    assert len(created2) == 1
    repo = SqliteAlertRepository(db)
    pending = [a for a in repo.list_pending() if a.alert_type == "policy_violation"]
    assert len(pending) == 2


def test_subject_passed_through_to_alert(tmp_path):
    db = str(tmp_path / "cert-watch.sqlite3")
    init_schema(db)
    violations = [
        PolicyViolation("key_size_rsa", "critical", "RSA key too small", "Replace"),
    ]
    created = evaluate_policy_alerts(
        "cert-8", "host8.example.com", violations, db, subject="CN=test.example.com",
    )
    assert len(created) == 1
    assert created[0].subject == "CN=test.example.com"


def test_default_subject_is_empty(tmp_path):
    db = str(tmp_path / "cert-watch.sqlite3")
    init_schema(db)
    violations = [
        PolicyViolation("key_size_rsa", "critical", "RSA key too small", "Replace"),
    ]
    created = evaluate_policy_alerts("cert-9", "host9.example.com", violations, db)
    assert len(created) == 1
    assert created[0].subject == ""