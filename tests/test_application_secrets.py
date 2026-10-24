"""Metadata privacy, expiry stages and durable notification lifecycle."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from cert_watch.alerting.rules.application_secrets import evaluate_application_secrets
from cert_watch.application_secrets import parse_metadata
from cert_watch.auth.rbac import AuthContext
from cert_watch.auth.scope import MissingAuthContextError, ScopeDeniedError
from cert_watch.database import SqliteAlertRepository
from cert_watch.database.application_secrets import list_application_secrets
from cert_watch.database.connection import _connect
from cert_watch.services.application_secrets import (
    create_application_secret,
    retire_application_secret,
)

NOW = datetime(2027, 1, 1, tzinfo=UTC)


def metadata(**changes):
    return {
        "application_name": "Example application", "application_id": "example-client",
        "credential_id": "example-key", "credential_name": "Deployment key",
        "tenant_id": "example-tenant", "owner_email": "owner@example.invalid",
        "expires_at": (NOW + timedelta(days=30)).isoformat(), **changes,
    }


def create(db, **changes):
    return create_application_secret(
        db, metadata(**changes), auth=AuthContext.system(), actor="test",
    )


@pytest.mark.parametrize("changes", [
    {"secretText": "SHOULD_NEVER_APPEAR"}, {"secret": "SHOULD_NEVER_APPEAR"},
    {"password": "SHOULD_NEVER_APPEAR"}, {"expires_at": "SHOULD_NEVER_APPEAR"},
    {"expires_at": "2027-01-01"}, {"owner_email": "a@example.invalid\r\nBcc:other"},
    {"application_id": ""}, {"application_name": 42}, {"credential_id": "x" * 257},
])
def test_invalid_metadata_never_echoes_values(db, changes):
    with pytest.raises(ValueError) as error:
        create(db, **changes)
    assert "SHOULD_NEVER_APPEAR" not in str(error.value)
    assert not list_application_secrets(db)
    assert not _connect(db).execute("SELECT * FROM audit_log").fetchall()


def test_timezone_normalization():
    value = parse_metadata(metadata(expires_at="2027-01-02T01:00:00+01:00"))
    assert value.expires_at == datetime(2027, 1, 2, tzinfo=UTC)


@pytest.mark.parametrize("expiry", [
    "0001-01-01T00:00:00+14:00", "9999-12-31T23:59:59-14:00",
])
def test_unrepresentable_utc_expiry_is_a_validation_error(expiry):
    with pytest.raises(ValueError, match="Expiry"):
        parse_metadata(metadata(expires_at=expiry))


@pytest.mark.parametrize("email", ["@example.invalid", "owner@", "owner\u00a0@example.invalid"])
def test_owner_requires_a_complete_single_address(email):
    with pytest.raises(ValueError, match="email"):
        parse_metadata(metadata(owner_email=email))


@pytest.mark.parametrize("auth", [None, AuthContext.from_tier("viewer", "viewer"),
                                 AuthContext.from_tier("operator", "operator")])
def test_direct_service_call_requires_admin(db, auth):
    error = MissingAuthContextError if auth is None else ScopeDeniedError
    with pytest.raises(error):
        create_application_secret(db, metadata(), auth=auth, actor="test")
    with pytest.raises(error):
        retire_application_secret(db, "missing", auth=auth, actor="test")
    assert list_application_secrets(db) == []


def test_inventory_schema_cannot_store_a_secret_value(db):
    columns = {row[1] for row in _connect(db).execute("PRAGMA table_info(application_secrets)")}
    assert columns == {
        "id", "application_name", "application_id", "credential_id", "credential_name",
        "tenant_id", "expires_at", "owner_email", "created_at", "retired_at",
    }


def test_active_identity_unique_but_rotation_and_tenants_independent(db):
    create(db)
    with pytest.raises(ValueError, match="already exists"):
        create(db)
    create(db, credential_id="replacement-key")
    create(db, tenant_id="another-tenant")
    assert len(list_application_secrets(db)) == 3


def test_thresholds_are_exact_and_only_most_urgent_fires(db):
    create(db)
    assert evaluate_application_secrets(db, now=NOW - timedelta(seconds=1)) == []
    alerts = evaluate_application_secrets(db, now=NOW)
    assert [item.threshold_days for item in alerts] == [30]
    assert alerts[0].extra_recipients == ["owner@example.invalid"]
    assert evaluate_application_secrets(db, now=NOW) == []
    alerts = evaluate_application_secrets(db, now=NOW + timedelta(days=23))
    assert [item.threshold_days for item in alerts] == [7]
    repo = SqliteAlertRepository(db)
    all_alerts = repo.list_for_cert(alerts[0].cert_id)
    assert {item.threshold_days: item.status for item in all_alerts} == {
        30: "cancelled", 7: "pending",
    }
    assert evaluate_application_secrets(db, now=NOW + timedelta(days=16)) == []
    assert [item.alert_type for item in evaluate_application_secrets(
        db, now=NOW + timedelta(days=30),
    )] == ["application_secret_expired"]
    assert evaluate_application_secrets(db, now=NOW + timedelta(days=40)) == []


def test_already_expired_record_raises_one_expired_alert(db):
    create(db, expires_at=(NOW - timedelta(days=5)).isoformat())
    alerts = evaluate_application_secrets(db, now=NOW)
    assert len(alerts) == 1
    assert alerts[0].threshold_days == 0
    assert alerts[0].alert_type == "application_secret_expired"


def test_retirement_cancels_queue_and_keeps_history(db):
    identifier = create(db)
    alert = evaluate_application_secrets(db, now=NOW)[0]
    assert retire_application_secret(db, identifier, auth=AuthContext.system(), actor="test")
    assert not retire_application_secret(db, identifier, auth=AuthContext.system(), actor="test")
    assert list_application_secrets(db)[0].retired_at is not None
    assert SqliteAlertRepository(db).list_for_cert(alert.cert_id)[0].status == "cancelled"
    assert not evaluate_application_secrets(db, now=NOW + timedelta(days=40))
    assert _connect(db).execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == 2
    create(db)  # Corrected metadata may be re-entered after explicit retirement.


def test_atomic_audit_failure_rolls_back_inventory(db):
    conn = _connect(db)
    conn.execute("CREATE TRIGGER refuse_audit BEFORE INSERT ON audit_log "
                 "BEGIN SELECT RAISE(ABORT,'synthetic refusal'); END")
    conn.commit()
    with pytest.raises(Exception, match="synthetic refusal"):
        create(db)
    assert not list_application_secrets(db)


def test_delivery_uses_existing_evidence_queue(db, fake_transport):
    from cert_watch.alerting.dispatch import Dispatcher

    create(db)
    evaluate_application_secrets(db, now=NOW)
    transport = fake_transport()
    Dispatcher(db, transports=[transport]).process_pending()
    assert len(transport.messages) == 1
    assert "Example application" in transport.messages[0].body
    assert _connect(db).execute("SELECT status FROM alerts").fetchone()[0] == "sent"
    events = _connect(db).execute(
        "SELECT event_kind FROM alert_delivery_events ORDER BY rowid",
    ).fetchall()
    assert [row[0] for row in events] == ["started", "completed"]


def test_scoped_dispatch_does_not_send_global_credential_alerts(db, fake_transport):
    from cert_watch.alerting.dispatch import Dispatcher

    create(db)
    evaluate_application_secrets(db, now=NOW)
    transport = fake_transport()
    Dispatcher(db, transports=[transport], scope_tags=("team",)).process_pending()
    assert not transport.messages


@pytest.mark.parametrize("days,state", [(31, "Current"), (30, "Expires within 30 days"),
    (7, "Expires within 7 days"), (0, "Expired"), (-1, "Expired")])
def test_inventory_status(db, days, state):
    create(db, expires_at=(NOW + timedelta(days=days)).isoformat())
    assert list_application_secrets(db)[0].state(NOW) == state
