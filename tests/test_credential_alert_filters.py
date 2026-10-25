"""Credential alert filters and counts agree with the displayed urgency."""

import pytest
from fastapi.testclient import TestClient

from cert_watch.certificate_model import parse_certificate
from cert_watch.database import Alert, SqliteAlertRepository, init_schema
from cert_watch.database.pagination import _count_alerts_by_filter, list_alerts_with_subject
from tests._helpers import seed_certificate


def _alert(database, threshold, *, kind="application_secret_expiry", cert_id=None):
    return SqliteAlertRepository(database).create(
        Alert(
            cert_id=cert_id or f"application-secret:synthetic-{threshold}",
            alert_type=kind,
            threshold_days=threshold,
            status="pending",
            message="Synthetic expiry reminder",
            subject=f"Synthetic credential {threshold}",
        )
    )


@pytest.mark.parametrize("threshold", [None, 0, 1, 3, 7, 8, 14, 30])
@pytest.mark.parametrize("limit", [0, 2], ids=["unpaged", "paged"])
def test_credential_threshold_controls_both_filter_and_count(db, threshold, limit):
    identifier = _alert(db, threshold)
    urgent = threshold is not None and threshold <= 7

    counts = _count_alerts_by_filter(db)
    assert counts == {"all": 1, "unread": 1, "critical": int(urgent), "warning": int(not urgent)}
    critical = list_alerts_with_subject(db, critical_only=True, limit=limit)
    warning = list_alerts_with_subject(db, warning_only=True, limit=limit)
    assert [row["id"] for row in critical] == ([identifier] if urgent else [])
    assert [row["id"] for row in warning] == ([] if urgent else [identifier])
    assert list_alerts_with_subject(db, critical_only=True, warning_only=True, limit=limit) == []


@pytest.mark.parametrize("limit", [0, 1])
def test_urgent_global_credentials_remain_hidden_from_scoped_filters(db, self_signed_leaf, limit):
    certificate_id = seed_certificate(
        db,
        parse_certificate(self_signed_leaf.der),
        cert_id="synthetic-team-a-leaf",
        source="uploaded",
        tags="team-a",
    )
    own_alert = _alert(db, 0, kind="expired", cert_id=certificate_id)
    _alert(db, 1)
    _alert(db, 14)
    _alert(db, 0, kind="application_secret_expired")

    counts = _count_alerts_by_filter(db, scope_tags=("team-a",))
    assert counts == {"all": 1, "unread": 1, "critical": 1, "warning": 0}
    critical = list_alerts_with_subject(db, critical_only=True, limit=limit, scope_tags=("team-a",))
    assert [row["id"] for row in critical] == [own_alert]
    assert (
        list_alerts_with_subject(db, warning_only=True, limit=limit, scope_tags=("team-a",)) == []
    )


def test_activity_critical_tab_lists_urgent_credential_and_agrees_with_badge(reload_app, tmp_path):
    app = reload_app().app
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    urgent = _alert(db, 7)
    later = _alert(db, 8)
    with TestClient(app) as client:
        all_page = client.get("/alerts")
        critical = client.get("/alerts?filter_type=critical")
        warnings = client.get("/alerts?filter_type=warning")

    assert all_page.status_code == critical.status_code == warnings.status_code == 200
    assert 'Critical <span class="cnt">1</span>' in all_page.text
    assert 'Warnings <span class="cnt">1</span>' in all_page.text
    assert f'data-alert-id="{urgent}"' in critical.text
    assert f'data-alert-id="{later}"' not in critical.text
    assert f'data-alert-id="{later}"' in warnings.text
    assert f'data-alert-id="{urgent}"' not in warnings.text
