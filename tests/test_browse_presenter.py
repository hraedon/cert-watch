from datetime import UTC, datetime

from cert_watch.presenters.browse import present_browse
from cert_watch.scan_freshness import ScanEvidence
from cert_watch.services.browse_page import BrowsePageData


def _browse_data() -> BrowsePageData:
    evidence = ScanEvidence(
        host_id="host-1",
        last_success=datetime(2026, 9, 22, 8, tzinfo=UTC),
        last_attempt=datetime(2026, 9, 22, 8, tzinfo=UTC),
        attempt_status="success",
        due_at=datetime(2026, 9, 23, 8, tzinfo=UTC),
        next_attempt_at=None,
        state="current",
    )
    return BrowsePageData(
        entries=[
            {
                "id": "cert-1",
                "host_id": "host-1",
                "kind": "scanned",
                "name": "vpn.example.test",
                "host": "vpn.example.test",
                "source": "scanned",
                "subject": "CN=vpn.example.test",
                "issuer": "CN=Example CA",
                "not_before": "2026-08-01T00:00:00+00:00",
                "not_after": "2026-10-02T00:00:00+00:00",
                "days_remaining": 10,
                "effective_days": 10,
                "condition": "8to30",
                "monitoring": "current",
                "renewal": "manual",
                "delivery": "ok",
                "chain_status": "public",
                "status": {
                    "condition": {"state": "8to30", "effective_days": 10},
                    "chain_trust_problem": False,
                    "chain_status": "public",
                    "monitoring": {
                        "state": "current",
                        "since": None,
                        "cause": None,
                        "raw_error": None,
                    },
                    "renewal": {"state": "manual", "source": "renewal_method"},
                    "delivery": {"state": "ok", "channels": []},
                },
                "owner_name": "Network team",
                "renewal_method": "manual",
                "tags": " production, vpn, production ",
                "san_dns_names": [
                    "vpn.example.test",
                    "alt.example.test",
                    "second.example.test",
                    "third.example.test",
                ],
            }
        ],
        all_tags=["production", "vpn"],
        pivot_groups=None,
        pivot_stats={"expired": 0, "critical": 0, "warning": 1, "healthy": 0},
        pivot_view="",
        calendar_data=None,
        filter_q="vpn",
        filter_urgency="warning",
        filter_source="scanned",
        sort_by="expiry",
        sort_order="asc",
        page=1,
        total_pages=2,
        total_entries=26,
        tracked_total=30,
        grouped=0,
        posture_grades={"cert-1": "B"},
        scan_evidence={"host-1": evidence},
    )


def test_browse_presenter_derives_row_display_without_http() -> None:
    view = present_browse(
        _browse_data(),
        now=datetime(2026, 9, 22, 12, tzinfo=UTC),
    )
    entry = view.entries[0]

    assert entry.tag_items == ("production", "vpn")
    assert entry.renewal_is_manual is True
    assert entry.renewal_label == "manual"
    assert entry.expiry_bar_percent == 11
    assert entry.visible_sans == ("alt.example.test", "second.example.test")
    assert entry.hidden_san_count == 1
    assert entry.posture_grade == "B"
    assert entry.freshness_label == "Current scan"
    assert entry.freshness_tone == "cw-muted"
    assert entry.condition_label == "10 days left"
    assert entry.condition_tone == "t-warn"
    assert entry.monitoring_label == ""
    assert entry.renewal_flag_label == ""
    assert entry.delivery_flag_label == ""
    assert entry.chain_problem_label == ""
    assert view.has_next is True
    assert view.browse_url(page=2).startswith("/browse?")


def test_browse_presenter_uses_four_axis_facts_without_recomputing_status() -> None:
    data = _browse_data()
    entry = {
        **data.entries[0],
        "days_remaining": 62,
        "effective_days": -3,
        "condition": "expired",
        "monitoring": "failing",
        "monitoring_attempt_status": "failure",
        "renewal": "stalled",
        "delivery": "failing",
        "chain_status": "invalid",
        "status": {
            "condition": {"state": "expired", "effective_days": -3},
            "chain_trust_problem": True,
            "chain_status": "invalid",
            "monitoring": {
                "state": "failing",
                "since": "2026-09-22T06:00:00+00:00",
                "cause": "The endpoint refused the connection.",
                "raw_error": "connection refused",
            },
            "renewal": {"state": "stalled", "source": "renewal_window"},
            "delivery": {"state": "failing", "channels": []},
        },
    }
    view = present_browse(
        BrowsePageData(**{**data.__dict__, "entries": [entry]}),
        now=datetime(2026, 9, 22, 12, tzinfo=UTC),
    )
    row = view.entries[0]

    assert row.condition_label == "Expired 3 days ago"
    assert row.condition_tone == "t-expired"
    assert row.condition_is_chain_limited is True
    assert row.monitoring_label == "Failing since 2026-09-22 06:00 UTC"
    assert row.monitoring_cause == "The endpoint refused the connection."
    assert row.renewal_flag_label == "Renewal stalled"
    assert row.delivery_flag_label == "Can't be delivered"
    assert row.chain_problem_label == "Chain invalid"


def test_browse_presenter_distinguishes_overdue_never_and_uploads() -> None:
    data = _browse_data()
    base = data.entries[0]
    entries = [
        {
            **base,
            "id": "overdue",
            "monitoring": "failing",
            "monitoring_attempt_status": "success",
            "monitoring_last_success": "2026-09-19T06:00:00+00:00",
            "status": {
                **base["status"],
                "monitoring": {
                    "state": "failing",
                    "since": "2026-09-20T06:00:00+00:00",
                    "cause": "The endpoint has no current successful observation.",
                    "raw_error": None,
                },
            },
        },
        {
            **base,
            "id": "never",
            "condition": None,
            "effective_days": None,
            "monitoring": "never_scanned",
            "status": {
                **base["status"],
                "condition": {"state": None, "effective_days": None},
                "monitoring": {
                    "state": "never_scanned",
                    "since": None,
                    "cause": None,
                    "raw_error": None,
                },
            },
        },
        {
            **base,
            "id": "upload",
            "host_id": None,
            "source": "uploaded",
            "monitoring": "not_monitored",
            "status": {
                **base["status"],
                "monitoring": {
                    "state": "not_monitored",
                    "since": None,
                    "cause": None,
                    "raw_error": None,
                },
            },
        },
    ]
    view = present_browse(BrowsePageData(**{**data.__dict__, "entries": entries}))

    assert [row.monitoring_label for row in view.entries] == [
        "Monitoring overdue",
        "Never scanned",
        "",
    ]


def test_browse_presenter_derives_calendar_tones_and_storms() -> None:
    data = _browse_data()
    data = BrowsePageData(
        **{
            **data.__dict__,
            "entries": [],
            "calendar_data": [
                {"bucket_start": "2026-09-21", "count": 1},
                {"bucket_start": "2026-09-28", "count": 3},
                {"bucket_start": "2026-10-05", "count": 4},
            ],
            "pivot_view": "calendar",
        }
    )

    view = present_browse(data, now=datetime(2026, 9, 22, 12, tzinfo=UTC))

    assert [bucket.tone for bucket in view.calendar_data or ()] == [
        "t-crit",
        "t-warn",
        "",
    ]
    assert view.calendar_storms == 2
