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
    assert view.has_next is True
    assert view.browse_url(page=2).startswith("/browse?")


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
