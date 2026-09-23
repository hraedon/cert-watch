from datetime import UTC, datetime

from cert_watch.presenters.home import Tone, present_home


def test_home_presenter_derives_attention_and_horizon_display() -> None:
    view = present_home(
        queue=[
            {
                "severity": "stalled",
                "kind": "certificate",
                "cert_id": "cert-1",
                "detail_url": "/certificates/cert-1",
                "endpoint": "vpn.example.test:443",
                "host": "vpn.example.test",
                "host_id": "host-1",
                "days_remaining": 4,
                "reasons": ["Renewal is overdue"],
                "owner_name": "Network team",
                "confidence": "current",
                "confidence_label": "Current scan",
                "host_count": 1,
            }
        ],
        stats={"expired": 0, "critical": 1, "warning": 0, "healthy": 2},
        tracked_total=3,
        scan_coverage={
            "total": 3,
            "current": 2,
            "overdue": 1,
            "unobserved": 0,
            "failed": 0,
            "unknown": 0,
        },
        calendar=[
            {"bucket_start": "2026-09-21", "count": 1},
            {"bucket_start": "2026-09-28", "count": 3},
            {"bucket_start": "2026-12-21", "count": 9},
        ],
        now=datetime(2026, 9, 22, 12, tzinfo=UTC),
    )

    assert view.queue[0].severity_label == "Renewal stalled"
    assert view.queue[0].severity_tone == "critical"
    assert [bucket.tone for bucket in view.horizon] == [Tone.CRITICAL, Tone.WARNING]
    assert view.horizon_storms == 1
    assert view.scan_coverage.current == 2
    assert view.template_context()["current_week_start"] == "2026-09-21"
