from datetime import UTC, datetime

from cert_watch.presenters.home import Tone, present_home


def test_home_presenter_derives_three_blocks_and_twelve_week_strip() -> None:
    axis_stats = {
        "condition": {"expired": 0, "le7": 1, "8to30": 0, "ok": 2},
        "monitoring": {"current": 2, "failing": 1, "never_scanned": 0},
        "delivery": {"ok": 2, "failing": 1, "unrouted": 0},
        "renewal": {},
        "overall": {},
    }
    view = present_home(
        axis_stats=axis_stats,
        home_data={
            "tracked_total": 3,
            "last_scan": "2026-09-22T07:29:00+00:00",
            "webhook_outcome": "failed",
            "rows": {
                "risk:le7": [{
                    "id": "cert-1",
                    "host": "vpn.example.test:443",
                    "host_id": "host-1",
                    "source": "scanned",
                    "condition": "le7",
                    "effective_days": 4,
                    "owner_name": "Network team",
                }],
                "monitoring:failing": [{
                    "id": "cert-1",
                    "host": "vpn.example.test:443",
                    "host_id": "host-1",
                    "source": "scanned",
                    "monitoring_error": "connection refused",
                    "monitoring_since": "2026-09-22T06:00:00+00:00",
                    "monitoring_last_success": "2026-09-21T06:00:00+00:00",
                    "owner_name": "Network team",
                }],
            },
            "chain_groups": [],
            "calendar": [
                {"bucket_start": "2026-09-21", "count": 1, "tone": "critical"},
                {"bucket_start": "2026-09-28", "count": 3, "tone": "critical"},
                {"bucket_start": "2026-10-05", "count": 1, "tone": "warning"},
                {"bucket_start": "2026-12-21", "count": 9, "tone": "neutral"},
            ],
        },
        smtp_configured=False,
        webhook_configured=True,
        sched_hour=7,
        sched_min=23,
        now=datetime(2026, 9, 22, 12, tzinfo=UTC),
    )

    assert view.risk_rows[0].condition_label == "4 days left"
    assert view.monitoring_rows[0].state_label == "Failing"
    assert "accepting connections" in view.monitoring_rows[0].cause.lower()
    assert len(view.horizon) == 12
    assert [bucket.tone for bucket in view.horizon[:3]] == [
        Tone.CRITICAL, Tone.CRITICAL, Tone.WARNING,
    ]
    assert [bucket.count for bucket in view.horizon[:2]] == [1, 3]
    assert all(bucket.bucket_start != "2026-12-21" for bucket in view.horizon)
    assert [line.label for line in view.delivery_lines] == [
        "Email not configured", "Webhook last delivery failed",
    ]
    assert view.last_run_label == "2026-09-22 07:29 UTC"
    assert view.next_run_label == "2026-09-23 07:23 UTC"
