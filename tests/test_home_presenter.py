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
            "webhook_failed_at": "2026-09-22T07:30:00+00:00",
            "routing_gap_total": 1,
            "rows": {
                "risk:le7": [{
                    "id": "cert-1",
                    "host": "vpn.example.test:443",
                    "host_id": "host-1",
                    "source": "scanned",
                    "condition": "le7",
                    "effective_days": 4,
                    "owner_name": "Network team",
                    "renewal": "manual",
                    "renewal_method": "manual",
                    "chain_status": "incomplete",
                    "issuer": "CN=Zeta Test CA",
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
                }, {
                    "id": "cert-2",
                    "host": "overdue.example.test:8443",
                    "host_id": "host-2",
                    "source": "scanned",
                    "monitoring_since": "2026-09-20T07:23:00+00:00",
                    "monitoring_last_success": "2026-09-19T07:23:00+00:00",
                    "monitoring_attempt_status": "success",
                    "owner_name": "",
                }],
                "monitoring:never_scanned": [{
                    "id": "host-3",
                    "host": "new.example.test:443",
                    "host_id": "host-3",
                    "source": "scanned",
                    "added_at": "2026-09-22T06:00:00+00:00",
                    "owner_name": "",
                }],
            },
            "chain_groups": [{
                "issuer": "CN=Zeta Test CA",
                "count": 1,
                "statuses": "incomplete",
                "total_certs": 3,
                "total_issuers": 2,
                "example_1_hostname": "zeta.example.test",
                "example_1_port": 443,
                "example_1_subject": "CN=zeta.example.test",
            }, {
                "issuer": "CN=Alpha Test CA",
                "count": 2,
                "statuses": "self-signed",
                "total_certs": 3,
                "total_issuers": 2,
                "example_1_hostname": "alpha.example.test",
                "example_1_port": 443,
                "example_1_subject": "CN=alpha.example.test",
                "example_2_hostname": "ldaps.example.test",
                "example_2_port": 636,
                "example_2_subject": "CN=ldaps.example.test",
            }],
            "calendar": [
                {"bucket_start": "2026-09-21", "count": 1, "tone": "critical"},
                {"bucket_start": "2026-09-28", "count": 3, "tone": "critical"},
                {"bucket_start": "2026-10-05", "count": 1, "tone": "warning"},
                {"bucket_start": "2026-12-21", "count": 9, "tone": "neutral"},
            ],
        },
        smtp_configured=False,
        webhook_configured=True,
        webhook_kind="slack",
        sched_hour=7,
        sched_min=23,
        now=datetime(2026, 9, 22, 12, tzinfo=UTC),
    )

    assert view.risk_rows[0].condition_label == "4 days left"
    assert view.risk_rows[0].difference == "Manual renewal"
    assert view.risk_rows[0].chain_url == (
        "/browse?chain_problem=1&issuer=CN%3DZeta+Test+CA&grouped=0"
    )
    assert view.risk_rows[0].chain_label == (
        "Chain can\u2019t be verified \u2014 view certificates issued by Zeta Test CA"
    )
    assert view.monitoring_rows[0].state_label == "Failing"
    assert "accepting connections" in view.monitoring_rows[0].cause.lower()
    assert view.monitoring_rows[0].when_label == "since 2026-09-22 06:00 UTC"
    assert view.monitoring_rows[0].when_prefix == "since"
    assert view.monitoring_rows[0].when_time_label == "2026-09-22 06:00 UTC"
    assert view.monitoring_rows[1].state == "failing"
    assert view.monitoring_rows[1].state_label == "Overdue"
    assert view.monitoring_rows[1].cause == "Scan overdue since 2026-09-20 07:23 UTC."
    assert view.monitoring_rows[1].cause_time_label == "2026-09-20 07:23 UTC"
    assert view.monitoring_rows[1].name == "overdue.example.test:8443"
    assert view.monitoring_rows[1].owner_name == ""
    assert view.monitoring_rows[2].when_label == "added 2026-09-22 06:00 UTC"
    assert len(view.horizon) == 12
    assert [bucket.tone for bucket in view.horizon[:3]] == [
        Tone.CRITICAL, Tone.CRITICAL, Tone.WARNING,
    ]
    assert [bucket.count for bucket in view.horizon[:2]] == [1, 3]
    assert all(bucket.bucket_start != "2026-12-21" for bucket in view.horizon)
    assert [line.label for line in view.delivery_lines] == [
        "Slack webhook failing",
        "Email not configured",
        "1 certificate has no owner and no alert group",
        "Scan failures aren\u2019t alerted",
    ]
    assert view.delivery_lines[0].detail == "Last failed 2026-09-22 07:30 UTC."
    assert [group.issuer for group in view.chain_groups] == [
        "Alpha Test CA", "Zeta Test CA",
    ]
    assert view.chain_groups[0].examples == (
        "alpha.example.test", "ldaps.example.test:636",
    )
    assert [(fix.fix, [group.issuer for group in fix.groups]) for fix in view.chain_fixes] == [
        ("missing", ["Zeta Test CA"]),
        ("self_signed", ["Alpha Test CA"]),
    ]
    assert view.last_scan_activity_label == "Last scan activity 2026-09-22 07:29 UTC"
    assert view.next_run_label == "2026-09-23 07:23 UTC"


def test_home_presenter_uses_safe_raw_error_and_no_scans_copy() -> None:
    axis_stats = {
        "condition": {"expired": 0, "le7": 0, "8to30": 0, "ok": 0},
        "monitoring": {"current": 0, "failing": 1, "never_scanned": 0},
        "delivery": {"ok": 0, "failing": 0, "unrouted": 0},
        "renewal": {},
        "overall": {},
    }
    raw = "  unexpected <script>alert('x')</script>  " + ("x" * 300)
    view = present_home(
        axis_stats=axis_stats,
        home_data={
            "tracked_total": 1,
            "rows": {"monitoring:failing": [{
                "id": "host-1",
                "host": "odd.example.test:443",
                "host_id": "host-1",
                "source": "scanned",
                "monitoring_error": raw,
                "monitoring_since": "2026-09-22T06:00:00+00:00",
                "monitoring_attempt_status": "failure",
            }]},
        },
        smtp_configured=True,
        webhook_configured=False,
        webhook_kind="generic",
        sched_hour=7,
        sched_min=23,
        now=datetime(2026, 9, 22, 12, tzinfo=UTC),
    )

    assert view.monitoring_rows[0].cause.startswith("unexpected <script>")
    assert len(view.monitoring_rows[0].cause) <= 164
    assert view.last_scan_activity_label == "No scans yet"


def _minimal_home(rows: dict, chain_groups: list) -> object:
    return present_home(
        axis_stats={
            "condition": {"expired": 0, "le7": 0, "8to30": 0, "ok": 0},
            "monitoring": {"current": 0, "failing": 0, "never_scanned": 0},
            "delivery": {"ok": 0, "failing": 0, "unrouted": 0},
            "renewal": {},
            "overall": {},
        },
        home_data={"tracked_total": 1, "rows": rows, "chain_groups": chain_groups},
        smtp_configured=True,
        webhook_configured=False,
        webhook_kind="",
        sched_hour=6,
        sched_min=0,
        now=datetime(2026, 9, 22, 12, tzinfo=UTC),
    )


def test_home_chain_fixes_print_each_guidance_once_in_severity_order() -> None:
    def group(issuer: str, statuses: str) -> dict:
        return {"issuer": f"CN={issuer}", "count": 1, "statuses": statuses,
                "total_certs": 4, "total_issuers": 4}

    view = _minimal_home({}, [
        group("Missing One", "incomplete"),
        group("Mixed", "invalid,self-signed"),
        group("Broken", "invalid,unknown"),
        group("Missing Two", "unknown,unverified"),
    ])
    assert [fix.fix for fix in view.chain_fixes] == ["invalid", "missing", "self_signed"]
    by_fix = {fix.fix: [g.issuer for g in fix.groups] for fix in view.chain_fixes}
    # Self-signed wins over invalid, matching the per-issuer guidance.
    assert by_fix == {
        "invalid": ["Broken"],
        "missing": ["Missing One", "Missing Two"],
        "self_signed": ["Mixed"],
    }
    for fix in view.chain_fixes:
        assert {g.guidance for g in fix.groups} == {fix.guidance}


def test_home_risk_row_marks_chain_only_when_the_chain_is_unverified() -> None:
    base = {"host_id": "h", "source": "scanned", "condition": "le7", "effective_days": 3}
    view = _minimal_home({"risk:le7": [
        {**base, "id": "ok", "host": "ok.example.test:443", "chain_status": "public",
         "issuer": "CN=Fine CA"},
        {**base, "id": "bad", "host": "bad.example.test:443", "chain_status": "self-signed"},
    ]}, [])
    broken, clean = sorted(view.risk_rows, key=lambda row: row.name)
    assert clean.chain_url is None and clean.chain_label == ""
    assert "chain" not in clean.difference
    # No issuer recorded: link the whole unverified population, not a broken filter.
    assert broken.chain_url == "/browse?chain_problem=1&grouped=0"
    assert broken.chain_label == "Chain can\u2019t be verified"
    assert broken.difference == ""
