"""Detail A: diagnosis-first status, disclosures and one complete editor."""

from __future__ import annotations

import pytest

pytest.importorskip("playwright")
from playwright.sync_api import Page, expect

CASES = {
    "current": ("Current", "Expires in", None),
    "expiring": ("Current", "Expires in", "Renew the certificate"),
    "expired": ("Current", "Expired", "Renew the certificate now"),
    "failing": ("Failing since", "Last seen", "Check the service"),
    "overdue": ("Scan overdue", "Last seen", "overdue"),
    "never": ("Never scanned", "No certificate observed", "Assign an owner"),
    "uploaded": ("Not monitored", "Expires in", "Assign an owner"),
    "chain": ("Current", "Expires in", "chain"),
    "routing_gap": ("Current", "Expires in", "Assign an owner"),
}


@pytest.mark.parametrize("case", CASES)
def test_detail_a_renders_each_real_state_without_mobile_overflow(
    page: Page,
    detail_estate_server: tuple[str, dict[str, str]],
    case: str,
) -> None:
    base, ids = detail_estate_server
    monitoring, certificate, action = CASES[case]
    page.set_viewport_size({"width": 390, "height": 844})
    page.goto(f"{base}/certificates/{ids[case]}")

    expect(page.locator("#cw-health")).to_have_count(0)
    axes = page.get_by_test_id("detail-state-axes")
    expect(axes).to_be_visible()
    expect(axes.locator(".cw-detail-axis")).to_have_count(4)
    for label in ("Certificate", "Monitoring", "Renewal", "Alerts"):
        expect(axes).to_contain_text(label)
    expect(axes).to_contain_text(monitoring)
    expect(axes).to_contain_text(certificate)
    if action is None:
        expect(page.get_by_test_id("what-to-do")).to_have_count(0)
    else:
        expect(page.get_by_test_id("what-to-do")).to_contain_text(action)

    if case == "failing":
        expect(page.get_by_test_id("scan-failure-panel")).to_be_visible()
        expect(page.get_by_test_id("scan-failure-error")).to_contain_text(
            "Connection refused"
        )
        expect(axes.locator(".cw-detail-axis").first).to_have_class("cw-detail-axis")
        assert "t-ok" not in axes.locator(".cw-detail-axis-value").first.get_attribute(
            "class"
        )
    if case == "uploaded":
        expect(page.get_by_text("Uploaded", exact=True)).to_be_visible()
        expect(page.get_by_test_id("edit-host")).to_have_count(0)
        expect(page.get_by_test_id("cert-scan-btn")).to_have_count(0)
    if case == "routing_gap":
        expect(page.get_by_test_id("owner-routing-panel")).to_contain_text(
            "No matching alert group"
        )

    if case not in {"never"}:
        facts = page.get_by_test_id("certificate-facts")
        expect(facts).to_be_visible()
        assert facts.evaluate("el => !el.open")
    history = page.get_by_test_id("history-disclosure")
    expect(history).to_be_visible()
    assert history.evaluate("el => !el.open")
    assert page.evaluate("document.documentElement.scrollWidth === window.innerWidth")


def test_detail_a_edit_host_round_trips_every_control(
    page: Page,
    detail_estate_server: tuple[str, dict[str, str]],
) -> None:
    base, ids = detail_estate_server
    page.goto(f"{base}/certificates/{ids['never']}")
    page.get_by_test_id("edit-host").click()
    page.get_by_label("Owner name", exact=True).fill("Edge Operations")
    page.get_by_label("Owner email", exact=True).fill("edge@example.test")
    page.get_by_label("Slack channel", exact=True).fill("#edge-certs")
    page.get_by_label("Renewal method", exact=True).select_option("cert-manager")
    page.get_by_label("Runbook URL", exact=True).fill(
        "https://runbooks.example.test/edge-tls"
    )
    page.get_by_label("Scan interval (hours)", exact=True).fill("12")
    page.get_by_label("Alert threshold (days)", exact=True).fill("30")
    page.get_by_label(
        "Renewal status reported by operator", exact=True
    ).select_option("in_progress")
    page.get_by_label("Tags", exact=True).fill("detail-team, edge")
    page.get_by_label("Notes", exact=True).fill("Renew through the edge runbook.")
    page.get_by_test_id("save-host").click()
    expect(page.get_by_test_id("endpoint-settings-saved")).to_be_visible()

    page.get_by_test_id("edit-host").click()
    expect(page.get_by_label("Owner name", exact=True)).to_have_value("Edge Operations")
    expect(page.get_by_label("Owner email", exact=True)).to_have_value(
        "edge@example.test"
    )
    expect(page.get_by_label("Slack channel", exact=True)).to_have_value("#edge-certs")
    expect(page.get_by_label("Renewal method", exact=True)).to_have_value(
        "cert-manager"
    )
    expect(page.get_by_label("Runbook URL", exact=True)).to_have_value(
        "https://runbooks.example.test/edge-tls"
    )
    expect(page.get_by_label("Scan interval (hours)", exact=True)).to_have_value("12")
    expect(page.get_by_label("Alert threshold (days)", exact=True)).to_have_value("30")
    expect(
        page.get_by_label("Renewal status reported by operator", exact=True)
    ).to_have_value("in_progress")
    expect(page.get_by_label("Tags", exact=True)).to_have_value("detail-team,edge")
    expect(page.get_by_label("Notes", exact=True)).to_have_value(
        "Renew through the edge runbook."
    )


def test_detail_a_uses_only_the_five_type_scale_sizes(
    page: Page,
    detail_estate_server: tuple[str, dict[str, str]],
) -> None:
    base, ids = detail_estate_server
    page.goto(f"{base}/certificates/{ids['current']}")
    values = page.evaluate(
        """() => {
          const css = getComputedStyle(document.documentElement);
          return ['--cw-fs-xs', '--cw-fs-sm', '--cw-fs-md', '--cw-fs-lg', '--cw-fs-xl']
            .map(name => css.getPropertyValue(name).trim());
        }"""
    )
    assert values == ["12px", "14px", "16px", "20px", "28px"]
