"""Inventory counts and navigation retain the operator's selected population."""

from datetime import UTC, datetime, timedelta
from hashlib import sha256
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from cert_watch.certificate_model import Certificate
from cert_watch.database import SqliteCertificateRepository, SqliteHostRepository, init_schema


class _Navigation(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.links = []
        self.forms = []
        self.anchor = None
        self.form = None
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a":
            self.anchor = {**attrs, "parts": []}
        if tag == "form":
            self.form = {**attrs, "inputs": []}
        if tag == "input" and self.form is not None:
            self.form["inputs"].append(attrs)

    def handle_data(self, data):
        if self.anchor is not None:
            self.anchor["parts"].append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self.anchor is not None:
            self.anchor["text"] = " ".join(" ".join(self.anchor.pop("parts")).split())
            self.links.append(self.anchor)
            self.anchor = None
        if tag == "form" and self.form is not None:
            self.forms.append(self.form)
            self.form = None


def _add_file(db, name, days, *, tags=""):
    now = datetime.now(UTC)
    cert = Certificate(
        subject=f"CN={name}", issuer="CN=Issuer not uploaded",
        not_before=now - timedelta(days=300), not_after=now + timedelta(days=days),
        fingerprint_sha256=sha256(name.encode()).hexdigest(), is_leaf=True,
    )
    repo = SqliteCertificateRepository(db, source="uploaded")
    cert_id = repo.add(cert)
    repo.set_tags(cert_id, tags)
    return cert_id


def _stats(html):
    return {
        link["text"].split()[0]: (int(link["text"].split()[1]), link["href"])
        for link in _Navigation(html).links
        if "cw-stat" in link.get("class", "").split()
        and not link["text"].startswith("Expiring")
    }


def _params(link):
    return {key: values[0] for key, values in parse_qs(urlsplit(link["href"]).query).items()}


def test_home_cards_follow_to_the_same_flat_population(reload_app, tmp_path):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    _add_file(db, "long-lived-untrusted", 100)
    _add_file(db, "critical", 3)
    _add_file(db, "expired", -10)
    SqliteHostRepository(db).add("pending.example.test", 443)
    with TestClient(app_mod.app) as client:
        home = client.get("/")
        stats = _stats(home.text)
        assert set(stats) == {"Tracked", "Expired", "Critical", "Warning", "Healthy"}
        assert stats["Tracked"][0] == 4  # Includes the pending host with no certificate.
        assert stats["Healthy"][0] == 0  # Long lifetime does not establish chain trust.
        assert stats["Warning"][0] == 1
        for label, (count, href) in stats.items():
            assert parse_qs(urlsplit(href).query)["grouped"] == ["0"]
            browse = client.get(href)
            assert browse.status_code == 200
            assert browse.context["total_entries"] == count, label
            assert len(browse.context["entries"]) == count, label
        assert "No expirations in the next 12 weeks" not in home.text


def test_inventory_navigation_preserves_filters_encoding_and_sort_order(reload_app, tmp_path):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    query = "R&D + west / #one"
    for index in range(28):
        _add_file(db, f"match-{index:02}", 60 + index, tags=query)
    _add_file(db, "matching-expired", -5, tags=query)
    _add_file(db, "different-population", 100, tags="other")
    params = {
        "q": query, "urgency": "warning", "source": "uploaded",
        "sort_by": "days", "sort_order": "desc", "grouped": "0", "ignored": "discard-me",
    }
    with TestClient(app_mod.app) as client:
        response = client.get("/browse", params=params)
        assert response.status_code == 200
        assert response.context["total_entries"] == 28
        tracked_count, _ = _stats(response.text)["Tracked"]
        assert tracked_count == 29  # q/source population, independent of urgency selection.
        navigation = _Navigation(response.text)
        inventory_links = [link for link in navigation.links if (
            "sort" in link.get("class", "").split()
            or link["text"].startswith("Next")
            or "cw-stat" in link.get("class", "").split()
        )]
        assert inventory_links
        for link in inventory_links:
            actual = _params(link)
            assert actual["q"] == query
            assert actual["source"] == "uploaded"
            assert actual["grouped"] == "0"
            assert "ignored" not in actual
        next_link = next(link for link in navigation.links if link["text"].startswith("Next"))
        assert _params(next_link)["sort_by"] == "days"
        assert _params(next_link)["sort_order"] == "desc"
        second = client.get(next_link["href"])
        assert second.context["page"] == 2
        assert len(second.context["entries"]) == 3
        first_ids = {entry["id"] for entry in response.context["entries"]}
        second_ids = {entry["id"] for entry in second.context["entries"]}
        assert first_ids.isdisjoint(second_ids)
        assert min(entry["days_remaining"] for entry in response.context["entries"]) >= max(
            entry["days_remaining"] for entry in second.context["entries"]
        )
        search = next(form for form in navigation.forms if form.get("action") == "/browse")
        hidden = {field["name"]: field["value"] for field in search["inputs"]
                  if field.get("type") == "hidden"}
        assert hidden == {key: params[key] for key in (
            "urgency", "source", "sort_by", "sort_order", "grouped",
        )}
        assert 'data-testid="active-inventory-filters"' in response.text
        clear = next(link for link in navigation.links if link["text"] == "Clear filters")
        assert not {"q", "urgency", "source"} & _params(clear).keys()
        assert _params(clear)["grouped"] == "0"
        assert client.get(clear["href"]).context["total_entries"] == 30


@pytest.mark.parametrize("view", ["issuer", "owner", "renewal_method", "calendar"])
def test_global_views_drop_stale_inventory_filters(reload_app, tmp_path, view):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    _add_file(db, "uploaded-only", 50)
    with TestClient(app_mod.app) as client:
        response = client.get("/browse", params={
            "view": view, "q": "no-match", "urgency": "expired", "source": "scanned",
        })
    assert response.status_code == 200
    assert response.context["pivot_view"] == view
    assert response.context["filter_q"] == ""
    assert response.context["filter_urgency"] == ""
    assert response.context["filter_source"] == ""
    assert 'data-testid="dashboard-search"' not in response.text
    assert "Inventory filters do not apply" in response.text
    if view == "calendar":
        assert "scanned and uploaded certificates" in response.text
        assert response.context["total_entries"] == 1
    else:
        assert "scanned endpoints and pending hosts" in response.text
        assert response.context["pivot_groups"] == []
        assert response.context["entries"] == []
        assert 'data-testid="empty-pivot"' in response.text
        assert 'data-testid="cert-row"' not in response.text


def test_global_view_links_explicitly_leave_inventory_filters(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        response = client.get("/browse?q=team&urgency=warning&source=uploaded&grouped=0")
    navigation = _Navigation(response.text)
    view_links = [link for link in navigation.links if "view" in _params(link)]
    assert {_params(link)["view"] for link in view_links} == {
        "issuer", "owner", "renewal_method", "calendar",
    }
    for link in view_links:
        assert set(_params(link)) == {"view"}
        assert "all" in link["text"].lower()
