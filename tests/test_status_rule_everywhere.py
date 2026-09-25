"""One status per certificate on every surface, and counts that cost O(groups).

#113 review: the pivot groups, the group-expansion API and the compliance
report's buckets each derived status their own way (the leaf's days, the most
urgent chain certificate, the chain floor or not), so one certificate could be
Expired in a group, Healthy when the group was expanded and in no bucket of
the report. There is now one rule (:mod:`cert_watch.status_rule`) that the
Python rows and the SQL counts share.

The first half seeds an estate with *real* chains -- an expired intermediate
under a 99-day leaf, an intermediate expiring before a 60-day leaf, a chain no
trust anchor vouches for, one host on two ports, a pending endpoint and
uploaded files -- and asserts every surface gives each certificate the same
status. The second half is the scaling guard: on a larger estate, rendering a
group view, its cards, Home's cards and expanding one group must build rows
for at most the rows shown, never for the estate.
"""

from __future__ import annotations

import datetime as dt
from collections import Counter
from pathlib import Path
from urllib.parse import quote

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from cert_watch.certificate_model import Certificate, parse_certificate

NOW = dt.datetime.now(dt.UTC)


def _at(days: int) -> dt.datetime:
    # Half a day of slack keeps whole-day counts stable for the whole run.
    return NOW + dt.timedelta(days=days, hours=12)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _issue(subject: str, days: int, issuer: tuple[x509.Name, object] | None, *, ca: bool):
    key = ec.generate_private_key(ec.SECP256R1())
    issuer_name, issuer_key = issuer if issuer else (_name(subject), key)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - dt.timedelta(days=500))
        .not_valid_after(_at(days))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if not ca:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(subject)]), critical=False
        )
    cert = builder.sign(issuer_key, hashes.SHA256())
    parsed = parse_certificate(cert.public_bytes(serialization.Encoding.DER))
    assert isinstance(parsed, Certificate)
    return parsed, (_name(subject), key)


# key, owner, renewal method, leaf days, intermediate ("ok" / "expired" /
# "soon" / None = unknown issuer, no chain), expected status, effective days.
ROWS: list[tuple[str, str, str, int | None, str | None, str, int | None]] = [
    ("ok.example.test:443", "Team A", "acme", 90, "ok", "healthy", 90),
    ("ok.example.test:8443", "Team A", "acme", 20, "ok", "warning", 20),
    ("expint.example.test:443", "Team B", "manual", 99, "expired", "expired", -3),
    ("soon.example.test:443", "Team B", "", 60, "soon", "critical", 5),
    ("untrusted.example.test:443", "", "manual", 200, None, "warning", 200),
    ("pending.example.test:443", "Team A", "acme", None, None, "gray", None),
    ("upload-ok.example.test", "", "", 45, "ok", "healthy", 45),
    ("upload-untrusted.example.test", "", "", 100, None, "warning", 100),
]
EXPECTED = {key: status for key, _, _, _, _, status, _ in ROWS}
EFFECTIVE = {key: days for key, *_, days in ROWS}
STATUS_COUNTS = {
    u: sum(1 for s in EXPECTED.values() if s == u)
    for u in ("expired", "critical", "warning", "healthy")
}
_ORDER = ("expired", "critical", "warning", "healthy", "gray")


def _row_key(entry: dict) -> str:
    if entry.get("kind") == "uploaded":
        return entry["subject"].split("CN=", 1)[-1].split(",", 1)[0]
    return entry["host"]


def _seed(db: Path, *, with_anchor: bool = True) -> Certificate:
    from cert_watch.database import (
        SqliteHostRepository,
        SqliteTrustAnchorRepository,
        init_schema,
        replace_scanned,
    )
    from cert_watch.database.connection import _connect
    from cert_watch.upload import UploadedEntry, store_uploaded

    init_schema(db)
    root, root_issuer = _issue("Example Private Root", 3650, None, ca=True)
    inters = {}
    for label, days in (("ok", 400), ("expired", -3), ("soon", 5)):
        inters[label] = _issue(f"Example Issuing CA {label}", days, root_issuer, ca=True)
    stray = _issue("Unknown Stray CA", 3650, None, ca=True)[1]
    if with_anchor:
        SqliteTrustAnchorRepository(db).add(root)

    for key, owner, method, days, inter, _status, _eff in ROWS:
        if ":" not in key:
            continue
        host, port = key.rsplit(":", 1)
        SqliteHostRepository(db).add(host, int(port))
        with _connect(db) as conn:
            conn.execute(
                "UPDATE hosts SET owner_name = ?, renewal_method = ?"
                " WHERE hostname = ? AND port = ?",
                (owner, method, host, int(port)),
            )
            conn.commit()
        if days is None:
            continue
        issuer = inters[inter][1] if inter else stray
        leaf, _ = _issue(host, days, issuer, ca=False)
        chain = [inters[inter][0]] if inter else []
        replace_scanned(db, host, int(port), leaf, chain, bool(inter))
    for key, _owner, _method, days, inter, _status, _eff in ROWS:
        if ":" in key:
            continue
        leaf, _ = _issue(key, days or 0, inters[inter][1] if inter else stray, ca=False)
        chain = [inters[inter][0]] if inter else []
        store_uploaded(UploadedEntry(f"{key}.pem", leaf, chain), db)
    return root


@pytest.fixture
def estate(tmp_path):
    db = tmp_path / "cert-watch.sqlite3"
    _seed(db)
    return db


def test_browse_rows_carry_the_expected_status(estate):
    from cert_watch.database import list_dashboard_page

    rows, total = list_dashboard_page(estate, per_page=25)
    assert total == len(ROWS)
    assert {_row_key(r): r["urgency"] for r in rows} == EXPECTED
    for r in rows:
        assert r.get("effective_days") == EFFECTIVE[_row_key(r)], _row_key(r)


def test_status_filter_selects_the_rows_with_that_status(estate):
    from cert_watch.database import list_dashboard_page

    for urgency in ("expired", "critical", "warning", "healthy"):
        rows, total = list_dashboard_page(estate, urgency=urgency, per_page=25)
        want = sorted(k for k, s in EXPECTED.items() if s == urgency)
        assert sorted(_row_key(r) for r in rows) == want, urgency
        assert total == len(want), urgency


def test_home_cards_and_group_view_cards_count_the_rows(estate):
    from cert_watch.database import dashboard_urgency_stats
    from cert_watch.services.browse_page import load_browse_page

    assert dashboard_urgency_stats(estate, scope_tags=()) == STATUS_COUNTS
    for view in ("", "owner", "issuer", "renewal_method"):
        data = load_browse_page(
            estate, q=None, urgency=None, source=None, sort_by="days", sort_order="asc",
            page=1, grouped=0, view=view, scope_tags=(), sched_hour=6, sched_min=0,
        )
        assert data.pivot_stats == STATUS_COUNTS, view
        assert data.tracked_total == len(ROWS), view


def _expected_groups(field: int, label) -> dict[str, dict]:
    groups: dict[str, dict] = {}
    for row in ROWS:
        key = label(row[field])
        g = groups.setdefault(key, {"count": 0, "statuses": set(), "earliest": None})
        g["count"] += 1
        g["statuses"].add(row[5])
        if row[6] is not None and (g["earliest"] is None or row[6] < g["earliest"]):
            g["earliest"] = row[6]
    for g in groups.values():
        worst = next(u for u in _ORDER if u in g["statuses"])
        g["worst"] = "gray" if worst == "healthy" and "gray" in g["statuses"] else worst
    return groups


_PIVOTS = [
    ("owner", 1, lambda raw: raw or "Unassigned"),
    ("renewal_method", 2,
     lambda raw: {"acme": "ACME", "manual": "Manual"}.get(raw, raw) or "Unknown"),
]


@pytest.mark.parametrize(("pivot", "field", "label"), _PIVOTS, ids=["owner", "method"])
def test_groups_agree_with_the_rows(estate, pivot, field, label):
    from cert_watch.database import list_fleet_pivot

    expected = _expected_groups(field, label)
    groups = {g["key"]: g for g in list_fleet_pivot(estate, pivot)}
    assert set(groups) == set(expected)
    for key, want in expected.items():
        assert groups[key]["count"] == want["count"], key
        assert groups[key]["worst_urgency"] == want["worst"], key
        # The soonest expiry in any row's stored chain.
        assert groups[key]["earliest_expiry"] == want["earliest"], key


@pytest.mark.parametrize(("pivot", "field", "label"), _PIVOTS, ids=["owner", "method"])
def test_expanding_a_group_shows_the_rows_it_counted(
    estate, tmp_path, reload_app, pivot, field, label,
):
    from fastapi.testclient import TestClient

    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        for key in _expected_groups(field, label):
            body = client.get(f"/api/pivot/{pivot}/{quote(key)}").json()
            got = {_row_key(e): e["urgency"] for e in body["entries"]}
            members = {r[0] for r in ROWS if label(r[field]) == key}
            assert got == {k: EXPECTED[k] for k in members}, key


def test_compliance_buckets_follow_the_status(estate):
    from cert_watch.compliance import build_compliance_report

    report = build_compliance_report(estate, signing_key="k")
    assert report.total_certs == len([r for r in ROWS if r[3] is not None])
    buckets = {b.label: b.entries for b in report.remediation_buckets}
    band = {
        "Expired": "expired",
        "Expiring within 7 days": "critical",
        "Expiring within 30 days": "warning",
    }
    placed: dict[str, str] = {}
    for label, entries in buckets.items():
        if label == "Failed posture checks":
            continue
        for e in entries:
            key = e.host if e.host != "(uploaded)" else e.subject.split("CN=", 1)[-1]
            assert key not in placed, f"{key} in two expiry buckets"
            placed[key] = label
            assert e.urgency == EXPECTED[key], key
            assert e.days_remaining == EFFECTIVE[key], key
            if label in band:
                # The status is at least as urgent as the bucket says.
                assert _ORDER.index(e.urgency) <= _ORDER.index(band[label]), key
    # The reviewer's two cases: an expired intermediate under a 99-day leaf is
    # Expired and listed as such; a 5-day intermediate under a 60-day leaf is
    # due within 7 days, not 90.
    assert placed["expint.example.test:443"] == "Expired"
    assert placed["soon.example.test:443"] == "Expiring within 7 days"
    for key, status in EXPECTED.items():
        if status in ("expired", "critical"):
            assert key in placed, key


def test_posture_and_metrics_count_the_same_certificates(estate, tmp_path, reload_app):
    from fastapi.testclient import TestClient

    from cert_watch.compliance import build_compliance_report, fleet_grade_summary

    report = build_compliance_report(estate, signing_key="k")
    summary = fleet_grade_summary(estate)
    assert summary is not None
    assert summary["total"] == report.total_certs

    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        text = client.get("/metrics").text
    got = {}
    for line in text.splitlines():
        if line.startswith("cert_watch_certificates_by_urgency{"):
            label = line.split('urgency="', 1)[1].split('"', 1)[0]
            got[label] = int(float(line.rsplit(" ", 1)[1]))
    assert got == STATUS_COUNTS


def test_grouped_browse_filter_uses_the_same_status(estate):
    from cert_watch.database import list_dashboard_grouped_page

    for urgency in ("expired", "critical", "warning", "healthy"):
        rows, _ = list_dashboard_grouped_page(estate, urgency=urgency, per_page=0)
        assert sorted(_row_key(r) for r in rows) == sorted(
            k for k, s in EXPECTED.items() if s == urgency
        ), urgency


def test_trust_anchor_changes_reach_the_counts(tmp_path):
    """The SQL counts read a cached chain status; adding or removing a trust
    anchor must change it exactly as it changes the rows."""
    from cert_watch.database import (
        SqliteTrustAnchorRepository,
        dashboard_urgency_stats,
        list_dashboard_page,
    )

    db = tmp_path / "anchors.sqlite3"
    root = _seed(db, with_anchor=False)
    anchors = SqliteTrustAnchorRepository(db)

    def rows_and_counts():
        rows, _ = list_dashboard_page(db, per_page=25)
        by_key = {_row_key(r): r["urgency"] for r in rows}
        counts = Counter(s for s in by_key.values() if s != "gray")
        assert dashboard_urgency_stats(db) == {u: counts.get(u, 0) for u in STATUS_COUNTS}
        return by_key

    # No anchor: the private chains are incomplete, so Healthy is lifted.
    assert rows_and_counts()["ok.example.test:443"] == "warning"
    # A different key under the root's name vouches for nothing.
    impostor, _ = _issue("Example Private Root", 3650, None, ca=True)
    impostor_id = anchors.add(impostor)
    assert rows_and_counts()["ok.example.test:443"] == "warning"
    anchors.delete(impostor_id)
    # The real root: every surface now sees the expected estate.
    root_id = anchors.add(root)
    assert rows_and_counts() == EXPECTED
    assert dashboard_urgency_stats(db) == STATUS_COUNTS
    # And removing it again takes effect everywhere.
    anchors.delete(root_id)
    assert rows_and_counts()["ok.example.test:443"] == "warning"


# --- scaling guard -------------------------------------------------------------


def _count_built_rows(monkeypatch) -> dict[str, int]:
    """Count leaf rows handed to the row builder (``n``) and live chain
    verifications (``verified``): the per-row work a request does."""
    from cert_watch.database import dashboard_grouped, dashboard_rows, dashboard_unified

    calls = {"n": 0, "verified": 0}
    real = dashboard_rows._build_dashboard_rows

    def counting(cert_rows, anchor_rows, **kwargs):
        calls["n"] += sum(1 for r in cert_rows if dict(r)["is_leaf"])
        return real(cert_rows, anchor_rows, **kwargs)

    for module in (dashboard_rows, dashboard_unified, dashboard_grouped):
        monkeypatch.setattr(module, "_build_dashboard_rows", counting)
    return calls

BIG_OWNERS = [f"Team {i}" for i in range(6)]
PER_OWNER = 40


@pytest.fixture
def big_estate(tmp_path, monkeypatch):
    """240 endpoints across six owners plus a two-endpoint group, with chain
    status evaluations counted (each built row evaluates it once)."""
    from cert_watch.database import SqliteHostRepository, init_schema, replace_scanned
    from cert_watch.database.connection import _connect

    calls = _count_built_rows(monkeypatch)

    def counting_chain_status(leaf, chain, anchors):
        calls["verified"] += 1
        return "public"

    monkeypatch.setattr("cert_watch.cert_chain.chain_status", counting_chain_status)
    db = tmp_path / "big.sqlite3"
    init_schema(db)
    hosts = SqliteHostRepository(db)
    endpoints = [
        (f"h{o}-{i}.example.test", owner)
        for o, owner in enumerate(BIG_OWNERS) for i in range(PER_OWNER)
    ] + [("small-1.example.test", "Small"), ("small-2.example.test", "Small")]
    for n, (host, _owner) in enumerate(endpoints):
        hosts.add(host, 443)
        cert = Certificate(
            subject=f"CN={host}",
            issuer="CN=Example CA",
            not_before=NOW - dt.timedelta(days=30),
            not_after=_at(5 + n % 90),
            fingerprint_sha256=f"fp-{n}",
        )
        replace_scanned(db, host, 443, cert, [], True)
    with _connect(db) as conn:
        conn.executemany(
            "UPDATE hosts SET owner_name = ? WHERE hostname = ?",
            [(owner, host) for host, owner in endpoints],
        )
        conn.commit()
    return db, calls, len(endpoints)


def test_group_views_and_cards_do_not_build_the_estate(big_estate):
    from cert_watch.database import (
        dashboard_urgency_stats,
        get_pivot_group_entries,
        list_dashboard_grouped_page,
        list_dashboard_page,
    )
    from cert_watch.services.browse_page import load_browse_page

    db, calls, size = big_estate
    # First read fills the chain-status cache: once per certificate, ever.
    assert sum(dashboard_urgency_stats(db).values()) == size
    first_fill = calls["verified"]
    assert first_fill <= size

    def built(fn) -> int:
        calls["n"] = 0
        fn()
        return calls["n"]

    for view in ("owner", "issuer", "renewal_method"):
        assert built(lambda view=view: load_browse_page(
            db, q=None, urgency=None, source=None, sort_by="days", sort_order="asc",
            page=1, grouped=0, view=view, scope_tags=(), sched_hour=6, sched_min=0,
        )) == 0, view
    assert built(lambda: dashboard_urgency_stats(db)) == 0
    assert built(lambda: get_pivot_group_entries(db, "owner", "Small")) == 2
    assert built(lambda: list_dashboard_page(db, per_page=25)) <= 25
    assert built(lambda: list_dashboard_page(db, urgency="warning", per_page=25)) <= 25
    assert built(lambda: list_dashboard_grouped_page(db, per_page=25)) <= 25


def test_steady_state_recomputes_no_chain_status(big_estate):
    from cert_watch.database import dashboard_urgency_stats
    from cert_watch.database.chain_status_cache import refresh_chain_status

    db, _calls, size = big_estate
    dashboard_urgency_stats(db)
    assert refresh_chain_status(db) == 0
    # A rescan replaces one leaf: exactly that one is recomputed.
    from cert_watch.database import replace_scanned

    replace_scanned(db, "small-1.example.test", 443, Certificate(
        subject="CN=small-1.example.test", issuer="CN=Example CA",
        not_before=NOW - dt.timedelta(days=1), not_after=_at(300),
        fingerprint_sha256="fp-renewed",
    ), [], True)
    assert refresh_chain_status(db) == 1
    assert sum(dashboard_urgency_stats(db).values()) == size


# --- large groups, Home's queue ----------------------------------------------

LARGE = 460  # past the 400-row threshold the old expansion path switched on


@pytest.fixture
def large_group_estate(tmp_path, monkeypatch):
    """One owner with 460 endpoints (all expiring within 30 days, so every row
    needs attention) and 40 other endpoints, chain evaluations counted."""
    from cert_watch.database import SqliteHostRepository, init_schema, replace_scanned
    from cert_watch.database.connection import _connect

    calls = _count_built_rows(monkeypatch)

    def counting_chain_status(leaf, chain, anchors):
        calls["verified"] += 1
        return "public"

    monkeypatch.setattr("cert_watch.cert_chain.chain_status", counting_chain_status)
    db = tmp_path / "cert-watch.sqlite3"  # the app's database under reload_app
    init_schema(db)
    hosts = SqliteHostRepository(db)
    owners = []
    for n in range(LARGE + 40):
        host = f"lg-{n}.example.test"
        hosts.add(host, 443)
        owners.append(("Big Team" if n < LARGE else "Other Team", host))
        replace_scanned(db, host, 443, Certificate(
            subject=f"CN={host}", issuer="CN=Example CA",
            not_before=NOW - dt.timedelta(days=30), not_after=_at(1 + n % 25),
            fingerprint_sha256=f"lg-{n}",
        ), [], True)
    with _connect(db) as conn:
        conn.executemany("UPDATE hosts SET owner_name = ? WHERE hostname = ?", owners)
        conn.commit()
    return db, calls


def _traced(db: Path, fn):
    """Run *fn*, returning its result and every SQL statement it ran."""
    from cert_watch.database.connection import _connect

    statements: list[str] = []
    conn = _connect(db)
    conn.set_trace_callback(statements.append)
    try:
        return fn(), statements
    finally:
        conn.set_trace_callback(None)


def _estate_wide_reads(statements: list[str]) -> list[str]:
    """Reads of hosts or scan history not keyed by the selected rows."""
    import re

    unkeyed = re.compile(
        r"SELECT \* FROM hosts(\s+ORDER BY|\s*$)|FROM scan_history sh1\s+WHERE 1 = 1"
    )
    return [s for s in statements if unkeyed.search(s)]


def test_expanding_a_large_group_is_paged_and_keyed_by_the_group(large_group_estate):
    from cert_watch.database import dashboard_urgency_stats, get_pivot_group_page

    db, calls = large_group_estate
    dashboard_urgency_stats(db)  # fill the cache
    calls["n"] = 0
    (entries, total), statements = _traced(
        db, lambda: get_pivot_group_page(db, "owner", "Big Team", page=2, per_page=100)
    )
    assert total == LARGE
    assert len(entries) == 100
    assert calls["n"] == 100
    assert _estate_wide_reads(statements) == []

    # The whole group, when asked for, still reads only the group.
    from cert_watch.database import get_pivot_group_entries

    calls["n"] = 0
    everything, statements = _traced(db, lambda: get_pivot_group_entries(db, "owner", "Big Team"))
    assert len(everything) == LARGE
    assert calls["n"] == LARGE
    assert _estate_wide_reads(statements) == []


def test_group_expansion_api_pages(large_group_estate, reload_app):
    from fastapi.testclient import TestClient

    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        first = client.get("/api/pivot/owner/Big%20Team").json()
        last = client.get("/api/pivot/owner/Big%20Team?page=5").json()
    assert (first["total"], len(first["entries"]), first["has_more"]) == (LARGE, 100, True)
    assert (len(last["entries"]), last["has_more"]) == (LARGE - 400, False)
    seen = {e["id"] for e in first["entries"]} & {e["id"] for e in last["entries"]}
    assert seen == set()


def test_home_queue_builds_only_the_items_shown(large_group_estate):
    from cert_watch.attention import HOME_QUEUE_LIMIT, attention_queue_page
    from cert_watch.database import dashboard_urgency_stats

    db, calls = large_group_estate
    dashboard_urgency_stats(db)
    calls["n"] = 0
    (items, total), statements = _traced(db, lambda: attention_queue_page(db))
    assert total == LARGE + 40
    assert len(items) == HOME_QUEUE_LIMIT
    assert calls["n"] <= HOME_QUEUE_LIMIT
    assert _estate_wide_reads(statements) == []


def test_home_queue_page_is_the_head_of_the_whole_queue(estate):
    """Ranking in SQL picks exactly the items the full ranking puts first."""
    from cert_watch.attention import attention_queue_page

    everything, total = attention_queue_page(estate, limit=None)
    assert total == len(everything)
    for limit in range(1, len(everything) + 1):
        head, head_total = attention_queue_page(estate, limit=limit)
        assert head_total == total
        assert head == everything[:limit], limit


def test_home_queue_uses_the_status_rule(estate):
    """The queue lists every certificate the cards count as not healthy, at
    that severity: an expired intermediate under a 99-day leaf is Expired."""
    from cert_watch.attention import attention_queue_page

    items, _ = attention_queue_page(estate, limit=None)
    by_endpoint: dict[str, set[str]] = {}
    for item in items:
        by_endpoint.setdefault(item["endpoint"], set()).add(item["severity"])
    expint = next(i for i in items if i["endpoint"] == "expint.example.test:443")
    assert expint["severity"] == "expired"
    assert expint["days_remaining"] == -3
    assert any("chain certificate" in r for r in expint["reasons"])
    soon = next(i for i in items if i["endpoint"] == "soon.example.test:443")
    assert (soon["severity"], soon["days_remaining"]) == ("critical", 5)
    for key, status in EXPECTED.items():
        if status in ("expired", "critical", "warning"):
            assert key in by_endpoint, key


# --- one instant per request ---------------------------------------------------

REFERENCE = dt.datetime(2035, 1, 1, 12, 0, tzinfo=dt.UTC)


@pytest.fixture
def boundary(tmp_path):
    """A certificate expiring exactly seven days after REFERENCE: Warning at
    REFERENCE, Critical one second later."""
    from cert_watch.database import SqliteHostRepository, init_schema, replace_scanned

    db = tmp_path / "boundary.sqlite3"
    init_schema(db)
    SqliteHostRepository(db).add("boundary.example.test", 443)
    replace_scanned(db, "boundary.example.test", 443, Certificate(
        subject="CN=boundary.example.test", issuer="CN=Unknown",
        not_before=REFERENCE - dt.timedelta(days=1),
        not_after=REFERENCE + dt.timedelta(days=7), fingerprint_sha256="boundary",
    ), [], True)
    return db


def test_an_injected_instant_reaches_the_rows_too(boundary, monkeypatch):
    from freezegun import freeze_time

    from cert_watch.database import get_pivot_group_entries, list_dashboard_page, list_fleet_pivot

    monkeypatch.setattr("cert_watch.cert_chain.chain_status", lambda *a: "public")
    with freeze_time(REFERENCE + dt.timedelta(seconds=1)):
        rows, total = list_dashboard_page(boundary, urgency="warning", per_page=25, now=REFERENCE)
        assert total == 1
        assert [(r["urgency"], r["effective_days"]) for r in rows] == [("warning", 7)]
        group = list_fleet_pivot(boundary, "owner", now=REFERENCE)[0]
        expanded = get_pivot_group_entries(boundary, "owner", group["key"], now=REFERENCE)
    assert (group["worst_urgency"], group["earliest_expiry"]) == ("warning", 7)
    assert [(r["urgency"], r["effective_days"]) for r in expanded] == [("warning", 7)]


def test_a_request_judges_selection_and_rows_at_one_instant(boundary, monkeypatch):
    """The clock ticks a second on every read, straddling the boundary; the
    filter and the rows it returns must still agree."""
    from freezegun import freeze_time

    from cert_watch.database import list_dashboard_page

    monkeypatch.setattr("cert_watch.cert_chain.chain_status", lambda *a: "public")
    for urgency in ("warning", "critical"):
        with freeze_time(REFERENCE - dt.timedelta(milliseconds=500), auto_tick_seconds=1):
            rows, total = list_dashboard_page(boundary, urgency=urgency, per_page=25)
        assert total == len(rows)
        assert all(r["urgency"] == urgency for r in rows), (urgency, rows)
