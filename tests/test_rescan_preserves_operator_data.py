"""What a scan does to every stored reference to a certificate id (#113).

A scan rewrites the endpoint's certificate rows: an unchanged rescan keeps
the leaf's id (#113 item 3), a renewal inserts a successor with a new id.
Everything else in the schema that names a certificate id has to do the right
thing in both cases. ``CERT_ID_REFERENCES`` in ``cert_ops`` declares the
policy per column; the first tests keep that declaration complete, the rest
prove each policy holds.

The #115 review found two operator-set values that every scan silently
dropped (in 1.0.2 too, since every scan inserted a fresh row without them):
the certificate's own ``tags`` and its manual alert-group assignments.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

import pytest

from cert_watch.alerting.routing import resolve_routing
from cert_watch.certificate_model import parse_certificate
from cert_watch.database import (
    Alert,
    SqliteAlertGroupRepository,
    SqliteAlertRepository,
    SqliteCertificateRepository,
    SqliteHostRepository,
    init_schema,
)
from cert_watch.database.connection import _connect
from tests._helpers import seed_scanned
from tests.conftest import _make_cert

_HOST = "leaf.example.test"
_POLICIES = {"KEPT", "FOLLOWS", "HISTORY", "REDERIVED", "ENDPOINT"}


def _db(tmp_path: Path) -> Path:
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    SqliteHostRepository(db).add(_HOST, 443)
    return db


def _scan_first(db: Path, self_signed_leaf) -> str:
    return seed_scanned(db, _HOST, 443, parse_certificate(self_signed_leaf.der))


def _scan_again(db: Path, self_signed_leaf, mode: str) -> str:
    """``rescan`` observes the same certificate; ``renewal`` a new one."""
    der = self_signed_leaf.der if mode == "rescan" else _make_cert(_HOST, days_valid=90).der
    return seed_scanned(db, _HOST, 443, parse_certificate(der))


def _rows(db: Path, sql: str, params: tuple = ()) -> list[dict]:
    with _connect(db) as conn:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]


# -- the declaration is complete -----------------------------------------


def _cert_id_columns(conn: sqlite3.Connection) -> set[str]:
    """Columns that, by name or foreign key, hold a certificate id."""
    found: set[str] = set()
    tables = [
        r[0]
        for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        )
    ]
    for table in tables:
        fks = {
            row[3]
            for row in conn.execute(f"PRAGMA foreign_key_list({table})")
            if row[2] == "certificates"
        }
        for row in conn.execute(f"PRAGMA table_info({table})"):
            col = row[1]
            if table == "certificates":
                named = col == "id" or col.endswith("_id")
            else:
                named = re.search(r"cert", col, re.IGNORECASE) is not None
            if named or col in fks:
                found.add(f"{table}.{col}")
    return found


def test_every_cert_id_column_has_a_declared_scan_policy(tmp_path):
    """A new column naming a certificate (``*cert*``, a foreign key to
    ``certificates``, or a new ``certificates.*_id``) fails here until
    ``CERT_ID_REFERENCES`` says what an unchanged rescan and a renewal do
    to it -- otherwise a scan silently orphans or drops it.

    The detection is a name/foreign-key heuristic, not a proof. A column
    named without "cert" (``resource_id``, ``target_id``) or a JSON/text body
    that happens to embed a certificate id is not found; those have to be
    declared by hand, as ``audit_log.target_id`` and ``event_log.payload``
    are. The test only guarantees that declared columns still exist.
    """
    from cert_watch.database.cert_ops import CERT_ID_REFERENCES

    db = tmp_path / "c.sqlite3"
    init_schema(db)
    with _connect(db) as conn:
        detected = _cert_id_columns(conn)
        existing = {
            f"{t}.{row[1]}"
            for (t,) in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
            for row in conn.execute(f"PRAGMA table_info({t})")
        }
    assert "alerts.cert_id" in detected  # the detector itself works
    assert detected - set(CERT_ID_REFERENCES) == set()
    # Informal references (JSON payloads, keys) can't be detected by name;
    # a declared column that no longer exists is a stale declaration.
    assert set(CERT_ID_REFERENCES) - existing == set()
    for policy in CERT_ID_REFERENCES.values():
        assert set(policy) <= _POLICIES


def test_every_certificate_column_is_either_scanned_or_carried(tmp_path):
    """A new operator-set column must be added to the carried set, or a scan
    silently wipes it."""
    from cert_watch.database.cert_ops import CARRIED_CERT_COLUMNS, SCAN_CERT_COLUMNS

    db = tmp_path / "c.sqlite3"
    init_schema(db)
    with _connect(db) as conn:
        columns = [row[1] for row in conn.execute("PRAGMA table_info(certificates)")]
    assert set(SCAN_CERT_COLUMNS).isdisjoint(CARRIED_CERT_COLUMNS)
    assert set(columns) == set(SCAN_CERT_COLUMNS) | set(CARRIED_CERT_COLUMNS)


# -- certificates.* ------------------------------------------------------


def test_certificates_id_kept_on_rescan_new_on_renewal(tmp_path, self_signed_leaf):
    db = _db(tmp_path)
    first = _scan_first(db, self_signed_leaf)
    assert _scan_again(db, self_signed_leaf, "rescan") == first
    renewed = _scan_again(db, self_signed_leaf, "renewal")
    assert renewed != first
    assert _rows(db, "SELECT id FROM certificates WHERE id = ?", (first,)) == []


def test_replaces_cert_id_names_the_predecessor_and_survives_a_rescan(tmp_path, self_signed_leaf):
    db = _db(tmp_path)
    first = _scan_first(db, self_signed_leaf)
    renewed = _scan_again(db, self_signed_leaf, "renewal")
    lineage = _rows(db, "SELECT replaces_cert_id FROM certificates WHERE id = ?", (renewed,))
    assert lineage == [{"replaces_cert_id": first}]
    # An unchanged rescan of the successor keeps that lineage (never itself).
    renewed_leaf = _rows(db, "SELECT raw_der FROM certificates WHERE id = ?", (renewed,))
    again = seed_scanned(db, _HOST, 443, parse_certificate(renewed_leaf[0]["raw_der"]))
    assert again == renewed
    lineage = _rows(db, "SELECT replaces_cert_id FROM certificates WHERE id = ?", (renewed,))
    assert lineage == [{"replaces_cert_id": first}]


@pytest.mark.parametrize("mode", ["rescan", "renewal"])
def test_chain_rows_hang_off_the_current_leaf(tmp_path, self_signed_leaf, mode):
    db = _db(tmp_path)
    chain = [parse_certificate(_make_cert("ca.example.test", days_valid=900).der)]
    seed_scanned(db, _HOST, 443, parse_certificate(self_signed_leaf.der), chain)
    der = self_signed_leaf.der if mode == "rescan" else _make_cert(_HOST, days_valid=90).der
    current = seed_scanned(db, _HOST, 443, parse_certificate(der), chain)
    parents = _rows(db, "SELECT parent_cert_id FROM certificates WHERE is_leaf = 0")
    assert parents == [{"parent_cert_id": current}]


@pytest.mark.parametrize("mode", ["rescan", "renewal"])
def test_certificate_tags_survive(tmp_path, self_signed_leaf, mode):
    """#115 review finding 2: the leaf's own tags were dropped by every scan,
    narrowing tag-scoped access, compliance scope and tag-matched routing."""
    db = _db(tmp_path)
    old = _scan_first(db, self_signed_leaf)
    repo = SqliteCertificateRepository(db)
    repo.set_tags(old, "team-a,pci")

    current = _scan_again(db, self_signed_leaf, mode)
    assert repo.get_tags(current) == "team-a,pci"


# -- alert_group_certs.cert_id ------------------------------------------


@pytest.mark.parametrize("mode", ["rescan", "renewal"])
def test_manual_alert_group_assignment_survives(tmp_path, self_signed_leaf, mode):
    """#115 review finding 1: the manual assignment was deleted by every scan,
    so a later alert no longer routed to the group. It follows the endpoint's
    certificate to a successor on renewal."""
    db = _db(tmp_path)
    old = _scan_first(db, self_signed_leaf)
    groups = SqliteAlertGroupRepository(db)
    group_id = groups.create(name="G", recipients=["g@example.test"], match_tags=[])
    groups.assign_cert(group_id, old)

    current = _scan_again(db, self_signed_leaf, mode)
    assert groups.groups_for_cert_manual(current) == [group_id]
    assert "g@example.test" in str(resolve_routing(db, (current,))[current])
    if mode == "renewal":
        assert groups.groups_for_cert_manual(old) == []


# -- alerts.cert_id, alerts.read (acknowledgement), alerts.trigger_cert_id


def _alert(db: Path, cert_id: str, status: str = "sent") -> str:
    alert_id = SqliteAlertRepository(db).create(
        Alert(
            cert_id=cert_id,
            alert_type="expiry_warning",
            status=status,
            message="expiring",
            threshold_days=7,
            hostname=_HOST,
            dedupe_key=f"expiry:{_HOST}:443:{cert_id}:expiry_warning:7",
        )
    )
    with _connect(db) as conn:
        conn.execute("UPDATE alerts SET read = 1 WHERE id = ?", (alert_id,))
        conn.commit()
    return alert_id


def test_rescan_keeps_alerts_and_their_acknowledgement(tmp_path, self_signed_leaf):
    db = _db(tmp_path)
    cert_id = _scan_first(db, self_signed_leaf)
    alert_id = _alert(db, cert_id)
    _scan_again(db, self_signed_leaf, "rescan")
    [row] = _rows(db, "SELECT * FROM alerts WHERE id = ?", (alert_id,))
    assert (row["cert_id"], row["read"], row["status"], row["closed_at"]) == (
        cert_id,
        1,
        "sent",
        None,
    )
    assert row["trigger_cert_id"] == cert_id


def test_renewal_leaves_alerts_as_history_on_the_old_id(tmp_path, self_signed_leaf):
    """An alert and its acknowledgement describe the certificate that fired.
    A renewal closes it where it is; the successor starts with no alerts and
    nothing acknowledged on its behalf."""
    db = _db(tmp_path)
    old = _scan_first(db, self_signed_leaf)
    alert_id = _alert(db, old)
    new = _scan_again(db, self_signed_leaf, "renewal")
    [row] = _rows(db, "SELECT * FROM alerts WHERE id = ?", (alert_id,))
    assert (row["cert_id"], row["trigger_cert_id"], row["read"]) == (old, old, 1)
    assert row["closed_at"] is not None
    # (The renewal may raise its own new alerts, e.g. drift; none of them is
    # the old alert moved over, and none is acknowledged.)
    assert _rows(db, "SELECT id FROM alerts WHERE cert_id = ? AND read = 1", (new,)) == []


# -- keys and append-only history ---------------------------------------


@pytest.mark.parametrize("mode", ["rescan", "renewal"])
def test_history_and_keys_are_never_rewritten(tmp_path, self_signed_leaf, mode):
    from cert_watch.audit import record_audit

    db = _db(tmp_path)
    old = _scan_first(db, self_signed_leaf)
    _alert(db, old)
    record_audit(
        db,
        actor="admin",
        action="cert.update_tags",
        target_type="certificate",
        target_id=old,
        detail={"cert_id": old},
    )
    with _connect(db) as conn:
        conn.execute(
            "INSERT INTO rule_firings VALUES (?, '2026-01-01', '2026-01-01', 1)",
            (f"expiry:{_HOST}:443:fp:expiry_warning:7",),
        )
        conn.commit()

    def snapshot() -> tuple:
        return (
            _rows(db, "SELECT id, trigger_cert_id, dedupe_key FROM alerts ORDER BY id"),
            _rows(db, "SELECT * FROM rule_firings"),
            _rows(db, "SELECT * FROM audit_log ORDER BY id"),
            _rows(db, "SELECT id, payload FROM event_log ORDER BY id"),
        )

    before = snapshot()
    _scan_again(db, self_signed_leaf, mode)
    after = snapshot()
    # A scan may append rows (a renewal raises a drift alert and a lifecycle
    # event); the rows that existed before are never edited.
    for rows_before, rows_after in zip(before, after, strict=True):
        assert [r for r in rows_after if r in rows_before] == rows_before


# -- no reference is left dangling ---------------------------------------


@pytest.mark.parametrize("mode", ["rescan", "renewal"])
def test_live_references_never_dangle(tmp_path, self_signed_leaf, mode):
    """Every reference that is not history must name an existing row."""
    from cert_watch.database.cert_ops import CERT_ID_REFERENCES

    db = _db(tmp_path)
    old = _scan_first(db, self_signed_leaf)
    groups = SqliteAlertGroupRepository(db)
    groups.assign_cert(groups.create(name="G", recipients=[], match_tags=[]), old)
    _scan_again(db, self_signed_leaf, mode)

    live = [
        column
        for column, policies in CERT_ID_REFERENCES.items()
        if not set(policies) & {"HISTORY", "ENDPOINT"}
        and column not in {"certificates.id", "certificates.replaces_cert_id"}
    ]
    assert live  # parent_cert_id, alert_group_certs, scan_posture
    for column in live:
        table, col = column.split(".")
        dangling = _rows(
            db,
            f"SELECT {col} FROM {table} WHERE {col} IS NOT NULL "
            f"AND {col} NOT IN (SELECT id FROM certificates)",
        )
        assert dangling == [], column


# -- a duplicate leaf for the endpoint (#115 review round 2) ------------


def _team_b_operator():
    from cert_watch.auth.rbac import AuthContext

    return AuthContext(
        username="b",
        roles=["viewer"],
        tier="viewer",
        scope_tag="team-b",
        tag_tiers={"team-b": "operator"},
    )


def _with_stale_duplicate(db: Path, self_signed_leaf) -> tuple[str, str, str]:
    """The live team-a leaf, plus an older second leaf row for the same
    endpoint tagged team-b and manually routed to a stale group (the schema
    allows it and the repository API can insert one)."""
    from tests._helpers import seed_certificate

    live = _scan_first(db, self_signed_leaf)
    SqliteCertificateRepository(db).set_tags(live, "team-a")
    stale = seed_certificate(
        db,
        parse_certificate(_make_cert(_HOST, days_valid=30).der),
        hostname=_HOST,
        port=443,
        source="scanned",
    )
    with _connect(db) as conn:
        conn.execute(
            "UPDATE certificates SET created_at = '2000-01-01T00:00:00+00:00' WHERE id = ?",
            (stale,),
        )
        conn.commit()
    SqliteCertificateRepository(db).set_tags(stale, "team-b")
    groups = SqliteAlertGroupRepository(db)
    stale_group = groups.create(name="stale", recipients=["stale@example.test"], match_tags=[])
    groups.assign_cert(stale_group, stale)
    return live, stale, stale_group


@pytest.mark.parametrize("mode", ["rescan", "renewal"])
def test_stale_duplicate_leaf_never_leaks_tags_scope_or_routing(tmp_path, self_signed_leaf, mode):
    """Only the predecessor's data is carried: the row with exactly the
    scanned bytes on a rescan; on a renewal, what every current row shares.
    Pre-fix, a rescan merged the duplicate's team-b tag into the live team-a
    certificate (granting a team-b operator write access) and its stale group
    assignment (reviving an obsolete alert destination)."""
    from cert_watch.auth.scope import write_scope_error

    db = _db(tmp_path)
    live, _stale, _stale_group = _with_stale_duplicate(db, self_signed_leaf)
    team_b = _team_b_operator()
    assert write_scope_error(team_b, db, cert_id=live) is not None

    current = _scan_again(db, self_signed_leaf, mode)

    repo = SqliteCertificateRepository(db)
    # A rescan continues from the row with the scanned bytes. A renewal finds
    # two unrelated current rows (neither replaces the other), so it is
    # ambiguous and carries only what they share: here, nothing.
    assert repo.get_tags(current) == ("team-a" if mode == "rescan" else "")
    assert SqliteAlertGroupRepository(db).groups_for_cert_manual(current) == []
    assert "stale@example.test" not in str(resolve_routing(db, (current,))[current])
    assert write_scope_error(team_b, db, cert_id=current) is not None
    # The scan leaves exactly one leaf for the endpoint, continuing the live one.
    leaves = _rows(
        db,
        "SELECT id, replaces_cert_id FROM certificates WHERE hostname = ? AND is_leaf = 1",
        (_HOST,),
    )
    if mode == "rescan":
        assert leaves == [{"id": live, "replaces_cert_id": None}]
    else:
        assert leaves == [{"id": current, "replaces_cert_id": live}]


# -- predecessor chosen by lineage, not time (#115 review round 3) -----


def _leaf_row(db: Path, *, tags: str, replaces: str | None = None, created_at: str) -> str:
    from tests._helpers import seed_certificate

    cert_id = seed_certificate(
        db,
        parse_certificate(_make_cert(_HOST, days_valid=60).der),
        hostname=_HOST,
        port=443,
        source="scanned",
        replaces_cert_id=replaces,
    )
    SqliteCertificateRepository(db).set_tags(cert_id, tags)
    with _connect(db) as conn:
        conn.execute("UPDATE certificates SET created_at = ? WHERE id = ?", (created_at, cert_id))
        conn.commit()
    return cert_id


def _renewal(db: Path) -> str:
    return seed_scanned(db, _HOST, 443, parse_certificate(_make_cert(_HOST, days_valid=90).der))


@pytest.mark.parametrize(
    ("stale_created", "live_created"),
    [
        # clock rollback: the replaced row looks newer than its successor
        ("2026-09-02T00:00:00+00:00", "2026-09-01T00:00:00+00:00"),
        # equal timestamps; the stale row was inserted last (higher rowid)
        ("2026-09-01T00:00:00+00:00", "2026-09-01T00:00:00+00:00"),
    ],
)
def test_renewal_continues_from_the_lineage_head_not_the_newest_row(
    tmp_path, stale_created, live_created
):
    """Sol's round-3 probe: the live leaf L explicitly replaces S, but S sorts
    first by time. Pre-fix the renewal continued from S: its stale tag scope
    and alert route came back, and lineage pointed at S."""
    db = _db(tmp_path)
    groups = SqliteAlertGroupRepository(db)
    live = _leaf_row(db, tags="team-a", created_at=live_created)
    stale = _leaf_row(db, tags="team-stale", created_at=stale_created)
    with _connect(db) as conn:
        conn.execute("UPDATE certificates SET replaces_cert_id = ? WHERE id = ?", (stale, live))
        conn.commit()
    stale_group = groups.create(name="stale", recipients=["stale@example.test"], match_tags=[])
    groups.assign_cert(stale_group, stale)
    live_group = groups.create(name="live", recipients=["live@example.test"], match_tags=[])
    groups.assign_cert(live_group, live)

    new = _renewal(db)

    assert SqliteCertificateRepository(db).get_tags(new) == "team-a"
    assert groups.groups_for_cert_manual(new) == [live_group]
    assert "stale@example.test" not in str(resolve_routing(db, (new,))[new])
    assert _rows(db, "SELECT replaces_cert_id FROM certificates WHERE id = ?", (new,)) == [
        {"replaces_cert_id": live}
    ]


def test_two_current_heads_carry_only_what_they_share(tmp_path, caplog):
    """Two leaves that no row replaces: genuinely ambiguous. Fail closed --
    carry only the tags and groups common to both -- and say so."""
    import logging

    db = _db(tmp_path)
    groups = SqliteAlertGroupRepository(db)
    a = _leaf_row(db, tags="team-a,shared", created_at="2026-09-01T00:00:00+00:00")
    b = _leaf_row(db, tags="shared,team-b", created_at="2026-09-02T00:00:00+00:00")
    both = groups.create(name="both", recipients=["both@example.test"], match_tags=[])
    only_a = groups.create(name="only-a", recipients=["a@example.test"], match_tags=[])
    only_b = groups.create(name="only-b", recipients=["b@example.test"], match_tags=[])
    for cert_id in (a, b):
        groups.assign_cert(both, cert_id)
    groups.assign_cert(only_a, a)
    groups.assign_cert(only_b, b)  # b is the newest: time must not favour it

    with caplog.at_level(logging.WARNING, logger="cert_watch.database"):
        new = _renewal(db)

    assert SqliteCertificateRepository(db).get_tags(new) == "shared"
    assert groups.groups_for_cert_manual(new) == [both]
    assert any("2 current leaf certificates" in r.getMessage() for r in caplog.records)


# -- rescan continues from the same-bytes row (Fable's round-3 gap) -----


def _dup_estate(tmp_path):
    """The live certificate X (team-a), plus a NEWER duplicate row Y holding a
    different, more urgent certificate (team-b), each with its expiry alert."""
    from cert_watch.alerting.rules.expiry import evaluate_all_certs

    db = _db(tmp_path)
    live = parse_certificate(_make_cert(_HOST, days_valid=10, not_before_days_ago=355).der)
    x = seed_scanned(db, _HOST, 443, live)
    SqliteCertificateRepository(db).set_tags(x, "team-a")
    other = parse_certificate(_make_cert(_HOST, days_valid=2, not_before_days_ago=363).der)
    y = SqliteCertificateRepository(db, source="scanned", hostname=_HOST, port=443).add(other)
    SqliteCertificateRepository(db).set_tags(y, "team-b")
    evaluate_all_certs(db, SqliteAlertRepository(db))  # X -> 14-day alert, Y -> 3-day alert
    return db, x, y, live


def test_rescan_continues_from_the_same_bytes_row_not_the_newest(tmp_path):
    db, x, _y, live = _dup_estate(tmp_path)
    kept = seed_scanned(db, _HOST, 443, live)
    assert kept == x, "predecessor must be the row holding the scanned bytes"
    assert SqliteCertificateRepository(db).get_tags(kept) == "team-a"


def test_rescan_closes_a_different_duplicates_alerts_instead_of_moving_them(tmp_path):
    from cert_watch.alerting.rules.expiry import evaluate_all_certs

    db, x, _y, live = _dup_estate(tmp_path)
    seed_scanned(db, _HOST, 443, live)
    rows = _rows(db, "SELECT cert_id, closed_at IS NOT NULL AS closed FROM alerts")
    on_kept = [r for r in rows if r["cert_id"] == x]
    others = [r for r in rows if r["cert_id"] != x]
    assert on_kept and others, rows
    assert all(not r["closed"] for r in on_kept), rows  # X's own alert stays open
    assert all(r["closed"] for r in others), rows  # Y's is closed, not moved onto X
    # The kept certificate's own dedupe is intact: nothing fires again.
    assert evaluate_all_certs(db, SqliteAlertRepository(db)) == []


# -- the scan's replace holds the write lock from its first read --------

_WRITE_FROM_ANOTHER_PROCESS = r"""
import sqlite3, sys
conn = sqlite3.connect(sys.argv[1], timeout=1.5)
try:
    conn.execute("UPDATE certificates SET tags = 'late-writer' WHERE id = ?", (sys.argv[2],))
    conn.commit()
    print("wrote")
except sqlite3.OperationalError as exc:
    print("locked" if "locked" in str(exc) else repr(exc))
"""


def _race_after_predecessor_read(monkeypatch, db: Path, outcome: dict) -> None:
    """Once the replace has read the endpoint's rows, another PROCESS tries to
    change the predecessor's tags. It must be locked out until the scan
    commits, or the scan would carry (or drop) data it never saw."""
    import subprocess
    import sys

    import cert_watch.database.cert_ops as cert_ops

    real = cert_ops._select_predecessors

    def racing(rows, fingerprint):
        result = real(rows, fingerprint)
        if rows and "result" not in outcome:
            done = subprocess.run(
                [sys.executable, "-c", _WRITE_FROM_ANOTHER_PROCESS, str(db), rows[0]["id"]],
                capture_output=True,
                text=True,
                timeout=60,
            )
            outcome["result"] = done.stdout.strip() or done.stderr
        return result

    monkeypatch.setattr(cert_ops, "_select_predecessors", racing)


@pytest.mark.parametrize("path", ["store_scanned", "replace_scanned"])
def test_replace_reads_and_writes_in_one_immediate_transaction(
    tmp_path, monkeypatch, self_signed_leaf, path
):
    from cert_watch.database import replace_scanned

    db = _db(tmp_path)
    old = _scan_first(db, self_signed_leaf)
    SqliteCertificateRepository(db).set_tags(old, "team-a")
    outcome: dict = {}
    _race_after_predecessor_read(monkeypatch, db, outcome)
    leaf = parse_certificate(_make_cert(_HOST, days_valid=90).der)
    if path == "store_scanned":
        new = seed_scanned(db, _HOST, 443, leaf)
    else:
        new, _, _ = replace_scanned(db, _HOST, 443, leaf, [], None)
    assert outcome["result"] == "locked", outcome
    assert SqliteCertificateRepository(db).get_tags(new) == "team-a"
