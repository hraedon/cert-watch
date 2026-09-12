"""Independent routing oracles and immutable-source boundaries for Plan 050.

These expectations are written from the routing contract, not obtained by
calling the production resolver a second time. All databases are synthetic.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import sqlite3
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlsplit

import pytest

from cert_watch.__main__ import main
from cert_watch.database import init_schema
from cert_watch.database.connection import close_connections
from cert_watch.routing_report import build_routing_report, render_routing_report

_STAMP = "2026-09-12T00:00:00+00:00"
_SECRET = "synthetic-password-hash-do-not-read-57d3"


def _seal(path: Path) -> None:
    """Prepare a standalone fixture before exercising the diagnostic."""
    close_connections()
    conn = sqlite3.connect(path)
    try:
        conn.execute("PRAGMA journal_mode=DELETE")
    finally:
        conn.close()
    assert not any(Path(f"{path}{suffix}").exists() for suffix in ("-wal", "-shm", "-journal"))


def _tree_bytes(directory: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(directory)): path.read_bytes()
        for path in directory.rglob("*") if path.is_file()
    }


@dataclass
class Estate:
    path: Path

    def edit(self, sql: str, values: tuple = ()) -> None:
        conn = sqlite3.connect(self.path)
        try:
            conn.execute(sql, values)
            conn.commit()
        finally:
            conn.close()


@pytest.fixture
def snapshot(tmp_path: Path) -> Path:
    path = tmp_path / "source" / "snapshot.sqlite3"
    path.parent.mkdir()
    init_schema(path)
    _seal(path)
    yield path
    close_connections()


@pytest.fixture
def estate(snapshot: Path) -> Estate:
    conn = sqlite3.connect(snapshot)
    try:
        for cert_id, hostname, tags, leaf in [
            ("multi", "multi.example.test", " strasse, APP,app ", 1),
            ("manual", "manual.example.test", "", 1),
            ("role", "role.example.test", "role-scope", 1),
            ("owned", "owned.example.test", "", 1),
            ("empty-group", "empty.example.test", "empty", 1),
            ("orphan", "orphan.example.test", "", 1),
            ("invalid-owner", "invalid.example.test", "", 1),
            ("upload", None, "", 1),
            ("chain", "chain.example.test", "strasse", 0),
        ]:
            conn.execute(
                "INSERT INTO certificates "
                "(id, subject, issuer, not_before, not_after, san_dns_names, "
                "fingerprint_sha256, raw_der, hostname, port, is_leaf, tags, "
                "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (cert_id, f"CN={cert_id}", "CN=fixture", _STAMP, "2027-09-12T00:00:00+00:00",
                 "[]", cert_id * 8, b"synthetic-der", hostname, 443 if hostname else None,
                 leaf, tags, _STAMP, _STAMP),
            )
            if hostname:
                owner = {"owned": "Team@example.test", "invalid-owner": "bad-address"}.get(
                    cert_id, ""
                )
                conn.execute(
                    "INSERT INTO hosts (id, hostname, port, tags, owner_email, added_at) "
                    "VALUES (?, ?, 443, ?, ?, ?)",
                    (cert_id, hostname, "PROD" if cert_id == "multi" else "", owner, _STAMP),
                )
        for group_id, name, recipients, tags in [
            ("unicode", "Unicode team", "Shared@example.test,unicode@example.test", "Straße"),
            ("host", "Host team", "shared@example.test,host@example.test", "prod"),
            ("manual-group", "Manual team", "manual@example.test", "never"),
            ("role-group", "Role team", "role@example.test", "unmatched"),
            ("empty", "Empty recipients", "", "empty"),
            ("unmatched", "Nobody matches", "nobody@example.test", "absent"),
        ]:
            conn.execute(
                "INSERT INTO alert_groups (id, name, recipients, match_tags, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (group_id, name, recipients, tags, _STAMP),
            )
        conn.executemany(
            "INSERT INTO alert_group_certs (group_id, cert_id) VALUES (?, ?)",
            [("unicode", "multi"), ("manual-group", "manual"), ("manual-group", "upload")],
        )
        for role_id, email, scope, group_id in [
            ("team-role", "team@example.test", "", None),
            ("scope-role", "", " ROLE-SCOPE ", "role-group"),
            ("overlap-role", "", "APP", "unicode"),
        ]:
            conn.execute(
                "INSERT INTO roles (id, name, email, scope_tag, alert_group_id, "
                "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (role_id, role_id, email, scope, group_id, _STAMP, _STAMP),
            )
        for user_id, email in [("member", "member@example.test"), ("same", "Team@example.test")]:
            conn.execute(
                "INSERT INTO users (id, username, email, password_hash, role_id, "
                "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (user_id, user_id, email, _SECRET, "team-role", _STAMP, _STAMP),
            )
        conn.execute(
            "INSERT INTO kv_store (key, value, updated_at) VALUES (?, ?, ?)",
            ("smtp_password", _SECRET, _STAMP),
        )
        conn.commit()
    finally:
        conn.close()
    _seal(snapshot)
    return Estate(snapshot)


def test_empty_current_snapshot_has_no_routes(snapshot: Path):
    report = build_routing_report(snapshot)
    assert report["format_version"] == 1
    assert report["schema_version"] == "0032"
    assert report["snapshot_sha256"] == hashlib.sha256(snapshot.read_bytes()).hexdigest()
    assert report["counts"] == {"leaf_certificates": 0, "orphans": 0, "multi_match": 0}
    assert report["certificates"] == []
    assert report["groups"] == []


def test_adversarial_estate_matches_independent_route_matrix(estate: Estate):
    report = build_routing_report(estate.path)
    rows = {row["cert_id"]: row for row in report["certificates"]}
    expected_groups = {
        "multi": {"unicode", "host"}, "manual": {"manual-group"},
        "role": {"role-group"}, "owned": set(), "empty-group": {"empty"},
        "orphan": set(), "invalid-owner": set(), "upload": {"manual-group"},
    }
    expected_recipients = {
        "multi": {"shared@example.test", "unicode@example.test", "host@example.test"},
        "manual": {"manual@example.test"}, "role": {"role@example.test"},
        "owned": {"team@example.test", "member@example.test"},
        "empty-group": set(), "orphan": set(), "invalid-owner": {"bad-address"},
        "upload": {"manual@example.test"},
    }
    assert set(rows) == set(expected_groups)  # Includes uploads; excludes chain records.
    for cert_id, row in rows.items():
        assert set(row["group_ids"]) == expected_groups[cert_id], cert_id
        assert len(row["group_ids"]) == len(expected_groups[cert_id]), cert_id
        assert {r.casefold() for r in row["recipients"]} == expected_recipients[cert_id], cert_id
        assert len(row["recipients"]) == len(expected_recipients[cert_id]), cert_id
        assert row["orphan"] is (cert_id in {"empty-group", "orphan"}), cert_id
        assert row["multi_match"] is (cert_id == "multi"), cert_id
        assert row["invalid_recipients"] == (["bad-address"] if cert_id == "invalid-owner" else [])
    assert rows["owned"]["recipients"] == ["Team@example.test", "member@example.test"]
    assert report["counts"] == {"leaf_certificates": 8, "orphans": 2, "multi_match": 1}
    groups = {row["group_id"]: row for row in report["groups"]}
    assert set(groups) == {"unicode", "host", "manual-group", "role-group", "empty", "unmatched"}
    expected_members = {
        "unicode": {"multi"}, "host": {"multi"}, "manual-group": {"manual", "upload"},
        "role-group": {"role"}, "empty": {"empty-group"}, "unmatched": set(),
    }
    for group_id, cert_ids in expected_members.items():
        assert set(groups[group_id]["cert_ids"]) == cert_ids
        assert groups[group_id]["matched_count"] == len(cert_ids)


def test_success_preserves_source_bytes_and_is_repeatable(estate: Estate):
    before = _tree_bytes(estate.path.parent)
    first = build_routing_report(estate.path)
    second = build_routing_report(estate.path)
    assert second == first
    assert _tree_bytes(estate.path.parent) == before
    assert first["snapshot_sha256"] == hashlib.sha256(before[estate.path.name]).hexdigest()


def test_source_queries_never_read_credentials(estate: Estate, monkeypatch):
    real_connect = sqlite3.connect
    forbidden_reads: list[tuple[str, str]] = []
    observed_source_connections = []

    def guarded_connect(database, *args, **kwargs):
        conn = real_connect(database, *args, **kwargs)
        uri = str(database)
        filename = unquote(urlsplit(uri).path) if uri.startswith("file:") else uri
        # Windows file URIs contain /C:/, while native paths contain C:/.
        if filename.startswith("/") and len(filename) > 2 and filename[2] == ":":
            filename = filename[1:]
        if Path(filename).resolve() == estate.path.resolve():
            observed_source_connections.append(uri)

            def authorize(action, table, column, _database, _trigger):
                forbidden = table in {"kv_store", "api_keys", "session_versions"} or (
                    table == "users" and column == "password_hash"
                ) or (table == "alert_groups" and column == "webhook_url")
                if action == sqlite3.SQLITE_READ and forbidden:
                    forbidden_reads.append((table, column))
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK

            conn.set_authorizer(authorize)
        return conn

    monkeypatch.setattr(sqlite3, "connect", guarded_connect)
    report = build_routing_report(estate.path)
    assert observed_source_connections, "Credential guard must observe the source connection"
    assert forbidden_reads == []
    assert _SECRET not in json.dumps(report)
    owned = next(row for row in report["certificates"] if row["cert_id"] == "owned")
    assert owned["recipients"] == ["Team@example.test", "member@example.test"]


def test_diagnostic_does_not_load_settings_migrate_evaluate_or_connect(estate: Estate, monkeypatch):
    import cert_watch.alerts as alerts
    import cert_watch.config as config
    import cert_watch.database as database
    import cert_watch.database.schema as schema
    import cert_watch.migrations.runner as migrations

    def forbidden(*_args, **_kwargs):
        pytest.fail("Diagnostic attempted initialization, evaluation, delivery, or live settings")

    for module, name in [
        (config.Settings, "from_env"), (database, "init_schema"), (schema, "init_schema"),
        (migrations, "run_pending_migrations"), (alerts, "evaluate_all_certs"),
        (alerts, "send_alert"), (alerts, "send_webhook"), (socket, "create_connection"),
        (socket.socket, "connect"),
    ]:
        monkeypatch.setattr(module, name, forbidden)
    assert build_routing_report(estate.path)["counts"]["leaf_certificates"] == 8


@pytest.mark.parametrize("suffix", ["-wal", "-shm", "-journal"])
def test_companion_file_refusal_preserves_source(snapshot: Path, suffix: str):
    Path(f"{snapshot}{suffix}").write_bytes(b"do not alter companion")
    before = _tree_bytes(snapshot.parent)
    with pytest.raises(ValueError):
        build_routing_report(snapshot)
    assert _tree_bytes(snapshot.parent) == before


def test_committed_wal_route_is_rejected_instead_of_omitted(snapshot: Path):
    writer = sqlite3.connect(snapshot)
    try:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute(
            "INSERT INTO alert_groups (id, name, recipients, match_tags, created_at) "
            "VALUES ('wal-only', 'Committed in WAL', 'wal@example.test', 'prod', ?)", (_STAMP,),
        )
        writer.commit()
        assert Path(f"{snapshot}-wal").stat().st_size > 32
        before = _tree_bytes(snapshot.parent)
        with pytest.raises(ValueError):
            build_routing_report(snapshot)
        assert _tree_bytes(snapshot.parent) == before
    finally:
        writer.close()


def test_missing_snapshot_cli_fails_without_creating_files(tmp_path: Path, capsys):
    path = tmp_path / "does-not-exist.sqlite3"
    with pytest.raises(SystemExit) as caught:
        main(["routing-report", str(path)])
    assert caught.value.code == 2
    captured = capsys.readouterr()
    assert captured.err.strip()
    assert captured.out == ""
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("payload", [b"not a database", b""])
def test_malformed_snapshot_is_refused_unchanged(tmp_path: Path, payload: bytes):
    path = tmp_path / "malformed.sqlite3"
    path.write_bytes(payload)
    before = _tree_bytes(tmp_path)
    with pytest.raises(ValueError):
        build_routing_report(path)
    assert _tree_bytes(tmp_path) == before


@pytest.mark.parametrize("sql", [
    "DELETE FROM schema_version WHERE id = '0019'",
    "INSERT INTO schema_version VALUES ('9999', 'Future migration', '2026-09-12')",
    "DROP TABLE schema_version",
])
def test_incomplete_future_or_missing_migrations_are_not_repaired(snapshot: Path, sql: str):
    Estate(snapshot).edit(sql)
    before = _tree_bytes(snapshot.parent)
    with pytest.raises(ValueError):
        build_routing_report(snapshot)
    assert _tree_bytes(snapshot.parent) == before


def test_missing_routing_column_is_not_defaulted_or_repaired(snapshot: Path):
    Estate(snapshot).edit("ALTER TABLE certificates DROP COLUMN tags")
    before = _tree_bytes(snapshot.parent)
    with pytest.raises(ValueError):
        build_routing_report(snapshot)
    assert _tree_bytes(snapshot.parent) == before


@pytest.mark.parametrize("replacement", ["view", "generated-column", "virtual-table"])
def test_credential_expression_cannot_impersonate_a_routing_column(
    estate: Estate, replacement, monkeypatch,
):
    import cert_watch.alerts as alerts

    resolver_calls = []
    original_resolver = alerts._resolve_group_config

    def record_resolution(*args, **kwargs):
        resolver_calls.append(True)
        return original_resolver(*args, **kwargs)

    monkeypatch.setattr(alerts, "_resolve_group_config", record_resolution)
    if replacement == "view":
        estate.edit("ALTER TABLE users RENAME TO original_users")
        estate.edit(
            "CREATE VIEW users AS SELECT id, username, password_hash AS email, role_id "
            "FROM original_users"
        )
    elif replacement == "generated-column":
        estate.edit("ALTER TABLE users RENAME COLUMN email TO original_email")
        estate.edit("ALTER TABLE users ADD COLUMN email TEXT AS (password_hash) VIRTUAL")
    else:
        estate.edit("ALTER TABLE users RENAME TO original_users")
        estate.edit(
            "CREATE VIRTUAL TABLE users USING fts5("
            "id, username, email, role_id, content='original_users')"
        )
    before = _tree_bytes(estate.path.parent)
    with pytest.raises(ValueError):
        build_routing_report(estate.path)
    assert resolver_calls == [], "Forged source shapes must fail before routing evaluation"
    assert _tree_bytes(estate.path.parent) == before


def test_malformed_owner_value_is_refused_as_a_snapshot_error(estate: Estate, capsys):
    # SQLite's TEXT affinity still permits BLOB storage. The migration ledger
    # and ordinary-table shape remain valid, but the route is not a text value.
    estate.edit("UPDATE hosts SET owner_email = ? WHERE id = 'owned'", (b"bad-owner",))
    before = _tree_bytes(estate.path.parent)
    with pytest.raises(ValueError):
        build_routing_report(estate.path)
    with pytest.raises(SystemExit) as caught:
        main(["routing-report", str(estate.path), "--format", "json"])
    assert caught.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert len(captured.err.splitlines()) == 1
    assert "Traceback" not in captured.err
    assert "bad-owner" not in captured.err
    assert _tree_bytes(estate.path.parent) == before


def test_null_recipient_in_malformed_ordinary_table_is_refused(estate: Estate):
    estate.edit("ALTER TABLE alert_groups RENAME TO original_alert_groups")
    estate.edit("CREATE TABLE alert_groups AS SELECT * FROM original_alert_groups")
    estate.edit("UPDATE alert_groups SET recipients = NULL WHERE id = 'unicode'")
    before = _tree_bytes(estate.path.parent)
    with pytest.raises(ValueError):
        build_routing_report(estate.path)
    assert _tree_bytes(estate.path.parent) == before


def test_uri_sensitive_filename_is_read_as_the_actual_file(snapshot: Path):
    other_paths = set(snapshot.parent.iterdir()) - {snapshot}
    renamed = snapshot.with_name("estate #1 %20 snapshot.sqlite3")
    snapshot.rename(renamed)
    report = build_routing_report(renamed)
    assert report["snapshot_sha256"] == hashlib.sha256(renamed.read_bytes()).hexdigest()
    assert set(renamed.parent.iterdir()) == other_paths | {renamed}


@pytest.mark.parametrize("mutation", ["identity", "bytes"])
def test_source_change_during_inspection_invalidates_report(estate: Estate, monkeypatch, mutation):
    import cert_watch.alerts as alerts

    original_resolver = alerts.resolve_cert_recipients
    changed = False

    def change_source_then_resolve(*args, **kwargs):
        nonlocal changed
        if not changed:
            changed = True
            state = estate.path.stat()
            if mutation == "identity":
                os.utime(estate.path, ns=(state.st_atime_ns, state.st_mtime_ns + 1_000_000_000))
            else:
                # Simulate an external writer after extraction, preserving file
                # size and mtime so only content binding detects this change.
                contents = bytearray(estate.path.read_bytes())
                contents[-1] ^= 1
                estate.path.write_bytes(contents)
                os.utime(estate.path, ns=(state.st_atime_ns, state.st_mtime_ns))
            assert estate.path.stat().st_size == state.st_size
        return original_resolver(*args, **kwargs)

    monkeypatch.setattr(alerts, "resolve_cert_recipients", change_source_then_resolve)
    with pytest.raises(ValueError):
        build_routing_report(estate.path)
    assert changed, "External-change simulation must run during actual resolver execution"


@pytest.mark.parametrize("output_format", ["json", "text"])
def test_cli_formats_report_without_source_writes(estate: Estate, capsys, output_format: str):
    before = _tree_bytes(estate.path.parent)
    main(["routing-report", str(estate.path), "--format", output_format])
    captured = capsys.readouterr()
    assert captured.err == ""
    if output_format == "json":
        report = json.loads(captured.out)
        assert report["counts"] == {"leaf_certificates": 8, "orphans": 2, "multi_match": 1}
    else:
        assert "multi.example.test" in captured.out
        assert "orphan.example.test" in captured.out
        assert "Nobody matches" in captured.out
    assert _tree_bytes(estate.path.parent) == before


def test_text_discloses_raw_routing_and_unverified_delivery(estate: Estate, capsys):
    report = build_routing_report(estate.path)
    rendered = render_routing_report(report)
    lowered = rendered.casefold()
    assert "smtp" in lowered
    assert "webhook" in lowered
    assert "global" in lowered
    assert "deliver" in lowered
    assert "invalid" in lowered
    assert "bad-address" in rendered
    main(["routing-report", str(estate.path)])
    assert capsys.readouterr().out.rstrip() == rendered.rstrip()


def test_failure_cleans_scratch_and_does_not_change_source(estate: Estate, monkeypatch):
    import cert_watch.alerts as alerts
    import cert_watch.routing_report as routing_report

    real_temporary_directory = tempfile.TemporaryDirectory
    scratch_paths: list[Path] = []

    def record_temporary_directory(*args, **kwargs):
        directory = real_temporary_directory(*args, **kwargs)
        scratch_paths.append(Path(directory.name))
        return directory

    def fail_resolver(*_args, **_kwargs):
        raise ValueError("injected resolver failure")

    monkeypatch.setattr(routing_report, "TemporaryDirectory", record_temporary_directory)
    monkeypatch.setattr(alerts, "resolve_cert_recipients", fail_resolver)
    before = _tree_bytes(estate.path.parent)
    with pytest.raises(ValueError):
        build_routing_report(estate.path)
    assert scratch_paths, "The cleanup guard must observe disposable scratch storage"
    assert all(not path.exists() for path in scratch_paths)
    assert _tree_bytes(estate.path.parent) == before


def test_report_output_is_ascii_only_so_a_legacy_console_cannot_fail() -> None:
    """Both output paths must survive a non-UTF-8 console (Windows default cp1252).

    The suite cannot catch this through ``capsys``, which captures as UTF-8, so
    assert the property directly: rendered text and JSON are pure ASCII. This
    also escapes Unicode bidi/format characters, which is what makes
    ``render_routing_report``'s terminal-safety promise true for DB-sourced text.
    """
    hostile = "CN=東京.example ‮EVIL"
    report = {
        "snapshot_sha256": "abc",
        "schema_version": 31,
        "counts": {"leaf_certificates": 1, "orphans": 0, "multi_match": 0},
        "groups": [
            {"name": hostile, "group_id": "g1", "matched_count": 1, "cert_ids": [1]}
        ],
        "certificates": [
            {
                "cert_id": 1,
                "hostname": hostile,
                "port": 443,
                "subject": hostile,
                "recipients": ["é@example.com"],
                "orphan": False,
                "multi_match": False,
                "invalid_recipients": [hostile],
                "group_ids": ["g1"],
            }
        ],
        "scope": "scope text",
    }

    rendered = render_routing_report(report)
    rendered.encode("ascii")  # raises UnicodeEncodeError on regression
    assert "‮" not in rendered, "bidi controls must be escaped, not passed through"
    assert "\\u202e" in rendered

    as_json = json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2)
    as_json.encode("cp1252")  # the Windows console default
