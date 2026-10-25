"""A failed connection setup must release the handle before propagating errors."""

from __future__ import annotations

import sqlite3
from contextlib import suppress

import pytest

from cert_watch import status_rule
from cert_watch.database import connection


@pytest.fixture
def opened_connections(monkeypatch):
    connection.close_connections()
    original_connect = sqlite3.connect
    opened = []

    def record(*args, **kwargs):
        conn = original_connect(*args, **kwargs)
        opened.append(conn)
        return conn

    monkeypatch.setattr(sqlite3, "connect", record)
    try:
        yield opened
    finally:
        connection.close_connections()
        for conn in opened:
            with suppress(sqlite3.Error):
                conn.close()


def assert_closed(conn):
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        conn.execute("SELECT 1")


@pytest.mark.parametrize("pragma", ["journal_mode", "busy_timeout", "foreign_keys"])
def test_setup_sql_error_closes_uncached_handle_and_allows_retry(
    tmp_path, monkeypatch, opened_connections, pragma
):
    record = sqlite3.connect
    should_fail = True
    attempted = []

    def connect(*args, **kwargs):
        conn = record(*args, **kwargs)
        if should_fail:

            def authorize(action, name, *args):
                if action == sqlite3.SQLITE_PRAGMA:
                    attempted.append(name)
                    if name == pragma:
                        return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK

            conn.set_authorizer(authorize)
        return conn

    monkeypatch.setattr(sqlite3, "connect", connect)
    path = tmp_path / "setup.sqlite3"
    with pytest.raises(sqlite3.DatabaseError, match="not authorized"):
        connection._connect(path)
    assert pragma in attempted
    assert len(opened_connections) == 1
    assert str(path) not in connection._thread_cache().connections
    failed = opened_connections[0]
    assert_closed(failed)

    should_fail = False
    healthy = connection._connect(path)
    assert healthy is not failed
    assert len(opened_connections) == 2
    assert connection._thread_cache().connections[str(path)] is healthy
    assert healthy.execute("SELECT cw_casefold('Straße')").fetchone()[0] == "strasse"
    assert healthy.execute("PRAGMA foreign_keys").fetchone()[0] == 1


@pytest.mark.parametrize("error", [RuntimeError("synthetic setup failure"), KeyboardInterrupt()])
def test_function_setup_failure_closes_handle_and_preserves_error(
    tmp_path, monkeypatch, opened_connections, error
):
    def fail(conn):
        raise error

    monkeypatch.setattr(status_rule, "register_sql_functions", fail)
    path = tmp_path / "setup.sqlite3"
    with pytest.raises(type(error)) as raised:
        connection._connect(path)
    assert raised.value is error
    assert str(path) not in connection._thread_cache().connections
    assert_closed(opened_connections[0])


def test_cleanup_sql_error_does_not_replace_setup_error(tmp_path, monkeypatch, opened_connections):
    class CloseFails(sqlite3.Connection):
        def close(self):
            super().close()
            raise sqlite3.OperationalError("synthetic close failure")

    record = sqlite3.connect

    def connect(*args, **kwargs):
        return record(*args, factory=CloseFails, **kwargs)

    error = RuntimeError("synthetic setup failure")

    def fail(conn):
        raise error

    monkeypatch.setattr(sqlite3, "connect", connect)
    monkeypatch.setattr(status_rule, "register_sql_functions", fail)
    with pytest.raises(RuntimeError) as raised:
        connection._connect(tmp_path / "setup.sqlite3")
    assert raised.value is error
    assert_closed(opened_connections[0])


def test_successful_setup_keeps_connection_cached(tmp_path, opened_connections):
    path = tmp_path / "healthy.sqlite3"
    conn = connection._connect(path)
    assert connection._connect(path) is conn
    assert len(opened_connections) == 1
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 15000
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert conn.execute("SELECT cw_casefold('Synthetic')").fetchone()[0] == "synthetic"
