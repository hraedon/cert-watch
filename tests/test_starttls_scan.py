"""Tests for STARTTLS scanning (host.starttls_mode).

Covers: the openssl ``-starttls`` argv wiring + allowlist guard, routing of
STARTTLS scans through openssl even on Python 3.13+, the no-wrapped-fallback
error path, the hosts.starttls_mode schema/round-trip, and route validation.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from cert_watch.database import SqliteHostRepository, init_schema
from cert_watch.scan import ScanError, scan_host
from cert_watch.scan_conn import STARTTLS_MODES, _scan_via_openssl


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    db = tmp_path / "starttls.sqlite3"
    init_schema(db)
    return db


def _no_dns(monkeypatch):
    monkeypatch.setattr(
        "cert_watch.scan_conn._resolve_host",
        lambda *a, **kw: (2, ("93.184.216.34", 443)),
    )


# ---------- openssl argv wiring ----------


def test_starttls_mode_adds_openssl_flag(monkeypatch):
    _no_dns(monkeypatch)
    with patch("cert_watch.scan_conn._run_openssl") as mock_run:
        mock_run.return_value = (b"", b"", 0)
        _scan_via_openssl("mail.example.com", 587, timeout=1, starttls_mode="smtp")
    argv = mock_run.call_args[0][0]
    assert "-starttls" in argv
    assert argv[argv.index("-starttls") + 1] == "smtp"


def test_no_starttls_flag_when_mode_empty(monkeypatch):
    _no_dns(monkeypatch)
    with patch("cert_watch.scan_conn._run_openssl") as mock_run:
        mock_run.return_value = (b"", b"", 0)
        _scan_via_openssl("example.com", 443, timeout=1)
    assert "-starttls" not in mock_run.call_args[0][0]


def test_unknown_starttls_mode_not_forwarded(monkeypatch):
    """A non-allowlisted mode must never reach the openssl argv (injection guard)."""
    _no_dns(monkeypatch)
    with patch("cert_watch.scan_conn._run_openssl") as mock_run:
        mock_run.return_value = (b"", b"", 0)
        _scan_via_openssl(
            "h.example.com", 443, timeout=1, starttls_mode="smtp; rm -rf /"
        )
    assert "-starttls" not in mock_run.call_args[0][0]


def test_starttls_mode_normalised_case(monkeypatch):
    _no_dns(monkeypatch)
    with patch("cert_watch.scan_conn._run_openssl") as mock_run:
        mock_run.return_value = (b"", b"", 0)
        _scan_via_openssl("h.example.com", 636, timeout=1, starttls_mode="LDAP")
    argv = mock_run.call_args[0][0]
    assert argv[argv.index("-starttls") + 1] == "ldap"


# ---------- routing: STARTTLS always uses openssl, even on 3.13+ ----------


def test_starttls_scan_routes_through_openssl(monkeypatch):
    """With starttls_mode set, the native ssl path must not be used at all."""
    _no_dns(monkeypatch)

    def _boom(*a, **kw):
        raise AssertionError("native _open_tls_connection must not run for STARTTLS")

    monkeypatch.setattr("cert_watch.scan._open_tls_connection", _boom)
    monkeypatch.setattr(
        "cert_watch.scan._scan_via_openssl",
        lambda *a, **kw: ([], ""),  # openssl yields nothing
    )
    result = scan_host(
        "mail.example.com", 587, retries=1, starttls_mode="smtp", pinned_ip="93.184.216.34"
    )
    # Yielded nothing → ScanError, but crucially the native path never ran.
    assert isinstance(result, ScanError)


def test_starttls_failure_returns_error_not_wrapped_fallback(monkeypatch):
    """A STARTTLS scan that yields no chain returns a clear error rather than
    silently falling back to a wrapped-TLS handshake on a cleartext port."""
    _no_dns(monkeypatch)
    monkeypatch.setattr("cert_watch.scan._scan_via_openssl", lambda *a, **kw: ([], ""))
    monkeypatch.setattr(
        "cert_watch.scan._open_tls_connection",
        lambda *a, **kw: (_ for _ in ()).throw(
            AssertionError("must not attempt wrapped TLS for STARTTLS scan")
        ),
    )
    result = scan_host(
        "mail.example.com", 587, retries=1, starttls_mode="smtp", pinned_ip="93.184.216.34"
    )
    assert isinstance(result, ScanError)
    assert "starttls" in result.error_message.lower()


# ---------- schema + repository round-trip ----------


def test_hosts_table_has_starttls_column(db_path: Path):
    from cert_watch.database import _connect

    with _connect(db_path) as conn:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(hosts)")}
    assert "starttls_mode" in cols


def test_host_repo_round_trips_starttls_mode(db_path: Path):
    repo = SqliteHostRepository(db_path)
    repo.add("mail.example.com", 587, starttls_mode="smtp")
    repo.add("web.example.com", 443)  # default: implicit TLS
    by_host = {h.hostname: h.starttls_mode for h in repo.list_all()}
    assert by_host["mail.example.com"] == "smtp"
    assert by_host["web.example.com"] == ""


def test_init_schema_idempotent_with_starttls(db_path: Path):
    # Second init must not error on the already-present column.
    init_schema(db_path)
    from cert_watch.database import _connect

    with _connect(db_path) as conn:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(hosts)")}
    assert "starttls_mode" in cols


def test_supported_modes_cover_common_protocols():
    for proto in ("smtp", "imap", "pop3", "ldap", "postgres"):
        assert proto in STARTTLS_MODES
