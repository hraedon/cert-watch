"""Deterministic coverage of the database-locked paths in scan.py.

These branches used to run only when the full suite happened to produce real
SQLite contention, so scan.py's measured coverage moved between runs and its
per-module floor failed intermittently. Driving them directly makes both the
behaviour and the coverage number stable.
"""

from __future__ import annotations

import asyncio
import sqlite3

import pytest

from cert_watch import scan
from cert_watch.certificate_model import parse_certificate
from cert_watch.scan import ScannedEntry, store_scanned, store_scanned_async


def _entry(self_signed_leaf) -> ScannedEntry:
    return ScannedEntry(
        host="locked.example.test", port=443,
        leaf=parse_certificate(self_signed_leaf.der), chain=[],
    )


def test_store_scanned_reraises_lock_errors_after_rollback(
    tmp_path, self_signed_leaf, monkeypatch
) -> None:
    def locked(*_args, **_kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(scan, "_stage_history", locked)

    with pytest.raises(sqlite3.OperationalError, match="locked"):
        store_scanned(_entry(self_signed_leaf), tmp_path / "cw.sqlite3")


def test_store_scanned_async_retries_a_locked_database(
    tmp_path, self_signed_leaf, monkeypatch
) -> None:
    calls: list[int] = []

    def flaky_store(*_args, **_kwargs):
        calls.append(1)
        if len(calls) < 3:
            raise sqlite3.OperationalError("database is locked")
        return "leaf-id"

    monkeypatch.setattr(scan, "store_scanned", flaky_store)
    monkeypatch.setattr("time.sleep", lambda _seconds: None)

    leaf_id = asyncio.run(
        store_scanned_async(_entry(self_signed_leaf), tmp_path / "cw.sqlite3")
    )

    assert leaf_id == "leaf-id"
    assert len(calls) == 3


def test_store_scanned_async_gives_up_after_three_locked_attempts(
    tmp_path, self_signed_leaf, monkeypatch
) -> None:
    def always_locked(*_args, **_kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(scan, "store_scanned", always_locked)
    monkeypatch.setattr("time.sleep", lambda _seconds: None)

    with pytest.raises(sqlite3.OperationalError, match="locked"):
        asyncio.run(
            store_scanned_async(_entry(self_signed_leaf), tmp_path / "cw.sqlite3")
        )


def test_store_scanned_async_does_not_retry_other_operational_errors(
    tmp_path, self_signed_leaf, monkeypatch
) -> None:
    calls: list[int] = []

    def broken(*_args, **_kwargs):
        calls.append(1)
        raise sqlite3.OperationalError("no such table: certificates")

    monkeypatch.setattr(scan, "store_scanned", broken)
    monkeypatch.setattr("time.sleep", lambda _seconds: None)

    with pytest.raises(sqlite3.OperationalError, match="no such table"):
        asyncio.run(
            store_scanned_async(_entry(self_signed_leaf), tmp_path / "cw.sqlite3")
        )
    assert len(calls) == 1
