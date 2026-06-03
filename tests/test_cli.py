"""Tests for the cert-watch CLI subcommands (backup, hash-password, re-encrypt)."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from unittest.mock import patch

from cert_watch.__main__ import main
from cert_watch.database import init_schema
from cert_watch.database.queries import derive_encryption_key, fernet_encrypt, kv_set


def _make_db(tmp_path: Path) -> Path:
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    return db


class TestBackupSubcommand:
    def test_backup_creates_file(self, tmp_path, monkeypatch):
        _make_db(tmp_path)
        monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
        backup_path = tmp_path / "backup.sqlite3"
        main(["backup", str(backup_path)])
        assert backup_path.exists()
        assert backup_path.stat().st_size > 0

    def test_backup_is_valid_sqlite(self, tmp_path, monkeypatch):
        _make_db(tmp_path)
        monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
        backup_path = tmp_path / "backup.sqlite3"
        main(["backup", str(backup_path)])
        with sqlite3.connect(str(backup_path)) as conn:
            tables = {row[0] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()}
        assert "certificates" in tables
        assert "schema_version" in tables

    def test_backup_preserves_data(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path)
        monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
        kv_set(db, "test_key", "test_val")
        backup_path = tmp_path / "backup.sqlite3"
        main(["backup", str(backup_path)])
        with sqlite3.connect(str(backup_path)) as conn:
            row = conn.execute(
                "SELECT value FROM kv_store WHERE key = ?", ("test_key",)
            ).fetchone()
        assert row is not None
        assert row[0] == "test_val"

    def test_backup_creates_parent_dirs(self, tmp_path, monkeypatch):
        _make_db(tmp_path)
        monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
        backup_path = tmp_path / "subdir" / "deep" / "backup.sqlite3"
        main(["backup", str(backup_path)])
        assert backup_path.exists()


class TestHashPasswordSubcommand:
    def test_hash_password_generates_scrypt_hash(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
        with patch("getpass.getpass") as mock_getpass:
            mock_getpass.side_effect = ["testpassword", "testpassword"]
            with patch("builtins.print") as mock_print:
                main(["hash-password"])
        mock_print.assert_called_once()
        output = mock_print.call_args[0][0]
        assert output.startswith("scrypt$")
        from cert_watch.auth.local_admin import verify_scrypt_hash
        assert verify_scrypt_hash("testpassword", output)

    def test_hash_password_mismatch_exits(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
        with patch("getpass.getpass") as mock_getpass:
            mock_getpass.side_effect = ["password1", "password2"]
            try:
                main(["hash-password"])
                raise AssertionError("Should have raised SystemExit")
            except SystemExit as e:
                assert e.code == 1

    def test_hash_password_empty_exits(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
        with patch("getpass.getpass") as mock_getpass:
            mock_getpass.side_effect = ["", ""]
            try:
                main(["hash-password"])
                raise AssertionError("Should have raised SystemExit")
            except SystemExit as e:
                assert e.code == 1


class TestReEncryptSubcommand:
    def test_re_encrypt_rotates_kv_store_values(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path)
        monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
        old_key_raw = "old-signing-key-for-test"
        new_key_raw = "new-signing-key-for-test"
        old_key = derive_encryption_key(old_key_raw)
        encrypted = fernet_encrypt("secret-value", old_key)
        kv_set(db, "smtp_password", encrypted)
        monkeypatch.setenv("CERT_WATCH_AUTH_SECRET", new_key_raw)
        main(["re-encrypt", old_key_raw])
        from cert_watch.database.queries import fernet_decrypt
        new_key = derive_encryption_key(new_key_raw)
        with sqlite3.connect(str(db)) as conn:
            row = conn.execute(
                "SELECT value FROM kv_store WHERE key = ?", ("smtp_password",)
            ).fetchone()
        assert row is not None
        decrypted = fernet_decrypt(row[0], new_key)
        assert decrypted == "secret-value"

    def test_re_encrypt_skips_plaintext_values(self, tmp_path, monkeypatch):
        db = _make_db(tmp_path)
        monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
        kv_set(db, "plain_key", "plain_value")
        monkeypatch.setenv("CERT_WATCH_AUTH_SECRET", "new-key")
        main(["re-encrypt", "old-key"])
        with sqlite3.connect(str(db)) as conn:
            row = conn.execute(
                "SELECT value FROM kv_store WHERE key = ?", ("plain_key",)
            ).fetchone()
        assert row[0] == "plain_value"

    def test_re_encrypt_reports_count(self, tmp_path, monkeypatch, capsys):
        db = _make_db(tmp_path)
        monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
        old_key_raw = "old-key"
        old_key = derive_encryption_key(old_key_raw)
        encrypted = fernet_encrypt("val1", old_key)
        kv_set(db, "k1", encrypted)
        monkeypatch.setenv("CERT_WATCH_AUTH_SECRET", "new-key")
        main(["re-encrypt", old_key_raw])
        captured = capsys.readouterr()
        assert "Re-encrypted 1 kv_store value(s)." in captured.out


class TestDefaultCommand:
    def test_help_exits_cleanly(self):
        try:
            main(["--help"])
            raise AssertionError("Should have raised SystemExit(0)")
        except SystemExit as e:
            assert e.code == 0

    def test_backup_subcommand_help(self):
        try:
            main(["backup", "--help"])
            raise AssertionError("Should have raised SystemExit(0)")
        except SystemExit as e:
            assert e.code == 0
