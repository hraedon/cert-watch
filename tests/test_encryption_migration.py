from __future__ import annotations

from cryptography.fernet import Fernet

from cert_watch.database import init_schema, kv_get, kv_set
from cert_watch.database.connection import _connect
from cert_watch.database.encryption import (
    _ENCRYPTED_PREFIX,
    _ENCRYPTED_PREFIX_V2,
    check_encrypted_values,
    derive_encryption_key,
    derive_encryption_key_legacy,
    fernet_decrypt,
    fernet_encrypt,
    re_encrypt_kv_store,
)


def _insert_v1_secret(db, key, plaintext, legacy_key):
    token = Fernet(legacy_key.encode()).encrypt(plaintext.encode()).decode()
    kv_set(db, key, _ENCRYPTED_PREFIX + token)


def test_v1_to_v2_migration_round_trip(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    signing_key = "production-signing-key-2025"
    legacy_key = derive_encryption_key_legacy(signing_key)
    new_key = derive_encryption_key(signing_key)

    secrets = {
        "smtp_password": "hunter2",
        "ldap_bind_password": "secret123",
        "webhook_headers": '{"Authorization": "Bearer tok"}',
        "oauth_client_secret": "oauth-secret-val",
        "pagerduty_routing_key": "rk-abc123",
    }
    for k, v in secrets.items():
        _insert_v1_secret(db, k, v, legacy_key)

    count = re_encrypt_kv_store(db, legacy_key, new_key)
    assert count == len(secrets)

    for k, expected_plain in secrets.items():
        stored = kv_get(db, k)
        assert stored.startswith(_ENCRYPTED_PREFIX_V2), f"{k} not migrated to v2"
        assert not stored.startswith(_ENCRYPTED_PREFIX), f"{k} still v1"
        decrypted = fernet_decrypt(stored, new_key)
        assert decrypted == expected_plain, f"{k} plaintext mismatch"


def test_migration_preserves_undecryptable_values(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    signing_key_a = "key-a-signing"
    signing_key_b = "key-b-signing"
    legacy_key_a = derive_encryption_key_legacy(signing_key_a)
    legacy_key_b = derive_encryption_key_legacy(signing_key_b)
    new_key = derive_encryption_key(signing_key_a)

    _insert_v1_secret(db, "smtp_password", "hunter2", legacy_key_a)
    _insert_v1_secret(db, "ldap_bind_password", "secret123", legacy_key_a)
    _insert_v1_secret(db, "oauth_client_secret", "oauth-val", legacy_key_b)
    _insert_v1_secret(db, "pagerduty_routing_key", "rk-xyz", legacy_key_b)

    count = re_encrypt_kv_store(db, legacy_key_a, new_key)
    assert count == 2

    smtp_stored = kv_get(db, "smtp_password")
    assert smtp_stored.startswith(_ENCRYPTED_PREFIX_V2)
    assert fernet_decrypt(smtp_stored, new_key) == "hunter2"

    ldap_stored = kv_get(db, "ldap_bind_password")
    assert ldap_stored.startswith(_ENCRYPTED_PREFIX_V2)
    assert fernet_decrypt(ldap_stored, new_key) == "secret123"

    oauth_stored = kv_get(db, "oauth_client_secret")
    assert oauth_stored.startswith(_ENCRYPTED_PREFIX)
    assert fernet_decrypt(oauth_stored, legacy_key_b) == "oauth-val"
    assert fernet_decrypt(oauth_stored, new_key) is None

    pd_stored = kv_get(db, "pagerduty_routing_key")
    assert pd_stored.startswith(_ENCRYPTED_PREFIX)
    assert fernet_decrypt(pd_stored, legacy_key_b) == "rk-xyz"


def test_startup_auto_migration_path(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    signing_key = "startup-migration-test-key"
    legacy_key = derive_encryption_key_legacy(signing_key)
    new_key = derive_encryption_key(signing_key)

    secrets = {
        "smtp_password": "hunter2",
        "ldap_bind_password": "secret123",
        "webhook_url": "https://hooks.example.com/abc",
    }
    for k, v in secrets.items():
        _insert_v1_secret(db, k, v, legacy_key)

    undecryptable = check_encrypted_values(db, new_key)
    assert len(undecryptable) == len(secrets)
    for k in secrets:
        assert k in undecryptable

    migrated = re_encrypt_kv_store(db, legacy_key, new_key)
    assert migrated == len(secrets)

    still_undecryptable = check_encrypted_values(db, new_key)
    assert still_undecryptable == []

    for k, expected_plain in secrets.items():
        stored = kv_get(db, k)
        assert stored.startswith(_ENCRYPTED_PREFIX_V2)
        assert fernet_decrypt(stored, new_key) == expected_plain


def test_migration_with_mixed_v1_v2(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    signing_key = "mixed-migration-key"
    legacy_key = derive_encryption_key_legacy(signing_key)
    new_key = derive_encryption_key(signing_key)

    v1_secrets = {
        "smtp_password": "hunter2",
        "ldap_bind_password": "secret123",
    }
    v2_secrets = {
        "webhook_headers": '{"Authorization": "Bearer tok"}',
        "pagerduty_routing_key": "rk-mixed",
    }
    for k, v in v1_secrets.items():
        _insert_v1_secret(db, k, v, legacy_key)
    for k, v in v2_secrets.items():
        kv_set(db, k, fernet_encrypt(v, legacy_key))

    original_v2_values = {k: kv_get(db, k) for k in v2_secrets}

    count = re_encrypt_kv_store(db, legacy_key, new_key)
    assert count == len(v1_secrets) + len(v2_secrets)

    for k, expected_plain in v1_secrets.items():
        stored = kv_get(db, k)
        assert stored.startswith(_ENCRYPTED_PREFIX_V2), f"{k} should be v2"
        assert fernet_decrypt(stored, new_key) == expected_plain

    for k, expected_plain in v2_secrets.items():
        stored = kv_get(db, k)
        assert stored.startswith(_ENCRYPTED_PREFIX_V2), f"{k} should be v2"
        assert fernet_decrypt(stored, new_key) == expected_plain
        assert fernet_decrypt(stored, legacy_key) is None, (
            f"{k} should no longer decrypt with old key"
        )
        assert stored != original_v2_values[k], f"{k} ciphertext should have changed"


def test_migration_does_not_silently_empty_values(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    signing_key = "correct-signing-key"
    wrong_signing_key = "wrong-signing-key"
    legacy_key = derive_encryption_key_legacy(signing_key)
    wrong_legacy_key = derive_encryption_key_legacy(wrong_signing_key)
    new_key = derive_encryption_key(signing_key)

    secrets = {
        "smtp_password": "hunter2",
        "ldap_bind_password": "secret123",
        "webhook_headers": '{"Authorization": "Bearer tok"}',
    }
    original_ciphertexts = {}
    for k, v in secrets.items():
        _insert_v1_secret(db, k, v, legacy_key)
        original_ciphertexts[k] = kv_get(db, k)

    count = re_encrypt_kv_store(db, wrong_legacy_key, new_key)
    assert count == 0

    with _connect(db) as conn:
        rows = conn.execute("SELECT key, value FROM kv_store").fetchall()

    for row in rows:
        k = row["key"]
        val = row["value"]
        assert val is not None, f"{k} became None"
        assert val == original_ciphertexts[k], f"{k} was modified despite wrong key"
        assert val.startswith(_ENCRYPTED_PREFIX), f"{k} should still be v1"
        assert fernet_decrypt(val, legacy_key) == secrets[k], (
            f"{k} should still decrypt with correct key"
        )
