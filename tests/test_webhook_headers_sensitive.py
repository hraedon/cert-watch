"""webhook_headers is a SENSITIVE_SETTING_KEY: encrypted at rest, masked in the
UI, and decrypted on read *before* JSON parsing.

The load path (``config/kv_loader._merge_kv_settings``) used to do
``json.loads(raw)`` directly. Once the key joined ``SENSITIVE_SETTING_KEYS``,
that path would feed ``enc:v1:<ciphertext>`` to ``json.loads`` — which raises,
falls back to None, and silently drops the configured headers. These tests pin
the decrypt-then-parse invariant, the plaintext migration path (values written
before the key became sensitive), and the route-level encrypt-on-write.
"""
from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from cert_watch.config import SENSITIVE_SETTING_KEYS, Settings
from cert_watch.database import (
    derive_encryption_key,
    fernet_encrypt,
    init_schema,
    kv_get,
    kv_set,
)

_SIGNING_KEY = "test-auth-secret-for-tests"


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "cw.sqlite3"
    init_schema(path)
    return path


def _clear_webhook_env(monkeypatch):
    monkeypatch.delenv("ALERT_WEBHOOK_HEADERS", raising=False)


def test_webhook_headers_classified_sensitive():
    """Guard: the key must remain in the sensitive set."""
    assert "webhook_headers" in SENSITIVE_SETTING_KEYS


def test_encrypted_webhook_headers_round_trip_through_loader(db, monkeypatch):
    """An encrypted blob in kv must decrypt then parse back to the dict.

    Break-and-watch for the kv_loader fix: reverting the ``_decrypt`` call feeds
    ``enc:v1:...`` to ``json.loads``, which raises → fallback None → this fails.
    """
    _clear_webhook_env(monkeypatch)
    enc_key = derive_encryption_key(_SIGNING_KEY)
    payload = '{"Authorization": "Bearer s3cr3t", "X-Scope": "certs"}'
    kv_set(db, "webhook_headers", fernet_encrypt(payload, enc_key))

    s = Settings.from_env_with_kv(db, encryption_key=enc_key)
    assert s.webhook_headers == {"Authorization": "Bearer s3cr3t", "X-Scope": "certs"}


def test_plaintext_webhook_headers_migrates_cleanly(db, monkeypatch):
    """Values written before this key became sensitive (plaintext JSON) must
    still load even when an encryption key is present: ``fernet_decrypt`` passes
    non-``enc:v1:`` values through unchanged, so nothing is dropped on upgrade.
    """
    _clear_webhook_env(monkeypatch)
    enc_key = derive_encryption_key(_SIGNING_KEY)
    kv_set(db, "webhook_headers", '{"X-Scope": "certs"}')

    s = Settings.from_env_with_kv(db, encryption_key=enc_key)
    assert s.webhook_headers == {"X-Scope": "certs"}


def test_encrypted_webhook_headers_with_wrong_key_falls_back(db, monkeypatch):
    """A value we cannot decrypt (rotated/corrupted key) falls back to None
    rather than raising — mirroring the invalid-JSON fallback contract.
    """
    _clear_webhook_env(monkeypatch)
    good_key = derive_encryption_key(_SIGNING_KEY)
    wrong_key = derive_encryption_key("a-different-signing-key")
    kv_set(db, "webhook_headers", fernet_encrypt('{"X": "y"}', good_key))

    s = Settings.from_env_with_kv(db, encryption_key=wrong_key)
    assert s.webhook_headers is None


def test_save_alerts_route_encrypts_webhook_headers(reload_app, tmp_path):
    """Posting webhook_headers via /settings/alerts stores it encrypted (enc:v1:).

    Break-and-watch for ``routes/settings/alerts.py`` encrypt=True: reverting to
    encrypt=False stores plaintext, so the ``enc:v1:`` prefix assertion fails.
    """
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/alerts",
            data={"webhook_headers": '{"Authorization": "Bearer tok"}'},
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "saved=1" in r.headers["location"]

    stored = kv_get(tmp_path / "cert-watch.sqlite3", "webhook_headers")
    assert stored is not None
    assert stored.startswith("enc:v1:"), "webhook_headers was not encrypted at rest"


def test_save_alerts_route_blank_webhook_headers_preserves_existing(reload_app, tmp_path):
    """An empty webhook_headers field on save must NOT overwrite an existing
    encrypted value (the password-field round-trip: blank == 'leave unchanged').
    """
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    enc_key = derive_encryption_key(_SIGNING_KEY)
    existing = fernet_encrypt('{"Authorization": "Bearer keep"}', enc_key)
    kv_set(db, "webhook_headers", existing)

    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/alerts",
            data={"webhook_headers": ""},
            follow_redirects=False,
        )
    assert r.status_code == 303

    # Unchanged: still the same encrypted blob, not cleared/overwritten.
    assert kv_get(db, "webhook_headers") == existing
