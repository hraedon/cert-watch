from cert_watch.config import Settings


def test_settings_repr_redacts_credential_bearing_urls(tmp_path):
    settings = Settings(
        db_path=tmp_path / "cert-watch.sqlite3",
        data_dir=tmp_path,
        webhook_url="https://hooks.slack.com/services/T/B/secret",
        renewal_webhook_url="https://user:token@renew.example.test/hook",
        hec_url="https://token@http-inputs.example.test/services/collector",
    )

    rendered = repr(settings)
    assert "hooks.slack.com" not in rendered
    assert "user:token" not in rendered
    assert "token@http-inputs" not in rendered
