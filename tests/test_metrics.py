from fastapi.testclient import TestClient


def test_metrics_empty(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/metrics")
    assert r.status_code == 200
    text = r.text
    assert "cert_watch_cert_expiry_days" in text
    assert "cert_watch_hosts_tracked 0" in text
    assert "cert_watch_certificates_tracked 0" in text
    assert "cert_watch_certificates_expired 0" in text


def test_metrics_with_data(tmp_path, reload_app, leaf_pem_file):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.upload import UploadedEntry, store_uploaded, upload_certificate

    entry = upload_certificate(leaf_pem_file)
    assert isinstance(entry, UploadedEntry)
    store_uploaded(entry, db)

    from cert_watch.database import SqliteHostRepository

    SqliteHostRepository(db).add("metric.example.com", 443)

    with TestClient(app_mod.app) as client:
        r = client.get("/metrics")
    assert r.status_code == 200
    text = r.text
    assert "cert_watch_cert_expiry_days{" in text
    assert "cert_watch_hosts_tracked 1" in text
    assert "cert_watch_certificates_tracked 1" in text
    assert "leaf.example.com" in text


def test_metrics_scan_errors_counter(tmp_path, reload_app):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import init_schema
    from cert_watch.scheduler import ScanHistory, record_scan_history

    init_schema(db)

    # Insert failure records with distinct error messages
    record_scan_history(db, ScanHistory(
        hostname="fail.example.com", port=443,
        status="failure", error_message="Connection refused",
    ))
    record_scan_history(db, ScanHistory(
        hostname="timeout.example.com", port=443,
        status="failure", error_message="Connection timed out",
    ))
    record_scan_history(db, ScanHistory(
        hostname="dns.example.com", port=443,
        status="failure", error_message="Could not resolve hostname",
    ))
    record_scan_history(db, ScanHistory(
        hostname="blocked.example.com", port=443,
        status="failure", error_message="pinned IP 127.0.0.1 is a blocked address",
    ))
    # success record should not appear in counter
    record_scan_history(db, ScanHistory(
        hostname="ok.example.com", port=443,
        status="success",
    ))

    with TestClient(app_mod.app) as client:
        r = client.get("/metrics")
    assert r.status_code == 200
    text = r.text
    assert "cert_scan_errors_total" in text
    assert 'reason="connection_refused"' in text
    assert 'reason="timeout"' in text
    assert 'reason="dns_failure"' in text
    assert 'reason="blocked"' in text
    assert 'host="fail.example.com:443"' in text
    assert 'host="timeout.example.com:443"' in text
    assert 'host="dns.example.com:443"' in text
    assert 'host="blocked.example.com:443"' in text
    # success host should not appear
    assert 'host="ok.example.com:443"' not in text


def test_prometheus_rules_valid_yaml():
    """FEAT-011: prometheus-rules.yaml must be valid YAML with expected alerts."""
    from pathlib import Path

    import yaml

    rules_path = Path(__file__).resolve().parent.parent / "deploy" / "k8s" / "prometheus-rules.yaml"
    assert rules_path.exists(), f"prometheus-rules.yaml not found at {rules_path}"
    content = rules_path.read_text()
    doc = yaml.safe_load(content)
    assert doc["apiVersion"] == "monitoring.coreos.com/v1"
    assert doc["kind"] == "PrometheusRule"
    assert doc["metadata"]["name"] == "cert-watch-alerts"
    rules = doc["spec"]["groups"][0]["rules"]
    alert_names = {r["alert"] for r in rules}
    assert "CertExpiringCritical" in alert_names
    assert "CertExpiringWarning" in alert_names
    assert "CertExpired" in alert_names
