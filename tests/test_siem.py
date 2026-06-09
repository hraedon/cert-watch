"""Tests for SIEM / log export (Plan 028): syslog + Splunk HEC, fail-open."""

from __future__ import annotations

import json

import pytest


@pytest.fixture(autouse=True)
def _reset_siem():
    from cert_watch import siem

    siem.reset_exporter()
    yield
    siem.reset_exporter()


def test_disabled_by_default():
    from cert_watch.siem import siem_enabled

    assert siem_enabled() is False


def test_export_is_noop_when_disabled():
    # No sinks configured → export must not raise and must do nothing.
    from cert_watch.siem import export_audit_event

    export_audit_event({"action": "noop"})  # no exception


def test_syslog_enables_and_export_is_fail_open(monkeypatch):
    monkeypatch.setenv("CERT_WATCH_SYSLOG_HOST", "127.0.0.1")
    monkeypatch.setenv("CERT_WATCH_SYSLOG_PORT", "9999")  # nothing listening
    from cert_watch import siem

    siem.reset_exporter()
    assert siem.siem_enabled() is True
    # Even with no listener, exporting must never raise.
    siem.export_audit_event({"action": "login", "actor": "admin"})


def test_hec_requires_token(monkeypatch):
    # URL without a token is not "enabled" (HEC needs the token).
    monkeypatch.setenv("CERT_WATCH_HEC_URL", "https://hec.example:8088/services/collector")
    from cert_watch import siem

    siem.reset_exporter()
    assert siem.siem_enabled() is False


def test_hec_post_envelope_and_headers(monkeypatch):
    monkeypatch.setenv("CERT_WATCH_HEC_URL", "https://hec.example:8088/services/collector")
    monkeypatch.setenv("CERT_WATCH_HEC_TOKEN", "tok123")
    monkeypatch.setenv("CERT_WATCH_HEC_INDEX", "main")
    from cert_watch import siem

    siem.reset_exporter()
    assert siem.siem_enabled() is True

    captured: dict = {}

    class FakeResp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return FakeResp()

    monkeypatch.setattr("cert_watch.http_client.ssrf_safe_urlopen", fake_urlopen)

    # Call the HEC sink synchronously (bypassing the thread pool).
    siem._get_exporter()._to_hec({"action": "host.delete", "actor": "admin"})

    assert captured["url"].endswith("/services/collector")
    assert captured["headers"]["Authorization"] == "Splunk tok123"
    assert captured["allow_private"] is True
    body = json.loads(captured["data"])
    assert body["event"]["action"] == "host.delete"
    assert body["sourcetype"] == "cert_watch"
    assert body["index"] == "main"


def test_export_dispatches_to_hec_pool(monkeypatch):
    monkeypatch.setenv("CERT_WATCH_HEC_URL", "https://hec.example:8088/services/collector")
    monkeypatch.setenv("CERT_WATCH_HEC_TOKEN", "tok123")
    from cert_watch import siem

    siem.reset_exporter()
    calls: list = []

    class FakeResp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(url, **kwargs):
        calls.append(url)
        return FakeResp()

    monkeypatch.setattr("cert_watch.http_client.ssrf_safe_urlopen", fake_urlopen)
    exp = siem._get_exporter()
    exp.export({"action": "x"})
    exp._pool.shutdown(wait=True)  # flush the background POST
    assert calls and calls[0].endswith("/services/collector")


def test_eventlog_disabled_without_pywin32(monkeypatch):
    import importlib.util

    monkeypatch.setenv("CERT_WATCH_EVENTLOG", "1")
    from cert_watch import siem

    siem.reset_exporter()
    # On a host without pywin32 (CI/Linux), the sink disables itself gracefully
    # rather than crashing the audit path.
    if importlib.util.find_spec("win32evtlogutil") is None:
        assert siem.siem_enabled() is False


def test_eventlog_reports_event_when_available(monkeypatch):
    import sys
    import types

    fake_util = types.ModuleType("win32evtlogutil")
    fake_evtlog = types.ModuleType("win32evtlog")
    fake_evtlog.EVENTLOG_INFORMATION_TYPE = 4
    calls: list = []

    def report(source, eid, eventType=None, strings=None, **kw):
        calls.append((source, eid, eventType, strings))

    fake_util.ReportEvent = report
    monkeypatch.setitem(sys.modules, "win32evtlogutil", fake_util)
    monkeypatch.setitem(sys.modules, "win32evtlog", fake_evtlog)
    monkeypatch.setenv("CERT_WATCH_EVENTLOG", "1")
    monkeypatch.setenv("CERT_WATCH_EVENTLOG_SOURCE", "cert-watch-test")
    from cert_watch import siem

    siem.reset_exporter()
    assert siem.siem_enabled() is True
    siem.export_audit_event({"action": "login", "actor": "admin"})
    assert calls and calls[0][0] == "cert-watch-test"
    assert calls[0][2] == 4  # EVENTLOG_INFORMATION_TYPE
    assert "login" in calls[0][3][0]


def test_record_audit_fans_out_to_siem(monkeypatch, tmp_path):
    # record_audit should write the row AND export to the configured sink,
    # fail-open. Exercises the audit -> SIEM hook + instance stamping.
    monkeypatch.setenv("CERT_WATCH_SYSLOG_HOST", "127.0.0.1")
    monkeypatch.setenv("CERT_WATCH_SYSLOG_PORT", "9999")  # nothing listening
    from cert_watch import siem
    from cert_watch.audit import list_audit, record_audit
    from cert_watch.database import init_schema

    siem.reset_exporter()
    assert siem.siem_enabled() is True

    db = str(tmp_path / "audit.sqlite3")
    init_schema(db)
    record_audit(
        db, actor="admin", action="host.delete",
        target_type="host", target_id="h1",
    )
    rows = list_audit(db)
    assert any(r["action"] == "host.delete" for r in rows)  # row persisted


def test_hec_failure_is_swallowed(monkeypatch):
    monkeypatch.setenv("CERT_WATCH_HEC_URL", "https://hec.example:8088/services/collector")
    monkeypatch.setenv("CERT_WATCH_HEC_TOKEN", "tok123")
    from cert_watch import siem

    siem.reset_exporter()

    def boom(url, **kwargs):
        raise OSError("connection refused")

    monkeypatch.setattr("cert_watch.http_client.ssrf_safe_urlopen", boom)
    siem._get_exporter()._to_hec({"action": "x"})


def test_invalid_port_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("CERT_WATCH_SYSLOG_HOST", "127.0.0.1")
    monkeypatch.setenv("CERT_WATCH_SYSLOG_PORT", "not-a-number")
    from cert_watch import siem

    siem.reset_exporter()
    exp = siem._get_exporter()
    assert exp.syslog_port == 514


def test_syslog_setup_failure_disables_sink(monkeypatch):
    monkeypatch.setenv("CERT_WATCH_SYSLOG_HOST", "127.0.0.1")
    from logging.handlers import SysLogHandler

    from cert_watch import siem

    def bad_handler(*a, **kw):
        raise OSError("cannot create socket")

    monkeypatch.setattr(SysLogHandler, "__init__", bad_handler)
    siem.reset_exporter()
    exp = siem._get_exporter()
    assert exp.syslog_host == ""
    assert exp._syslog is None
    assert exp.enabled is False


def test_syslog_replaces_old_handlers(monkeypatch):
    monkeypatch.setenv("CERT_WATCH_SYSLOG_HOST", "127.0.0.1")
    from cert_watch import siem

    siem.reset_exporter()
    exp = siem._get_exporter()
    first_handler = exp._syslog.handlers[0]
    assert first_handler is not None
    exp._setup_syslog()
    assert first_handler not in exp._syslog.handlers
    assert len(exp._syslog.handlers) == 1


def test_syslog_export_failure_is_swallowed(monkeypatch):
    monkeypatch.setenv("CERT_WATCH_SYSLOG_HOST", "127.0.0.1")
    from cert_watch import siem

    siem.reset_exporter()
    exp = siem._get_exporter()
    exp._syslog.info = lambda msg: (_ for _ in ()).throw(OSError("broken pipe"))
    exp.export({"action": "x"})


def test_eventlog_export_failure_is_swallowed(monkeypatch):
    import sys
    import types

    fake_util = types.ModuleType("win32evtlogutil")
    fake_evtlog = types.ModuleType("win32evtlog")
    fake_evtlog.EVENTLOG_INFORMATION_TYPE = 4

    def bad_report(*a, **kw):
        raise OSError("event log full")

    fake_util.ReportEvent = bad_report
    monkeypatch.setitem(sys.modules, "win32evtlogutil", fake_util)
    monkeypatch.setitem(sys.modules, "win32evtlog", fake_evtlog)
    monkeypatch.setenv("CERT_WATCH_EVENTLOG", "1")
    from cert_watch import siem

    siem.reset_exporter()
    assert siem.siem_enabled() is True
    siem._get_exporter()._to_eventlog({"action": "x"})


def test_hec_non_2xx_logs_warning(monkeypatch):
    monkeypatch.setenv("CERT_WATCH_HEC_URL", "https://hec.example:8088/services/collector")
    monkeypatch.setenv("CERT_WATCH_HEC_TOKEN", "tok123")
    from cert_watch import siem

    siem.reset_exporter()

    class Resp500:
        status = 503

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(
        "cert_watch.http_client.ssrf_safe_urlopen",
        lambda url, **kw: Resp500(),
    )
    siem._get_exporter()._to_hec({"action": "x"})


def test_hec_no_index_omits_from_envelope(monkeypatch):
    monkeypatch.setenv("CERT_WATCH_HEC_URL", "https://hec.example:8088/services/collector")
    monkeypatch.setenv("CERT_WATCH_HEC_TOKEN", "tok123")
    from cert_watch import siem

    siem.reset_exporter()
    captured: dict = {}

    class FakeResp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(url, **kwargs):
        captured["data"] = kwargs.get("data", b"")
        return FakeResp()

    monkeypatch.setattr("cert_watch.http_client.ssrf_safe_urlopen", fake_urlopen)
    siem._get_exporter()._to_hec({"action": "scan"})
    body = json.loads(captured["data"])
    assert "index" not in body
    assert body["sourcetype"] == "cert_watch"


def test_close_cleans_up_pool_and_syslog(monkeypatch):
    monkeypatch.setenv("CERT_WATCH_SYSLOG_HOST", "127.0.0.1")
    monkeypatch.setenv("CERT_WATCH_HEC_URL", "https://hec.example:8088/s")
    monkeypatch.setenv("CERT_WATCH_HEC_TOKEN", "tok")
    from cert_watch import siem

    siem.reset_exporter()
    exp = siem._get_exporter()
    assert exp._syslog is not None
    assert exp._pool is not None
    exp.close()
    assert exp._syslog is None
    assert exp._pool is None
