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


def test_hec_failure_is_swallowed(monkeypatch):
    monkeypatch.setenv("CERT_WATCH_HEC_URL", "https://hec.example:8088/services/collector")
    monkeypatch.setenv("CERT_WATCH_HEC_TOKEN", "tok123")
    from cert_watch import siem

    siem.reset_exporter()

    def boom(url, **kwargs):
        raise OSError("connection refused")

    monkeypatch.setattr("cert_watch.http_client.ssrf_safe_urlopen", boom)
    # Fail-open: a down SIEM must not raise into the caller.
    siem._get_exporter()._to_hec({"action": "x"})
