"""SIEM / log export (Plan 028): emit audit events to syslog and/or Splunk HEC.

Both sinks are **fail-open** — a SIEM problem must never break or slow an audited
action. Syslog is local/fast and runs inline; Splunk HEC POSTs go through a small
bounded thread pool (and the SSRF-guarded opener) so the request path never
blocks on the network. When nothing is configured, ``export_audit_event`` is a
near-no-op (one cheap ``enabled`` check), so the audit write path is unchanged.

Config (env; ``*_FILE`` supported for the token via ``read_secret``):
  CERT_WATCH_SYSLOG_HOST / _PORT (514) / _PROTO (udp|tcp)
  CERT_WATCH_HEC_URL / _TOKEN (+_FILE) / _INDEX / _SOURCETYPE (cert_watch)
  CERT_WATCH_EVENTLOG (1) / _SOURCE (cert-watch)  — Windows only
  CERT_WATCH_INSTANCE_ID (defaults to hostname)

The Windows Event Log sink (``CERT_WATCH_EVENTLOG=1``) writes to the Application
log via pywin32; install the ``cert-watch[windows]`` extra. On non-Windows hosts
the sink disables itself gracefully. It runs inline (local + fast), like syslog.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from logging.handlers import SysLogHandler
from typing import Any

logger = logging.getLogger("cert_watch.siem")


def _instance_id() -> str:
    return os.environ.get("CERT_WATCH_INSTANCE_ID") or socket.gethostname()


class SiemExporter:
    """Builds the configured sinks once from the environment and fans events out."""

    def __init__(self) -> None:
        from cert_watch.config import read_secret

        self.syslog_host = os.environ.get("CERT_WATCH_SYSLOG_HOST", "").strip()
        try:
            self.syslog_port = int(os.environ.get("CERT_WATCH_SYSLOG_PORT", "514") or "514")
        except ValueError:
            self.syslog_port = 514
        self.syslog_proto = os.environ.get("CERT_WATCH_SYSLOG_PROTO", "udp").lower()

        self.hec_url = os.environ.get("CERT_WATCH_HEC_URL", "").strip()
        self.hec_token = read_secret("CERT_WATCH_HEC_TOKEN") or ""
        self.hec_index = os.environ.get("CERT_WATCH_HEC_INDEX", "").strip()
        self.hec_sourcetype = os.environ.get("CERT_WATCH_HEC_SOURCETYPE", "cert_watch").strip()

        self.eventlog_requested = os.environ.get("CERT_WATCH_EVENTLOG", "") == "1"
        self.eventlog_source = os.environ.get("CERT_WATCH_EVENTLOG_SOURCE", "cert-watch")

        self._syslog: logging.Logger | None = None
        self._pool: ThreadPoolExecutor | None = None
        self._eventlog: tuple[Any, Any] | None = None
        if self.syslog_host:
            self._setup_syslog()
        if self.eventlog_requested:
            self._setup_eventlog()
        if self.hec_url:
            self._pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="cw-hec")

    @property
    def enabled(self) -> bool:
        return bool(
            self.syslog_host
            or (self.hec_url and self.hec_token)
            or self._eventlog is not None
        )

    def _setup_syslog(self) -> None:
        try:
            socktype = socket.SOCK_STREAM if self.syslog_proto == "tcp" else socket.SOCK_DGRAM
            handler = SysLogHandler(
                address=(self.syslog_host, self.syslog_port), socktype=socktype
            )
            handler.setFormatter(logging.Formatter("cert-watch: %(message)s"))
            lg = logging.getLogger("cert_watch.siem.syslog")
            lg.setLevel(logging.INFO)
            lg.propagate = False
            # Close old handlers to avoid leaking sockets (BC-028)
            for old in lg.handlers:
                with contextlib.suppress(Exception):
                    old.close()
            lg.handlers = [handler]
            self._syslog = lg
        except Exception:
            logger.warning("syslog sink setup failed; disabling it", exc_info=True)
            self.syslog_host = ""
            self._syslog = None

    def close(self) -> None:
        """Close syslog handlers and shut down the thread pool."""
        if self._syslog is not None:
            for handler in self._syslog.handlers:
                with contextlib.suppress(Exception):
                    handler.close()
            self._syslog.handlers.clear()
            self._syslog = None
        if self._pool is not None:
            self._pool.shutdown(wait=False, cancel_futures=True)
            self._pool = None

    def _setup_eventlog(self) -> None:
        """Bind the Windows Event Log writer (pywin32), or disable gracefully.

        Available only on Windows with the ``cert-watch[windows]`` extra
        installed; on any other platform the import fails and the sink stays off.
        """
        try:
            import win32evtlog
            import win32evtlogutil

            self._eventlog = (win32evtlogutil, win32evtlog)
        except Exception:
            logger.warning(
                "CERT_WATCH_EVENTLOG=1 but pywin32 is unavailable "
                "(install 'cert-watch[windows]' on Windows); disabling it"
            )
            self._eventlog = None

    def export(self, event: dict[str, Any]) -> None:
        if self._syslog is not None:
            self._to_syslog(event)
        if self._eventlog is not None:
            self._to_eventlog(event)
        if self.hec_url and self.hec_token and self._pool is not None:
            self._pool.submit(self._to_hec, event)

    def _to_eventlog(self, event: dict[str, Any]) -> None:
        try:
            _evlog = self._eventlog
            if _evlog is None:
                return
            win32evtlogutil, win32evtlog = _evlog
            win32evtlogutil.ReportEvent(
                self.eventlog_source,
                1000,  # event ID
                eventType=win32evtlog.EVENTLOG_INFORMATION_TYPE,
                strings=[json.dumps(event, default=str, sort_keys=True)],
            )
        except Exception:
            logger.warning("Windows Event Log export failed", exc_info=True)

    def _to_syslog(self, event: dict[str, Any]) -> None:
        try:
            _syslog = self._syslog
            if _syslog is None:
                return
            _syslog.info(json.dumps(event, default=str, sort_keys=True))
        except Exception:
            logger.warning("syslog export failed", exc_info=True)

    def _to_hec(self, event: dict[str, Any]) -> None:
        from urllib.error import HTTPError

        from cert_watch.http_client import ssrf_safe_urlopen

        try:
            envelope: dict[str, Any] = {
                "event": event,
                "sourcetype": self.hec_sourcetype,
                "time": time.time(),
            }
            if self.hec_index:
                envelope["index"] = self.hec_index
            resp = ssrf_safe_urlopen(
                self.hec_url,
                data=json.dumps(envelope, default=str).encode("utf-8"),
                method="POST",
                headers={
                    "Authorization": f"Splunk {self.hec_token}",
                    "Content-Type": "application/json",
                },
                # HEC endpoints are typically internal; the operator configured
                # this URL explicitly, so private targets are allowed.
                allow_private=True,
            )
            with resp:
                if not (200 <= resp.status < 300):
                    logger.warning("HEC export non-2xx: %s", resp.status)
        except HTTPError as exc:
            logger.warning("HEC export non-2xx: %s", exc.code)
        except Exception:
            logger.warning("HEC export failed", exc_info=True)


_exporter: SiemExporter | None = None
_exporter_lock = threading.Lock()


def _get_exporter() -> SiemExporter:
    global _exporter
    if _exporter is None:
        with _exporter_lock:
            if _exporter is None:
                _exporter = SiemExporter()
    return _exporter


def reset_exporter() -> None:
    """Drop the cached exporter so the next call re-reads the environment (tests)."""
    global _exporter
    with _exporter_lock:
        if _exporter is not None:
            _exporter.close()
        _exporter = None


def siem_enabled() -> bool:
    return _get_exporter().enabled


def export_audit_event(event: dict[str, Any]) -> None:
    """Fan an audit event out to the configured SIEM sinks (fail-open)."""
    exp = _get_exporter()
    if exp.enabled:
        exp.export(event)
