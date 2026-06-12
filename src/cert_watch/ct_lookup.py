"""Certificate Transparency log lookups via crt.sh."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import quote, urlparse

from cert_watch.http_client import SSRFBlockedError, ssrf_safe_urlopen

_MAX_CT_RESPONSE = 10 * 1024 * 1024  # 10 MiB — guard against adversarial CT logs

_DOMAIN_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*"
    r"\.[a-zA-Z]{2,}$"
)
_MAX_DOMAIN_LEN = 253

_DEFAULT_CT_LOG_URL = "https://crt.sh"
_ct_log_url_cache: str | None = None


def _ct_log_url() -> str:
    """Return the CT log base URL, read from the environment on first call.

    Cached after the first read so repeated lookups don't re-parse the env.
    """
    global _ct_log_url_cache
    if _ct_log_url_cache is not None:
        return _ct_log_url_cache
    raw = os.environ.get("CERT_WATCH_CT_LOG_URL", _DEFAULT_CT_LOG_URL).rstrip("/")
    if urlparse(raw).scheme not in ("http", "https"):
        raw = _DEFAULT_CT_LOG_URL
    _ct_log_url_cache = raw
    return raw


@dataclass
class CTEntry:
    issuer_ca_id: int
    issuer_name: str
    common_name: str
    name_value: str
    not_before: datetime
    not_after: datetime
    serial_number: str


def query_ct_log(
    domain: str, *, timeout: int = 15
) -> list[CTEntry] | str:
    """Query crt.sh for certificates issued for *domain*.

    Returns a list of CTEntry on success, or an error message string on failure.
    Only returns certificates that are currently valid (not_before <= now <= not_after).
    """
    if not domain or len(domain) > _MAX_DOMAIN_LEN or not _DOMAIN_RE.match(domain):
        return f"Invalid domain: {domain}"
    url = f"{_ct_log_url()}/?q={quote(domain, safe='')}&output=json"
    try:
        with ssrf_safe_urlopen(
            url, timeout=timeout, headers={"User-Agent": "cert-watch/0.3"},
        ) as resp:
            raw = resp.read(_MAX_CT_RESPONSE + 1)
            if len(raw) > _MAX_CT_RESPONSE:
                return f"CT log response too large for {domain} (>{_MAX_CT_RESPONSE} bytes)"
    except SSRFBlockedError as exc:
        return f"CT lookup blocked by SSRF policy for {domain}: {exc}"
    except (OSError, ValueError) as exc:  # urllib / network errors
        return f"CT lookup failed for {domain}: {exc}"
    try:
        entries = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        return f"CT lookup returned invalid JSON for {domain}: {exc}"
    now = datetime.now(UTC)
    results: list[CTEntry] = []
    for e in entries[:50]:
        try:
            nb = datetime.fromisoformat(e["not_before"])
            na = datetime.fromisoformat(e["not_after"])
            if nb.tzinfo is None:
                nb = nb.replace(tzinfo=UTC)
            if na.tzinfo is None:
                na = na.replace(tzinfo=UTC)
        except (KeyError, ValueError):
            continue
        if nb <= now <= na:
            results.append(
                CTEntry(
                    issuer_ca_id=e.get("issuer_ca_id", 0),
                    issuer_name=e.get("issuer_name", ""),
                    common_name=e.get("common_name", ""),
                    name_value=e.get("name_value", ""),
                    not_before=nb,
                    not_after=na,
                    serial_number=e.get("serial_number", ""),
                )
            )
    return results
