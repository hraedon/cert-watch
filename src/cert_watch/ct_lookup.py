"""Certificate Transparency log lookups via crt.sh."""

from __future__ import annotations

import json
import os
import re
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlparse

_DOMAIN_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*"
    r"\.[a-zA-Z]{2,}$"
)
_MAX_DOMAIN_LEN = 253

# Configurable CT log base URL (default: crt.sh). Private CT logs can be
# targeted by setting CERT_WATCH_CT_LOG_URL (validated, must be http/https).
_CT_LOG_URL = os.environ.get("CERT_WATCH_CT_LOG_URL", "https://crt.sh").rstrip("/")
if urlparse(_CT_LOG_URL).scheme not in ("http", "https"):
    _CT_LOG_URL = "https://crt.sh"


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
    url = f"{_CT_LOG_URL}/?q={domain}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "cert-watch/0.3"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
    except Exception as exc:  # noqa: BLE001
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
