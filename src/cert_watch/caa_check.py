"""DNS CAA record checking. See spec FEAT-010."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

import dns.rdatatype
import dns.resolver

logger = logging.getLogger("cert_watch.caa_check")

_DOMAIN_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*"
    r"\.[a-zA-Z]{2,}$"
)
_MAX_DOMAIN_LEN = 253


@dataclass
class CAAResult:
    domain: str
    records: list[str]
    issue_allowed: bool
    issuewild_allowed: bool
    error: str = ""


def _query_caa_records(domain: str) -> list[str] | str:
    """Query CAA records for a domain using dnspython (a core dependency)."""
    # Walk up the domain tree looking for CAA records
    parts = domain.rstrip(".").split(".")
    for i in range(len(parts)):
        check_domain = ".".join(parts[i:])
        try:
            answers = dns.resolver.resolve(check_domain, dns.rdatatype.CAA)
            records = [str(r) for r in answers]
            if records:
                return records
        except dns.resolver.NXDOMAIN:
            continue
        except dns.resolver.NoAnswer:
            continue
        except (OSError, dns.exception.DNSException) as exc:  # DNS lookup
            logger.warning("CAA lookup failed for %s: %s", check_domain, exc)
            return f"DNS lookup failed: {exc}"
    return []


def check_caa(domain: str) -> CAAResult:
    """Check CAA records for a domain.

    Returns a CAAResult with:
    - records: raw CAA record strings
    - issue_allowed: False only if an empty issue tag (';') is found
    - issuewild_allowed: same logic for issuewild

    If no CAA records exist, issuance is implicitly allowed per RFC 8659.
    """
    raw = _query_caa_records(domain)
    if isinstance(raw, str):
        return CAAResult(
            domain=domain,
            records=[],
            issue_allowed=True,
            issuewild_allowed=True,
            error=raw,
        )

    if not raw:
        # No CAA records = no restriction
        return CAAResult(domain=domain, records=[], issue_allowed=True, issuewild_allowed=True)

    records: list[str] = []
    issue_allowed = True
    issuewild_allowed = True

    for r in raw:
        # CAA RDATA: flags tag value
        # e.g. "0 issue \"letsencrypt.org\""
        parts = r.split(None, 2)
        if len(parts) < 2:
            continue
        tag = parts[1].lower()
        value = parts[2] if len(parts) > 2 else ""
        records.append(f"{tag} {value}")
        if tag == "issue" and value.strip('"') == ";":
            issue_allowed = False
        if tag == "issuewild" and value.strip('"') == ";":
            issuewild_allowed = False

    return CAAResult(
        domain=domain,
        records=records,
        issue_allowed=issue_allowed,
        issuewild_allowed=issuewild_allowed,
    )
