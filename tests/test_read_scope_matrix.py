"""Read-scope matrix: a tag-scoped user sees nothing outside their scope (#112).

The write side of tag scoping is pinned by the golden authorization matrix;
this is its read-side counterpart. It seeds an estate with two tag-scoped
teams (``payments`` and ``hr-ops``, with mixed-case tags) plus untagged hosts,
then requests EVERY GET route the app registers as a viewer and as an
operator scoped to ``payments``, and checks two things:

1. **No out-of-scope identifier appears** in any body: hostname, certificate
   CN, SAN, tag or owner of another team or of an untagged host.
2. **Out-of-scope data changes nothing** (differential check). The payments
   half of the estate is seeded into a *baseline* database, which is copied
   and then extended with the other team and the untagged hosts to make the
   *full* database. The payments rows are byte-identical in both, so every
   response a payments-scoped user gets must be identical too, modulo
   per-request noise (CSRF tokens, nonces, timestamps, signatures). A count,
   a grade distribution or a chart bar that moves when another team's hosts
   are added is a leak even when no hostname is printed.

Routes with path parameters are requested with in-scope ids (compared across
the two databases) and with out-of-scope ids, which must answer exactly like
an id that does not exist.

A new GET route fails :func:`test_every_get_route_is_in_the_matrix` until it
is added to ``_ROUTE_REQUESTS`` or, with a reason, to ``_ESTATE_WIDE``.

State-changing routes get the same treatment (the second half of this file):
every POST/PUT/PATCH/DELETE route addressed by a host, certificate, alert or
alert-group id is sent an out-of-scope id and a nonexistent id, and the two
responses must be identical, the database must not change and no scan may
start. Adding an endpoint another team already monitors is refused.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import json
import re
import shutil
import socket
import sys
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from cert_watch.auth import SESSION_COOKIE, _scrypt_hash
from tests._route_inventory import _walk, mutating_routes
from tests.test_authz_characterization import _body_for, _csrf_header

# A throwaway password for the seeded local accounts, built at runtime so the
# suite carries no credential-shaped literal.
_PW = "-".join(["matrix", "viewer", "pw"])
_NONEXISTENT = "00000000-0000-4000-8000-000000000000"

# ---------------------------------------------------------------------------
# Estate
# ---------------------------------------------------------------------------

_NOW = dt.datetime.now(dt.UTC)


@dataclass(frozen=True)
class _HostSpec:
    hostname: str
    tags: str
    port: int = 443
    owner: str = ""
    renewal_method: str = ""
    sans: tuple[str, ...] = ()
    days: int = 60
    weak: bool = False  # RSA-1024 leaf: shows under Weak primitives
    scanned: bool = True
    rescan: bool = False  # a second scan with a new cert: events, drift, history
    failed_scan: bool = False  # a recorded scan failure (pending host)


# The in-scope team. Tags deliberately mix case against the role's scope.
_PAYMENTS = (
    _HostSpec("pay-api.payments.test", "Payments", owner="pay-owner",
              renewal_method="ACME", sans=("pay-api-alt.payments.test",), days=5,
              weak=True, rescan=True),
    _HostSpec("pay-web.payments.test", "payments,web", owner="pay-owner", days=40),
    _HostSpec("pay-queue.payments.test", "PAYMENTS", days=200),
    _HostSpec("pay-pending.payments.test", "payments", scanned=False, failed_scan=True),
    # One name, two endpoints, two teams: scope is per (hostname, port).
    _HostSpec("dual.ports.test", "Payments", port=8443, days=25),
)

# Out of scope: the other team, plus untagged hosts (visible to no scoped user).
_OTHER = (
    _HostSpec("hrops-portal.hrteam.test", "HR-Ops", owner="hrops-owner",
              renewal_method="Manual", sans=("hrops-portal-san.hrteam.test",),
              days=3, weak=True, rescan=True),
    _HostSpec("hrops-ldap.hrteam.test", "hr-ops,directory", owner="hrops-owner",
              days=-10, weak=True),
    _HostSpec("hrops-mail.hrteam.test", "HR-OPS", days=20),
    _HostSpec("hrops-sso.hrteam.test", "hr-ops", days=6),
    _HostSpec("hrops-pending.hrteam.test", "hr-ops", scanned=False, failed_scan=True),
    _HostSpec("dual.ports.test", "HR-Ops", sans=("dual-san.hrteam.test",), days=2,
              weak=True, rescan=True, failed_scan=True),
    # Pending (never scanned) endpoints with non-ASCII and IP-literal names:
    # the create paths are probed with their other spellings.
    _HostSpec("büro.hrteam.test".encode("idna").decode("ascii"), "hr-ops", scanned=False),
    _HostSpec("2001:db8::1", "HR-Ops", scanned=False),
    _HostSpec("untagged-a.shared.test", "", owner="shared-owner", days=9, weak=True),
    _HostSpec("untagged-b.shared.test", "", days=400),
    _HostSpec("untagged-pending.shared.test", "", scanned=False),
)

_PAYMENTS_UPLOAD_CN = "pay-upload.payments.test"
_OTHER_UPLOAD_CN = "hrops-upload.hrteam.test"
_UNTAGGED_UPLOAD_CN = "untagged-upload.shared.test"
_PAYMENTS_CA_CN = "Payments Issuing CA"
_OTHER_CA_CN = "HR-Ops Issuing CA"
_UNTAGGED_CA_CN = "Shared Estate CA"

# Strings that must never reach a payments-scoped user.
_FORBIDDEN_MARKERS: tuple[str, ...] = tuple(sorted({
    # A name shared with an in-scope endpoint is visible; its other port is
    # covered by the SAN below and by the differential test.
    *(h.hostname for h in _OTHER if h.hostname not in {p.hostname for p in _PAYMENTS}),
    *(s for h in _OTHER for s in h.sans),
    _OTHER_UPLOAD_CN, _UNTAGGED_UPLOAD_CN,
    "hrteam", "shared.test",  # every out-of-scope DNS name carries one of these
    "hr-ops", "hrops",  # the other team's tag and owner
    "shared-owner",
    _OTHER_CA_CN.casefold(), _UNTAGGED_CA_CN.casefold(),
}))

_KEYS: dict[int, rsa.RSAPrivateKey] = {}


def _key(bits: int) -> rsa.RSAPrivateKey:
    # One key per size keeps seeding fast; key reuse is irrelevant here.
    if bits not in _KEYS:
        _KEYS[bits] = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return _KEYS[bits]


def _ca(cn: str) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    key = _key(2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - dt.timedelta(days=30))
        .not_valid_after(_NOW + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _leaf(
    cn: str, sans: tuple[str, ...], days: int,
    ca: tuple[x509.Certificate, rsa.RSAPrivateKey], *, weak: bool,
) -> x509.Certificate:
    ca_cert, ca_key = ca
    key = _key(1024 if weak else 2048)
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - dt.timedelta(days=max(1, 90 - days)))
        .not_valid_after(_NOW + dt.timedelta(days=days))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in (cn, *sans)]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )


def _model(cert: x509.Certificate) -> Any:
    from cert_watch.certificate_model import parse_certificate

    parsed = parse_certificate(cert.public_bytes(serialization.Encoding.DER))
    assert not isinstance(parsed, Exception), parsed
    return parsed


def _no_caa(domain: str) -> Any:
    """CAA lookups hit DNS; the matrix stays off the network."""
    from cert_watch.caa_check import CAAResult

    return CAAResult(domain=domain, records=[], issue_allowed=True, issuewild_allowed=True)


def _seed_team(
    db: Path, hosts: tuple[_HostSpec, ...], ca_cn: str, upload_cn: str, upload_tags: str,
    *, anchor: bool,
) -> None:
    from cert_watch.database import SqliteAlertGroupRepository, SqliteHostRepository
    from cert_watch.database.connection import _connect
    from cert_watch.scan import ScannedEntry, _evaluate_posture, store_scanned
    from cert_watch.scheduler import ScanHistory, record_scan_history
    from cert_watch.upload import UploadedEntry, store_uploaded

    ca = _ca(ca_cn)
    ca_model = _model(ca[0])
    if anchor:
        from cert_watch.database import SqliteTrustAnchorRepository

        SqliteTrustAnchorRepository(db).add(ca_model)

    repo = SqliteHostRepository(db)
    with pytest.MonkeyPatch.context() as mp:
        # Posture evaluation looks up CAA records; keep the seed off the network.
        mp.setattr("cert_watch.caa_check.check_caa", _no_caa)
        for h in hosts:
            repo.add(
                h.hostname, h.port, tags=h.tags, owner_name=h.owner,
                renewal_method=h.renewal_method,
            )
            if h.failed_scan:
                record_scan_history(db, ScanHistory(
                    hostname=h.hostname, port=h.port, status="failure",
                    error_message=f"connection refused by {h.hostname}",
                ))
                from cert_watch.events import emit_scan_failed

                emit_scan_failed(db, h.hostname, h.port, f"refused by {h.tags or 'untagged'}")
            if not h.scanned:
                continue
            scans = 2 if h.rescan else 1
            for i in range(scans):
                leaf = _model(_leaf(h.hostname, h.sans, h.days + i, ca, weak=h.weak))
                entry = ScannedEntry(
                    host=h.hostname, port=h.port, leaf=leaf, chain=[ca_model],
                    protocol_version="TLSv1.2" if h.weak else "TLSv1.3",
                    scanned_at=_NOW - dt.timedelta(days=scans - i),
                )
                store_scanned(entry, db, _posture_eval=_evaluate_posture(db, entry))
                record_scan_history(db, ScanHistory(
                    hostname=h.hostname, port=h.port, status="success",
                    scanned_at=_NOW - dt.timedelta(days=scans - i),
                ))

    up = _leaf(upload_cn, (f"alt-{upload_cn}",), 12, ca, weak=False)
    store_uploaded(
        UploadedEntry(file_name=f"{upload_cn}.pem", leaf=_model(up), chain=[ca_model]),
        db, tags=upload_tags,
    )

    tag = next((t for h in hosts for t in h.tags.split(",") if t), "")
    if tag:
        SqliteAlertGroupRepository(db).create(
            name=f"{tag.casefold()}-alerts", recipients=[f"{tag.casefold()}@example.test"],
            match_tags=[tag],
        )

    # Expiry alerts for everything in the estate that is due.
    from cert_watch.alerting.rules.expiry import evaluate_all_certs
    from cert_watch.database import SqliteAlertRepository

    evaluate_all_certs(db, SqliteAlertRepository(db))
    with _connect(db) as conn:
        conn.commit()


def _hash(pw: str) -> str:
    return _scrypt_hash(pw, n=2**4, r=1, p=1)


def _seed_users(db: Path) -> None:
    from cert_watch.database import (
        Role,
        SqliteRoleRepository,
        SqliteUserRepository,
        kv_set,
    )

    kv_set(db, "local_admin_user", "admin")
    kv_set(db, "local_admin_password_hash", _hash(_PW))
    kv_set(db, "setup_complete", "1")
    roles = SqliteRoleRepository(db)
    users = SqliteUserRepository(db)
    from cert_watch.database import User

    for username, tier, scope in (
        ("pay-viewer", "viewer", "payments"),
        ("pay-operator", "operator", "Payments"),
    ):
        role_id = roles.add(Role(name=f"{username}-role", permission_tier=tier, scope_tag=scope))
        users.add(User(username=username, email="", password_hash=_hash(_PW), role_id=role_id))


@dataclass
class _Estate:
    baseline_dir: Path
    full_dir: Path
    in_scope: dict[str, str] = field(default_factory=dict)  # label -> id
    out_of_scope: dict[str, str] = field(default_factory=dict)


def _ids(db: Path) -> dict[str, str]:
    """label -> id for every host, certificate and alert group in *db*."""
    from cert_watch.database.connection import _connect

    out: dict[str, str] = {}
    with _connect(db) as conn:
        for r in conn.execute("SELECT id, hostname, port FROM hosts"):
            out[f"host:{r['hostname']}:{r['port']}"] = r["id"]
        for r in conn.execute(
            "SELECT id, subject, hostname, source, is_leaf FROM certificates"
        ):
            kind = "leaf" if r["is_leaf"] else "chain"
            label = f"{kind}:{r['source']}:{r['hostname'] or ''}:{r['subject']}"
            out[f"cert:{label}:{r['id']}"] = r["id"]
        for r in conn.execute("SELECT id, name FROM alert_groups"):
            out[f"group:{r['name']}"] = r["id"]
        for r in conn.execute("SELECT id, cert_id FROM alerts"):
            out[f"alert:{r['cert_id']}:{r['id']}"] = r["id"]
    return out


@pytest.fixture(scope="module")
def estate(tmp_path_factory: pytest.TempPathFactory) -> _Estate:
    from cert_watch.database import init_schema

    root = tmp_path_factory.mktemp("read-scope-matrix")
    baseline, full = root / "baseline", root / "full"
    baseline.mkdir()
    full.mkdir()
    bdb = baseline / "cert-watch.sqlite3"
    init_schema(bdb)
    _seed_users(bdb)
    _seed_team(bdb, _PAYMENTS, _PAYMENTS_CA_CN, _PAYMENTS_UPLOAD_CN, "Payments", anchor=True)
    base_ids = _ids(bdb)
    from cert_watch.database.connection import _connect

    with _connect(bdb) as conn:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    shutil.copy(bdb, full / "cert-watch.sqlite3")
    fdb = full / "cert-watch.sqlite3"
    others = tuple(h for h in _OTHER if h.tags)
    untagged = tuple(h for h in _OTHER if not h.tags)
    _seed_team(fdb, others, _OTHER_CA_CN, _OTHER_UPLOAD_CN, "HR-Ops", anchor=True)
    _seed_team(fdb, untagged, _UNTAGGED_CA_CN, _UNTAGGED_UPLOAD_CN, "", anchor=False)
    full_ids = _ids(fdb)
    est = _Estate(baseline_dir=baseline, full_dir=full)
    est.in_scope = base_ids
    est.out_of_scope = {k: v for k, v in full_ids.items() if k not in base_ids}
    assert set(base_ids.items()) <= set(full_ids.items())
    assert est.out_of_scope, "the out-of-scope half of the estate did not seed"
    return est


# ---------------------------------------------------------------------------
# Clients
# ---------------------------------------------------------------------------


# Two local accounts and one directory (role-map) session that resolves to
# the operator role: every scope path must be the same for all three.
_USERS = ("pay-viewer", "pay-operator", "pay-directory")
_DIRECTORY_USER = "pay-directory"
_DIRECTORY_ROLE = "pay-operator-role"
_ROLE_MAP = json.dumps({_DIRECTORY_ROLE: {"roles": [_DIRECTORY_ROLE]}})


@dataclass(frozen=True)
class _Snapshot:
    status: int
    content_type: str
    location: str
    body: str


# Per-request noise that legitimately differs between two otherwise identical
# requests. Everything else in a response must match.
_NOISE: tuple[tuple[re.Pattern[str], str], ...] = (
    # Per-session / per-request tokens.
    (re.compile(r'(name="_csrf_token"\s+value=")[^"]*'), r"\1<csrf>"),
    (re.compile(r'(name="csrf-token"\s+content=")[^"]*'), r"\1<csrf>"),
    (re.compile(r'(data-csrf=")[^"]*'), r"\1<csrf>"),
    (re.compile(r'(nonce=")[^"]*'), r"\1<nonce>"),
    # The report generation clock, and the hash and signature derived from it.
    # Only these; a certificate fingerprint or a scan timestamp that differs
    # between the two databases IS a leak and must stay visible.
    (re.compile(r'("generated_at":\s*")[^"]*'), r"\1<ts>"),
    (re.compile(r"(Generated(?: at)?[:,]? ?)\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}[0-9:.+]*"),
     r"\1<ts>"),
    (re.compile(r'("content_sha256":\s*")[0-9a-f]{64}'), r"\1<hash>"),
    (re.compile(r"(Content SHA-256[:,] ?)[0-9a-f]{64}"), r"\1<hash>"),
    (re.compile(r'("signature":\s*")[^"]*'), r"\1<sig>"),
    (re.compile(r"(HMAC-SHA256 signature[:,] ?)[0-9a-f]+"), r"\1<sig>"),
)


def _normalize(text: str, ids: dict[str, str] | None = None) -> str:
    for pattern, repl in _NOISE:
        text = pattern.sub(repl, text)
    for placeholder, value in (ids or {}).items():
        text = text.replace(value, placeholder)
    return text


def _snapshot(resp: Any, ids: dict[str, str] | None = None) -> _Snapshot:
    return _Snapshot(
        status=resp.status_code,
        content_type=resp.headers.get("content-type", "").split(";")[0],
        location=_normalize(resp.headers.get("location", ""), ids),
        body=_normalize(resp.text, ids),
    )


def _app(data_dir: Path) -> Any:
    from cert_watch.app import create_app
    from cert_watch.config import Settings

    base = Settings.from_env()
    assert Path(base.db_path).parent == data_dir
    return create_app(settings=Settings.from_env_with_kv(base.db_path))


def _read_sse(client: TestClient, url: str) -> str:
    """Read one polling cycle of an SSE endpoint.

    The event stream loops until the client disconnects. Report the client
    as disconnected on the second check and skip the poll interval, so the
    stream sends its first burst (every visible event) and ends.
    """
    import asyncio

    from starlette.requests import Request

    seen: set[int] = set()
    real_sleep = asyncio.sleep

    async def is_disconnected(self: Request) -> bool:
        if id(self) in seen:
            return True
        seen.add(id(self))
        return False

    async def sleep(delay: float, *args: Any, **kwargs: Any) -> Any:
        return await real_sleep(0 if delay == 3 else delay, *args, **kwargs)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(Request, "is_disconnected", is_disconnected)
        mp.setattr(asyncio, "sleep", sleep)
        resp = client.get(url)
    assert resp.status_code == 200, resp.status_code
    return resp.text


# ---------------------------------------------------------------------------
# The route matrix
# ---------------------------------------------------------------------------

# GET routes that are legitimately the same for every user, scoped or not,
# because they expose no estate data. Each needs a reason.
_ESTATE_WIDE: dict[str, str] = {
    "/openapi.json": "API schema; no estate data",
    "/docs": "Swagger UI shell; no estate data",
    "/docs/oauth2-redirect": "Swagger UI helper; no estate data",
    "/redoc": "ReDoc shell; no estate data",
    "/favicon.ico": "static asset",
    "/healthz": "liveness probe; no estate data",
    "/readyz": "readiness probe; no estate data",
    "/api/health": (
        "scheduler health: reports the time and status of the estate's most"
        " recent scan attempt, with no identifiers; a scoped user learns that"
        " the scheduler ran, not what it scanned"
    ),
    "/login": "login form",
    "/auth/login": "OAuth start; no provider configured here",
    "/auth/callback": "OAuth callback; no provider configured here",
    "/caa-check/{domain}": (
        "live CAA lookup for a caller-supplied public DNS name; returns DNS data,"
        " not estate data (the resolver is stubbed here)"
    ),
}


def _with_prefix(ids: dict[str, str], prefix: str) -> list[str]:
    return [v for k, v in ids.items() if k.startswith(prefix)]


def _requests_for(path: str, est: _Estate) -> tuple[list[str], list[tuple[str, str]]]:
    """Concrete URLs for *path*: (in_scope_urls, [(out_of_scope_url, out_id)]).

    Out-of-scope URLs are paired with the id they use so the comparison can
    substitute the nonexistent id for it.
    """
    ins, outs = est.in_scope, est.out_of_scope
    in_urls: list[str] = []
    out_urls: list[tuple[str, str]] = []

    def per(param: str, in_vals: list[str], out_vals: list[str], suffix: str = "") -> None:
        for v in in_vals:
            in_urls.append(path.replace(param, quote(v, safe="")) + suffix)
        for v in out_vals:
            out_urls.append((path.replace(param, quote(v, safe="")) + suffix, v))

    if "{cert_id}" in path:
        per("{cert_id}", _with_prefix(ins, "cert:"), _with_prefix(outs, "cert:"))
    elif "{host_id}" in path:
        per("{host_id}", _with_prefix(ins, "host:"), _with_prefix(outs, "host:"))
    elif "{group_id}" in path:
        per("{group_id}", _with_prefix(ins, "group:"), _with_prefix(outs, "group:"))
    elif "{hostname}" in path:
        mine = {h.hostname for h in _PAYMENTS}
        for h in _PAYMENTS:
            in_urls.append(path.replace("{hostname}", quote(h.hostname, safe="")))
            in_urls.append(
                path.replace("{hostname}", quote(h.hostname, safe="")) + f"?port={h.port}"
            )
        for h in _OTHER:
            url = path.replace("{hostname}", quote(h.hostname, safe=""))
            if h.hostname not in mine:
                out_urls.append((url, h.hostname))
            # A name shared with an in-scope endpoint is out of scope only
            # at the other port.
            out_urls.append((f"{url}?port={h.port}", h.hostname))
    elif "{pivot}" in path:
        groups = {
            "issuer": ([_PAYMENTS_CA_CN, f"CN={_PAYMENTS_CA_CN}"],
                       [_OTHER_CA_CN, f"CN={_OTHER_CA_CN}", _UNTAGGED_CA_CN,
                        f"CN={_UNTAGGED_CA_CN}"]),
            "owner": (["pay-owner"], ["hrops-owner", "shared-owner"]),
            "renewal_method": (["ACME", ""], ["Manual"]),
        }
        for pivot, (in_keys, out_keys) in groups.items():
            base = path.replace("{pivot}", pivot)
            for k in in_keys:
                in_urls.append(base.replace("{group_key:path}", quote(k, safe="")))
            for k in out_keys:
                out_urls.append((base.replace("{group_key:path}", quote(k, safe="")), k))
    else:
        in_urls.append(path)
        in_urls.extend(f"{path}?{q}" for q in _QUERY_VARIANTS.get(path, ()))
    return in_urls, out_urls


# Query-string variants worth requesting in addition to the bare path: views,
# filters, report scopes, partial renders. Tags are given in mixed case.
_QUERY_VARIANTS: dict[str, tuple[str, ...]] = {
    "/browse": (
        "grouped=0", "grouped=1", "source=uploaded", "source=scanned",
        "urgency=critical", "urgency=expired", "view=calendar", "view=issuer",
        "view=owner", "view=renewal_method", "q=test", "q=hrops", "q=pay",
        "sort_by=name&sort_order=desc", "page=2",
    ),
    "/alerts": ("filter_type=unread", "filter_type=critical", "filter_type=warning",
                "page=2"),
    "/api/alerts": ("limit=500",),
    "/api/certificates": ("limit=500",),
    "/api/hosts": ("limit=500",),
    "/api/calendar": ("bucket=week", "bucket=day", "bucket=month"),
    "/api/events": ("limit=500", "event_type=cert_changed", "source=scan"),
    "/api/events/failed": ("limit=500",),
    "/api/audit": ("target_type=host", "target_type=certificate", "limit=500"),
    "/audit": ("target_type=host",),
    "/api/trends/grades": ("days=365",),
    "/api/trends/tls-versions": ("days=365",),
    "/api/reports/expiring.csv": ("days=365",),
    "/api/reports/policy-violations": ("format=csv", "limit=500"),
    "/api/reports/compliance.json": (
        "tag=payments", "tag=PAYMENTS", "tag=hr-ops", "tag=payments,hr-ops",
    ),
    "/api/reports/compliance.csv": ("tag=payments", "tag=hr-ops", "tag=payments,hr-ops"),
    "/reports/compliance": (
        "tag=payments", "tag=Payments", "tag=hr-ops", "tag=payments,hr-ops",
    ),
    "/scan-history": ("page=2",),
    "/settings": ("tab=trust-anchors", "tab=tags", "tab=roles"),
    "/insights": ("tab=trends",),
    "/setup": ("step=2",),
}

# The SSE stream never ends; it is read for its first burst instead.
_STREAMS = frozenset({"/api/events/stream"})


def _get_routes() -> list[str]:
    from cert_watch.app import create_app

    return sorted({
        r.path for r in _walk(create_app().routes)
        if "GET" in (getattr(r, "methods", None) or set())
    })


@contextlib.contextmanager
def _client(
    data_dir: Path, username: str, scans: list[tuple[str, int]] | None = None
) -> Iterator[TestClient]:
    """A logged-in client against the app rooted at *data_dir*.

    Nothing here reaches the network: DNS resolves every name to one public
    address, and a scan is recorded in *scans* (as ``(hostname, port)``) and
    reported as failed instead of connecting.
    """
    import cert_watch.routes.auth as auth_routes
    import cert_watch.routes.hosts as hosts_routes
    import cert_watch.security.csrf as csrf_mod
    import cert_watch.services.host_management as host_management

    recorded = scans if scans is not None else []

    async def _route_scan(hostname: str, port: int, *a: Any, **k: Any) -> tuple[str, str]:
        recorded.append((hostname, port))
        return "scan_error", "scanning disabled in the read-scope matrix"

    async def _service_scan(hostname: str, port: int, *a: Any, **k: Any) -> Any:
        recorded.append((hostname, port))
        return host_management.ScanResult("scan_error", "scanning disabled in the matrix")

    def _resolve(hostname: str, port: int, **k: Any) -> list[tuple[int, tuple[Any, ...]]]:
        return [(socket.AF_INET, ("93.184.216.34", port))]

    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("CERT_WATCH_DATA_DIR", str(data_dir))
        mp.setenv("CERT_WATCH_COOKIE_SECURE", "0")
        mp.setenv("CERT_WATCH_ROLE_MAP", _ROLE_MAP)
        mp.delenv("CERT_WATCH_METRICS_TOKEN", raising=False)
        mp.setattr(csrf_mod, "_COOKIE_SECURE", False)
        # The scheduler would scan the pending hosts and change the estate
        # between the baseline and full runs.
        mp.setattr("cert_watch.scheduler.Scheduler.start", lambda self: None)
        # The matrix makes hundreds of requests from one client address. Route
        # modules import check_rate_limit by name, so patch each binding.
        mp.setattr("cert_watch.security.ratelimit.check_rate_limit", lambda *a, **k: True)
        for name, module in list(sys.modules.items()):
            if name.startswith("cert_watch.routes") and hasattr(module, "check_rate_limit"):
                mp.setattr(module, "check_rate_limit", lambda *a, **k: True)
        mp.setattr(hosts_routes, "_scan_and_store", _route_scan)
        mp.setattr(host_management, "_scan_and_store", _service_scan)
        mp.setattr("cert_watch.scan_resolver.resolve_hostname", _resolve)
        mp.setattr(auth_routes, "_COOKIE_SECURE", False)
        mp.setattr("cert_watch.caa_check.check_caa", _no_caa)
        with TestClient(_app(data_dir), follow_redirects=False) as client:
            if username == _DIRECTORY_USER:
                from cert_watch.auth import create_session

                client.cookies.set(SESSION_COOKIE, create_session(
                    username, client.app.state.security, roles=[_DIRECTORY_ROLE],
                ))
                yield client
                return
            page = client.get("/login").text
            m = re.search(r'name="_csrf_token" value="([^"]+)"', page)
            client.cookies.delete(SESSION_COOKIE)
            r = client.post("/login", data={
                "username": username, "password": _PW,
                "_csrf_token": m.group(1) if m else "",
            })
            assert r.status_code == 303 and r.headers["location"] == "/", (
                r.status_code, r.headers.get("location"))
            yield client


@dataclass
class _Run:
    # url -> snapshot, per (db, user)
    baseline: dict[str, _Snapshot] = field(default_factory=dict)
    full: dict[str, _Snapshot] = field(default_factory=dict)
    # out-of-scope url -> (snapshot, snapshot of the same url with a nonexistent id)
    out_vs_missing: dict[str, tuple[_Snapshot, _Snapshot]] = field(default_factory=dict)
    raw_full: dict[str, str] = field(default_factory=dict)


def _fetch(
    client: TestClient, url: str, ids: dict[str, str] | None = None
) -> tuple[_Snapshot, str]:
    path = url.split("?")[0]
    if path in _STREAMS:
        text = _read_sse(client, url)
        return _Snapshot(200, "text/event-stream", "", _normalize(text, ids)), text
    resp = client.get(url)
    return _snapshot(resp, ids), resp.text + "\n" + resp.headers.get("location", "")


@pytest.fixture(scope="module")
def runs(estate: _Estate) -> dict[str, _Run]:
    routes = [p for p in _get_routes() if p not in _ESTATE_WIDE]
    plan = {p: _requests_for(p, estate) for p in routes}
    out: dict[str, _Run] = {u: _Run() for u in _USERS}
    for user in _USERS:
        run = out[user]
        with _client(estate.baseline_dir, user) as client:
            for in_urls, _ in plan.values():
                for url in in_urls:
                    run.baseline[url] = _fetch(client, url)[0]
        with _client(estate.full_dir, user) as client:
            for in_urls, out_urls in plan.values():
                for url in in_urls:
                    snap, raw = _fetch(client, url)
                    run.full[url] = snap
                    run.raw_full[url] = raw
                for url, out_id in out_urls:
                    snap, raw = _fetch(client, url, {"<ID>": out_id})
                    # Routes echo the requested key back ({"group_key": ...});
                    # the caller supplied it, so it is not a leak. The
                    # differential test covers what comes back with it.
                    run.raw_full[url] = raw.replace(out_id, "<ID>").replace(
                        quote(out_id, safe=""), "<ID>")
                    missing_url = url.replace(quote(out_id, safe=""), _NONEXISTENT)
                    missing = _fetch(client, missing_url, {"<ID>": _NONEXISTENT})[0]
                    run.out_vs_missing[url] = (snap, missing)
    return out


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("user", _USERS)
def test_matrix_requests_actually_ran(runs: dict[str, _Run], user: str) -> None:
    """Guard the guards: a matrix answered by 429s, 5xx or login redirects
    proves nothing."""
    run = runs[user]
    snaps = [*run.full.values(), *(s for pair in run.out_vs_missing.values() for s in pair)]
    bad = sorted(
        u for u, s in [*run.full.items(), *((u, p[0]) for u, p in run.out_vs_missing.items())]
        if s.status == 429 or s.status >= 500 or s.location.startswith("/login")
    )
    assert not bad, bad
    assert sum(s.status == 200 for s in snaps) >= 100
    assert len(run.out_vs_missing) >= 50


def test_every_get_route_is_in_the_matrix() -> None:
    """A new GET route must be requested by the matrix or allowlisted."""
    routes = set(_get_routes())
    assert routes, "route inventory is empty"
    stale = set(_ESTATE_WIDE) - routes
    assert not stale, f"allowlist names routes that no longer exist: {sorted(stale)}"
    assert set(_QUERY_VARIANTS) <= routes, set(_QUERY_VARIANTS) - routes
    # Every non-allowlisted route produces at least one request.
    est = _Estate(Path("."), Path("."), {"cert:x": "c", "host:x": "h", "group:x": "g"}, {})
    empty = [p for p in routes - set(_ESTATE_WIDE) if not _requests_for(p, est)[0]]
    assert not empty, f"routes the matrix never requests: {sorted(empty)}"


@pytest.mark.parametrize("user", _USERS)
def test_no_out_of_scope_identifier_in_any_response(runs: dict[str, _Run], user: str) -> None:
    leaks: dict[str, list[str]] = {}
    for url, raw in runs[user].raw_full.items():
        folded = raw.casefold()
        # A search box echoes the user's own query; that is not a leak (the
        # differential test covers what the search returns).
        m = re.search(r"[?&]q=([^&]+)", url)
        if m:
            folded = folded.replace(m.group(1).casefold(), "")
        found = [m for m in _FORBIDDEN_MARKERS if m.casefold() in folded]
        if found:
            leaks[url] = found
    assert not leaks, "out-of-scope identifiers visible to a scoped user:\n" + "\n".join(
        f"  {u}: {', '.join(v)}" for u, v in sorted(leaks.items())
    )


@pytest.mark.parametrize("user", _USERS)
def test_out_of_scope_data_changes_no_response(runs: dict[str, _Run], user: str) -> None:
    run = runs[user]
    differing = sorted(u for u in run.baseline if run.baseline[u] != run.full[u])
    detail = []
    for u in differing:
        b, f = run.baseline[u], run.full[u]
        if (b.status, b.location) != (f.status, f.location):
            detail.append(f"  {u}: status {b.status}->{f.status} {b.location!r}->{f.location!r}")
        else:
            detail.append(f"  {u}: body differs ({_first_diff(b.body, f.body)})")
    assert not differing, (
        "responses a payments-scoped user gets change when out-of-scope data is"
        " added:\n" + "\n".join(detail)
    )


@pytest.mark.parametrize("user", _USERS)
def test_out_of_scope_ids_answer_like_missing_ids(runs: dict[str, _Run], user: str) -> None:
    run = runs[user]
    differing = sorted(u for u, (o, m) in run.out_vs_missing.items() if o != m)
    detail = []
    for u in differing:
        o, m = run.out_vs_missing[u]
        detail.append(
            f"  {u}: {o.status} vs missing {m.status}"
            + ("" if o.status != m.status else f" ({_first_diff(m.body, o.body)})")
        )
    assert not differing, (
        "out-of-scope ids answer differently from nonexistent ids:\n" + "\n".join(detail)
    )


def _first_diff(a: str, b: str) -> str:
    i = next((i for i, (x, y) in enumerate(zip(a, b, strict=False)) if x != y), min(len(a), len(b)))
    return f"at {i}: {a[max(0, i - 60):i + 60]!r} vs {b[max(0, i - 60):i + 60]!r}"


# ---------------------------------------------------------------------------
# Specific regressions from #112
# ---------------------------------------------------------------------------

_PAYMENTS_LEAVES = sum(h.scanned for h in _PAYMENTS) + 1  # + the uploaded cert


@pytest.mark.parametrize("user", _USERS)
def test_posture_shows_only_in_scope_weak_primitives(runs: dict[str, _Run], user: str) -> None:
    body = runs[user].full["/posture"].body
    assert runs[user].full["/posture"].status == 200
    assert "pay-api.payments.test" in body  # the in-scope RSA-1024 leaf is listed
    for host in ("hrops-portal.hrteam.test", "hrops-ldap.hrteam.test", "untagged-a.shared.test"):
        assert host not in body


@pytest.mark.parametrize("user", _USERS)
def test_compliance_link_from_posture_renders_a_scoped_report(
    runs: dict[str, _Run], user: str
) -> None:
    """The Posture menu links to /reports/compliance with no tag. A scoped user
    used to get a bare-text 403 there; now it is their team's report."""
    snap = runs[user].full["/reports/compliance"]
    assert (snap.status, snap.content_type) == (200, "text/html")
    assert "your team scope: payments" in snap.body.casefold()
    assert "pay-api.payments.test" in snap.body

    api = runs[user].full["/api/reports/compliance.json"]
    assert (api.status, api.content_type) == (200, "application/json")
    import json

    report = json.loads(api.body)
    assert report["scope_tag"].casefold() == "payments"
    assert report["total_certs"] == _PAYMENTS_LEAVES
    assert runs[user].full["/api/reports/compliance.csv"].status == 200


@pytest.mark.parametrize("user", _USERS)
def test_out_of_scope_compliance_tag_is_a_page_not_bare_text(
    runs: dict[str, _Run], estate: _Estate, user: str
) -> None:
    snap = runs[user].full["/reports/compliance?tag=hr-ops"]
    assert snap.status == 303
    assert snap.location.startswith("/reports/compliance?error=")
    with _client(estate.full_dir, user) as client:
        page = client.get(snap.location)
        # A tag that exists nowhere answers exactly like another team's tag.
        missing = client.get("/reports/compliance?tag=no-such-team")
    assert page.status_code == 200
    assert page.headers["content-type"].startswith("text/html")
    assert "outside your team scope" in page.text
    assert "your team scope: payments" in page.text.casefold()
    assert missing.status_code == 303
    assert missing.headers["location"] == snap.location


def test_unscoped_admin_compliance_report_still_covers_the_estate(estate: _Estate) -> None:
    from cert_watch.compliance import build_compliance_report

    full = build_compliance_report(estate.full_dir / "cert-watch.sqlite3")
    scoped = build_compliance_report(
        estate.full_dir / "cert-watch.sqlite3", scope_tags=("PAYMENTS",)
    )
    assert full.scope_tag == "" and full.scope_description == "All monitored certificates"
    assert scoped.total_certs == _PAYMENTS_LEAVES < full.total_certs
    # A requested tag narrows within the scope; it never widens it.
    crossed = build_compliance_report(
        estate.full_dir / "cert-watch.sqlite3", scope_tag="hr-ops", scope_tags=("payments",)
    )
    assert crossed.total_certs == 0


def test_scoped_database_reads_match_case_insensitively(estate: _Estate) -> None:
    from cert_watch.crypto_posture import analyze_fleet_crypto
    from cert_watch.database import posture_grade_counts

    db = estate.full_dir / "cert-watch.sqlite3"
    everything = analyze_fleet_crypto(db)
    for scope in (("payments",), ("PAYMENTS",), ("Payments",)):
        mine = analyze_fleet_crypto(db, scope_tags=scope)
        assert mine.total == _PAYMENTS_LEAVES
        assert {c["hostname"] for c in mine.weak_certs} == {"pay-api.payments.test"}
        assert sum(posture_grade_counts(db, scope_tags=scope).values()) == sum(
            h.scanned for h in _PAYMENTS
        )
    assert everything.total > _PAYMENTS_LEAVES
    assert sum(posture_grade_counts(db).values()) > sum(h.scanned for h in _PAYMENTS)


# ---------------------------------------------------------------------------
# State-changing routes: an out-of-scope target answers like a missing one,
# changes nothing and scans nothing
# ---------------------------------------------------------------------------

# Path parameters that address estate data, and the out-of-scope labels each
# is tried with (see _ids for the label format). One host or certificate of
# every kind, so that the chain-cert, uploaded-cert and untagged paths are all
# exercised without sending every id through every route.
_TARGET_PARAMS: dict[str, tuple[str, ...]] = {
    "host_id": (
        "host:hrops-portal.hrteam.test:443",
        "host:dual.ports.test:443",  # the port another team monitors
        "host:untagged-a.shared.test:443",
    ),
    "cert_id": (
        "cert:leaf:scanned:hrops-portal.hrteam.test:",
        "cert:leaf:scanned:dual.ports.test:",
        "cert:chain:scanned:hrops-portal.hrteam.test:",
        "cert:leaf:uploaded::CN=hrops-upload.hrteam.test",
        "cert:leaf:scanned:untagged-a.shared.test:",
    ),
    "alert_id": ("alert:",),
    "group_id": ("group:hr-ops-alerts",),
}

# Path parameters of mutating routes that do not address estate data. Each
# needs a reason; a new parameter fails test_every_mutating_route_is_classified.
_NOT_ESTATE_TARGETS: dict[str, str] = {
    "anchor_id": "trust anchors are admin-only and estate-wide",
    "key_id": "API keys are admin-only account objects",
    "role_id": "roles are admin-only account objects",
    "user_id": "users are admin-only account objects",
}

# Bookkeeping tables a refused request may legitimately touch.
_NOT_ESTATE_TABLES = frozenset({"audit_log", "rate_limits", "session_versions", "sqlite_sequence"})


def _pick(ids: dict[str, str], prefix: str) -> str:
    matches = sorted(v for k, v in ids.items() if k.startswith(prefix))
    assert matches, f"no seeded id labelled {prefix!r}"
    return matches[0]


def _target_combos(path: str, est: _Estate) -> list[dict[str, str]]:
    """Every combination of out-of-scope ids for the target params in *path*."""
    names = [n for n in re.findall(r"{(\w+)}", path) if n in _TARGET_PARAMS]
    combos: list[dict[str, str]] = [{}]
    for name in names:
        values = [_pick(est.out_of_scope, p) for p in _TARGET_PARAMS[name]]
        combos = [{**c, name: v} for c in combos for v in values]
    return combos if names else []


def _db_state(db: Path) -> dict[str, list[dict[str, Any]]]:
    """Every row of every estate table, for before/after comparison."""
    import sqlite3

    from cert_watch.database.connection import _connect

    out: dict[str, list[dict[str, Any]]] = {}
    with _connect(db) as conn:
        names = [
            r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        ]
        for name in names:
            if name in _NOT_ESTATE_TABLES:
                continue
            try:
                rows = conn.execute(f'SELECT * FROM "{name}" ORDER BY rowid').fetchall()
            except sqlite3.OperationalError:
                rows = conn.execute(f'SELECT * FROM "{name}"').fetchall()
            out[name] = [dict(r) for r in rows]
    return out


def _copy_estate(src_dir: Path, dst_dir: Path) -> Path:
    from cert_watch.database.connection import _connect

    with _connect(src_dir / "cert-watch.sqlite3") as conn:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    shutil.copy(src_dir / "cert-watch.sqlite3", dst_dir / "cert-watch.sqlite3")
    return dst_dir / "cert-watch.sqlite3"


def _send(
    client: TestClient, method: str, url: str, route: Any, path: str,
    headers: dict[str, str], ids: dict[str, str],
) -> _Snapshot:
    resp = client.request(method, url, headers=headers, **_body_for(route, path))
    return _snapshot(resp, ids)


def _mutating_targets() -> list[tuple[str, str, Any]]:
    from cert_watch.app import create_app

    return [
        (m, p, r) for m, p, r in mutating_routes(create_app())
        if any(f"{{{name}}}" in p for name in _TARGET_PARAMS)
    ]


@dataclass
class _MutationRun:
    # "METHOD url" -> (out-of-scope snapshot, snapshot with the nonexistent id)
    out_vs_missing: dict[str, tuple[_Snapshot, _Snapshot]] = field(default_factory=dict)
    changed_tables: dict[str, list[str]] = field(default_factory=dict)
    scans: dict[str, list[tuple[str, int]]] = field(default_factory=dict)


@pytest.fixture(scope="module")
def mutations(estate: _Estate, tmp_path_factory: pytest.TempPathFactory) -> dict[str, _MutationRun]:
    routes = _mutating_targets()
    out: dict[str, _MutationRun] = {}
    for user in _USERS:
        data_dir = tmp_path_factory.mktemp(f"mutations-{user}")
        db = _copy_estate(estate.full_dir, data_dir)
        run = _MutationRun()
        scans: list[tuple[str, int]] = []
        with _client(data_dir, user, scans) as client:
            headers = _csrf_header(client)
            for method, path, route in routes:
                for combo in _target_combos(path, estate):
                    url, missing_url = path, path
                    for name, value in combo.items():
                        url = url.replace("{" + name + "}", value)
                        missing_url = missing_url.replace("{" + name + "}", _NONEXISTENT)
                    key = f"{method} {url}"
                    before = _db_state(db)
                    scans.clear()
                    snap = _send(
                        client, method, url, route, path, headers,
                        dict.fromkeys(combo.values(), "<ID>"),
                    )
                    after = _db_state(db)
                    run.changed_tables[key] = sorted(
                        t for t in before if before[t] != after.get(t)
                    )
                    run.scans[key] = list(scans)
                    missing = _send(
                        client, method, missing_url, route, path, headers,
                        {_NONEXISTENT: "<ID>"},
                    )
                    run.out_vs_missing[key] = (snap, missing)
        out[user] = run
    return out


def test_every_mutating_route_is_classified() -> None:
    """Every path parameter of a mutating route is an estate target the
    matrix exercises, or is allowlisted with a reason."""
    from cert_watch.app import create_app

    params = {
        name
        for _m, path, _r in mutating_routes(create_app())
        for name in re.findall(r"{(\w+)}", path)
    }
    unknown = params - set(_TARGET_PARAMS) - set(_NOT_ESTATE_TARGETS)
    assert not unknown, f"mutating routes with unclassified parameters: {sorted(unknown)}"
    stale = set(_NOT_ESTATE_TARGETS) - params
    assert not stale, f"allowlist names parameters no route uses: {sorted(stale)}"
    assert len(_mutating_targets()) >= 20


@pytest.mark.parametrize("user", _USERS)
def test_mutating_matrix_actually_ran(mutations: dict[str, _MutationRun], user: str) -> None:
    run = mutations[user]
    bad = sorted(
        k for k, (o, m) in run.out_vs_missing.items()
        for s in (o, m)
        if s.status == 429 or s.status >= 500 or s.location.startswith("/login")
        or ("csrf" in s.body.casefold()[:400] and s.status == 403)
    )
    assert not bad, bad
    assert len(run.out_vs_missing) >= 40


@pytest.mark.parametrize("user", _USERS)
def test_out_of_scope_mutation_targets_answer_like_missing_ids(
    mutations: dict[str, _MutationRun], user: str
) -> None:
    run = mutations[user]
    differing = sorted(k for k, (o, m) in run.out_vs_missing.items() if o != m)
    detail = []
    for k in differing:
        o, m = run.out_vs_missing[k]
        detail.append(
            f"  {k}: {o.status} {o.location!r} vs missing {m.status} {m.location!r}"
            + ("" if (o.status, o.location) != (m.status, m.location)
               else f" ({_first_diff(m.body, o.body)})")
        )
    assert not differing, (
        "state-changing routes answer differently for an out-of-scope id than for a"
        " nonexistent one:\n" + "\n".join(detail)
    )


@pytest.mark.parametrize("user", _USERS)
def test_out_of_scope_mutation_targets_are_untouched_and_unscanned(
    mutations: dict[str, _MutationRun], user: str
) -> None:
    run = mutations[user]
    changed = {k: v for k, v in run.changed_tables.items() if v}
    assert not changed, "refused requests changed the estate:\n" + "\n".join(
        f"  {k}: {', '.join(v)}" for k, v in sorted(changed.items())
    )
    scanned = {k: v for k, v in run.scans.items() if v}
    assert not scanned, "refused requests started scans:\n" + "\n".join(
        f"  {k}: {v}" for k, v in sorted(scanned.items())
    )


# ---------------------------------------------------------------------------
# Specific regressions from the #116 review
# ---------------------------------------------------------------------------


def _endpoints(events: list[dict[str, Any]]) -> set[tuple[Any, Any]]:
    payloads = [json.loads(e["payload"]) for e in events if e.get("payload")]
    return {(p.get("hostname"), p.get("port")) for p in payloads}


def test_events_are_scoped_per_endpoint_not_per_hostname(estate: _Estate, tmp_path: Path) -> None:
    """``dual.ports.test`` is monitored on 8443 by payments and on 443 by
    hr-ops. Events name an endpoint; matching the hostname alone leaked the
    other port's events (finding 1)."""
    from cert_watch.database.connection import _connect
    from cert_watch.events import get_events, get_failed_deliveries

    db = _copy_estate(estate.full_dir, tmp_path)
    pay_leaf = _pick(estate.in_scope, "cert:leaf:scanned:dual.ports.test:")
    with _connect(db) as conn:
        # Failed deliveries are filtered by the same rule.
        conn.execute("UPDATE event_log SET delivery_status = 'failed'")
        for payload in (
            # A legacy event with no port cannot be placed on an endpoint: it
            # is not shown on the strength of the hostname alone...
            {"hostname": "dual.ports.test", "error_message": "portless HR-Ops event"},
            # ...but is shown when its certificate is in scope.
            {"hostname": "dual.ports.test", "cert_id": pay_leaf, "note": "via cert"},
        ):
            conn.execute(
                "INSERT INTO event_log (event_type, timestamp, source, payload,"
                " delivery_status, error_message, created_at)"
                " VALUES ('scan_failed', ?, 'scan', ?, 'failed', NULL, ?)",
                (_NOW.isoformat(), json.dumps(payload), _NOW.isoformat()),
            )
        conn.commit()

    everything = get_events(db, limit=1000)
    assert {("dual.ports.test", 443), ("dual.ports.test", 8443)} <= _endpoints(everything)
    for scope in (("payments",), ("PAYMENTS",)):
        for events in (
            get_events(db, limit=1000, scope_tags=scope),
            get_failed_deliveries(db, limit=1000, scope_tags=scope),
        ):
            endpoints = _endpoints(events)
            assert ("dual.ports.test", 8443) in endpoints
            assert ("dual.ports.test", 443) not in endpoints
            assert ("dual.ports.test", None) in endpoints  # only the via-cert row
            blob = json.dumps(events).casefold()
            assert "via cert" in blob
            for marker in _FORBIDDEN_MARKERS:
                assert marker.casefold() not in blob, marker
            assert all(
                hn is None or hn in {h.hostname for h in _PAYMENTS} for hn, _ in endpoints
            )


@pytest.mark.parametrize("user", ("pay-operator", _DIRECTORY_USER))
def test_adding_an_endpoint_another_team_monitors_is_refused(
    estate: _Estate, tmp_path_factory: pytest.TempPathFactory, user: str
) -> None:
    """``repo.add`` is idempotent, so adding an existing ``hostname:port``
    used to return the other team's host id and scan it (finding 2). Every
    add path -- JSON, form, CSV import by JSON and by form -- must refuse
    without touching or scanning the existing row."""
    from urllib.parse import unquote

    from cert_watch.database import SqliteHostRepository

    data_dir = tmp_path_factory.mktemp(f"add-existing-{user}")
    db = _copy_estate(estate.full_dir, data_dir)
    other_id = estate.out_of_scope["host:dual.ports.test:443"]
    hrops_id = estate.out_of_scope["host:hrops-portal.hrteam.test:443"]
    mine = estate.in_scope["host:pay-web.payments.test:443"]
    scans: list[tuple[str, int]] = []
    with _client(data_dir, user, scans) as client:
        headers = _csrf_header(client)
        before = _db_state(db)
        seen = ""

        # Every spelling of another team's endpoint: as stored, upper-case,
        # trailing dot, Unicode for a stored A-label, and expanded / bracketed
        # IPv6 for a stored compressed literal.
        for spelling in (
            "dual.ports.test", "DUAL.ports.test", "dual.ports.test.", "Dual.Ports.Test.",
            "hrops-portal.hrteam.test", "HROPS-PORTAL.hrteam.test",
            "büro.hrteam.test".encode("idna").decode("ascii"),
            "büro.hrteam.test", "BÜRO.hrteam.test.",
            "2001:db8::1", "2001:0db8:0:0:0:0:0:1", "2001:0DB8::1", "[2001:db8::1]",
        ):
            r = client.post(
                "/api/hosts", json={"hostname": spelling, "port": 443}, headers=headers
            )
            seen += r.text + r.headers.get("location", "")
            assert r.status_code == 403, (spelling, r.text)
            assert "outside your team scope" in r.json()["error"]
        # common_ports covers 443 (theirs) and 8443 (ours): refused as a whole.
        for spelling in ("dual.ports.test", "DUAL.PORTS.TEST."):
            r = client.post(
                "/api/hosts", json={"hostname": spelling, "common_ports": True},
                headers=headers,
            )
            seen += r.text
            assert r.status_code == 403, (spelling, r.text)
        for spelling in ("hrops-portal.hrteam.test", "Hrops-Portal.hrteam.test.",
                         "büro.hrteam.test", "[2001:0db8::1]"):
            r = client.post(
                "/hosts", data={"hostname": spelling, "port": "0443"}, headers=headers,
            )
            seen += r.headers.get("location", "")
            assert r.status_code == 303, spelling
            assert "outside your team scope" in unquote(r.headers["location"]), spelling

        csv = (
            "hostname,port\n"
            "hrops-mail.hrteam.test,443\n"
            "untagged-a.shared.test,443\n"
            '"HROPS-MAIL.hrteam.test.","0443"\n'
            '"büro.hrteam.test",443\n'
            '"2001:0db8:0:0:0:0:0:1",443\n'
        )
        r = client.post(
            "/api/hosts/import", headers=headers,
            files={"file": ("hosts.csv", csv.encode(), "text/csv")},
        )
        seen += r.text
        assert r.status_code == 400, r.text
        assert r.json()["imported"] == 0
        assert len(r.json()["errors"]) == 5
        assert all("outside your team scope" in e for e in r.json()["errors"])
        r = client.post(
            "/hosts/import", headers=headers,
            files={"file": ("hosts.csv", csv.encode(), "text/csv")},
        )
        seen += r.headers.get("location", "")
        assert r.status_code == 303
        assert "Import failed" in unquote(r.headers["location"])

        for label, value in estate.out_of_scope.items():
            if label.startswith("host:"):
                assert value not in seen, label
        assert other_id not in seen and hrops_id not in seen
        assert _db_state(db) == before, "a refused add changed the estate"
        assert scans == [], scans

        # The same operator re-adding their own endpoint keeps the idempotent
        # behaviour, and a fresh endpoint is created and scanned.
        r = client.post(
            "/api/hosts", json={"hostname": "pay-web.payments.test", "port": 443},
            headers=headers,
        )
        assert r.status_code == 201 and r.json()["ids"] == [mine], r.text
        r = client.post(
            "/api/hosts", json={"hostname": "Pay-New.payments.test.", "port": 443},
            headers=headers,
        )
        assert r.status_code == 201 and r.json()["ids"] != [mine], r.text
        # ...stored, resolved and scanned in canonical form.
        assert scans == [("pay-web.payments.test", 443), ("pay-new.payments.test", 443)]
        new_host = SqliteHostRepository(db).get(r.json()["ids"][0])
        assert new_host is not None and new_host.hostname == "pay-new.payments.test"


@pytest.mark.parametrize("user", ("pay-operator", _DIRECTORY_USER))
def test_deleting_an_endpoint_leaves_the_same_name_on_another_port_untouched(
    estate: _Estate, tmp_path_factory: pytest.TempPathFactory, user: str
) -> None:
    """Deleting ``dual.ports.test:8443`` (ours) must not touch a single row of
    ``dual.ports.test:443`` (hr-ops), in any table. ``event_log`` rows were
    deleted by hostname alone (#116 review)."""
    data_dir = tmp_path_factory.mktemp(f"delete-shared-name-{user}")
    db = _copy_estate(estate.full_dir, data_dir)
    mine = estate.in_scope["host:dual.ports.test:8443"]
    my_certs = {v for k, v in estate.in_scope.items() if k.startswith("cert:") and
                ":dual.ports.test:" in k}
    my_alerts = {v for k, v in estate.in_scope.items() if k.startswith("alert:") and
                 any(c in k for c in my_certs)}
    mine_ids = {mine, *my_certs, *my_alerts}
    with _client(data_dir, user) as client:
        before = _db_state(db)
        r = client.request("DELETE", f"/api/hosts/{mine}", headers=_csrf_header(client))
        assert r.status_code == 200, r.text
        after = _db_state(db)
    def is_mine(table: str, row: dict[str, Any]) -> bool:
        if table == "event_log":
            payload = json.loads(row["payload"])
            return payload.get("port") == 8443 or payload.get("cert_id") in my_certs
        return row.get("port") == 8443 or bool(set(map(str, row.values())) & mine_ids)

    for table, rows in before.items():
        added = [row for row in after[table] if row not in rows]
        assert not added, (table, added)
        removed = [row for row in rows if row not in after[table]]
        for row in removed:
            assert is_mine(table, row), (
                f"{table}: a row of another endpoint was deleted: {row!r}"
            )
    # The deletion did happen.
    assert len(before["hosts"]) == len(after["hosts"]) + 1
    assert len(before["event_log"]) > len(after["event_log"])
    survivors = [json.loads(row["payload"]) for row in after["event_log"]]
    assert any(
        p.get("hostname") == "dual.ports.test" and p.get("port") == 443 for p in survivors
    ), "hr-ops's dual.ports.test:443 events must survive"


@pytest.mark.parametrize("user", ("pay-operator", _DIRECTORY_USER))
def test_bulk_routes_act_only_inside_the_scope(
    estate: _Estate, tmp_path_factory: pytest.TempPathFactory, user: str
) -> None:
    """Scan-all and mark-all-read take no id: they must cover exactly the
    caller's endpoints and alerts."""
    data_dir = tmp_path_factory.mktemp(f"bulk-{user}")
    db = _copy_estate(estate.full_dir, data_dir)
    in_scope = {(h.hostname, h.port) for h in _PAYMENTS}
    scans: list[tuple[str, int]] = []
    with _client(data_dir, user, scans) as client:
        headers = _csrf_header(client)
        before = _db_state(db)
        r = client.post("/api/hosts/scan", headers=headers)
        assert r.status_code == 200, r.text
        assert set(scans) == in_scope and len(scans) == len(in_scope)
        scans.clear()
        r = client.post("/hosts/all/scan", headers=headers)
        assert r.status_code == 303, r.text
        assert set(scans) == in_scope and len(scans) == len(in_scope)

        r = client.post("/api/alerts/mark-all-read", headers=headers)
        assert r.status_code == 200, r.text
        r = client.post("/alerts/mark-all-read", headers=headers)
        assert r.status_code == 303, r.text
        after = _db_state(db)
    out_alerts = {v for k, v in estate.out_of_scope.items() if k.startswith("alert:")}
    out_hosts = {v for k, v in estate.out_of_scope.items() if k.startswith("host:")}
    assert out_alerts and out_hosts
    for table in ("alerts", "scan_history", "event_log", "hosts", "certificates"):
        changed = [row for row in after[table] if row not in before[table]]
        for row in changed:
            values = set(map(str, row.values()))
            assert not (values & (out_alerts | out_hosts)), (table, row)
            if table == "scan_history":
                assert (row["hostname"], row["port"]) in in_scope, row
            elif table == "event_log":
                payload = json.loads(row["payload"])
                assert (payload.get("hostname"), payload.get("port")) in in_scope, row


# Mutating routes that take no estate id. Each needs a reason; a new route
# fails test_every_mutating_route_is_classified until it is listed here, in
# _TARGET_PARAMS (id-addressed) or in _CREATE_ROUTES (probed with aliases).
_CREATE_ROUTES = frozenset({"/hosts", "/api/hosts", "/hosts/import", "/api/hosts/import"})
_BULK_ROUTES = frozenset({
    "/hosts/all/scan", "/api/hosts/scan", "/alerts/mark-all-read", "/api/alerts/mark-all-read",
})
_NON_TARGET_MUTATIONS: dict[str, str] = {
    "/login": "authentication",
    "/auth/logout": "authentication",
    "/setup": "first-run setup; refused once setup_complete",
    "/upload": "creates an uploaded certificate carrying the caller's scope tag",
    "/api/certificates/upload": "creates an uploaded certificate carrying the caller's scope tag",
    "/trust-anchors": "admin-only, estate-wide",
    "/api/trust-anchors": "admin-only, estate-wide",
    "/api/policy": "admin-only, estate-wide",
    "/api/webhook/test": "sends a test webhook; touches no estate data",
    "/alerts/flush": "flushes the caller's own scope of the alert queue (scope_tags)",
    "/api/alert-groups": "admin-only",
    "/api/api-keys": "admin-only account object",
    "/settings/api-keys": "admin-only account object",
    "/settings/alert-groups": "admin-only",
    "/settings/change-password": "the caller's own account",
    "/settings/smtp": "admin-only settings",
    "/settings/test-smtp": "admin-only settings",
    "/settings/alerts": "admin-only settings",
    "/settings/policy": "admin-only settings",
    "/settings/events": "admin-only settings",
    "/settings/auth": "admin-only settings",
    "/settings/ldap-role-map": "admin-only settings",
    "/settings/test-ldap": "admin-only settings",
    "/settings/pin-ldap-ca": "admin-only settings",
    "/settings/roles": "admin-only account object",
    "/settings/users": "admin-only account object",
}


def test_every_mutating_route_is_covered_or_allowlisted() -> None:
    from cert_watch.app import create_app

    paths = {p for _m, p, _r in mutating_routes(create_app())}
    targeted = {p for p in paths if any(f"{{{n}}}" in p for n in _TARGET_PARAMS)}
    other_param = {
        p for p in paths - targeted
        if any(f"{{{n}}}" in p for n in _NOT_ESTATE_TARGETS)
    }
    plain = paths - targeted - other_param
    unclassified = plain - _CREATE_ROUTES - _BULK_ROUTES - set(_NON_TARGET_MUTATIONS)
    assert not unclassified, f"mutating routes without scope coverage: {sorted(unclassified)}"
    stale = (_CREATE_ROUTES | _BULK_ROUTES | set(_NON_TARGET_MUTATIONS)) - plain
    assert not stale, f"allowlist names routes that no longer exist: {sorted(stale)}"


def test_report_tag_filter_must_be_one_tag_for_everyone() -> None:
    """``tag=payments,hr-ops`` passed the scope check on the overlapping part
    and was then filtered as one literal tag, yielding a signed, empty report
    named for the other team (#116 review). A list is refused for admins too."""
    from types import SimpleNamespace

    from cert_watch.routes._scoped import enforce_scope_tag

    def req(**ctx: Any) -> Any:
        return SimpleNamespace(state=SimpleNamespace(auth_context=SimpleNamespace(**ctx)))

    admin = req(is_admin=True, scope_tag="")
    unscoped = req(is_admin=False, scope_tag="")
    scoped = req(is_admin=False, scope_tag="payments")
    for r in (admin, unscoped, scoped):
        assert enforce_scope_tag(r, "payments,hr-ops") == "requested tag must be a single tag"
        assert enforce_scope_tag(r, "payments, HR-Ops") == "requested tag must be a single tag"
        assert enforce_scope_tag(r, "payments") is None
        assert enforce_scope_tag(r, "") is None
    assert enforce_scope_tag(scoped, "hr-ops") == "requested tag is outside your team scope"
    assert enforce_scope_tag(admin, "hr-ops") is None


def test_directory_user_is_scoped_through_the_same_path(runs: dict[str, _Run]) -> None:
    """The role-map session resolved to the scoped operator role, not to a
    full-access or unscoped context: its report is the team's report."""
    snap = runs[_DIRECTORY_USER].full["/api/reports/compliance.json"]
    assert snap.status == 200
    assert json.loads(snap.body)["scope_tag"].casefold() == "payments"
    assert runs[_DIRECTORY_USER].full["/settings"].location.startswith("/")  # not admin
