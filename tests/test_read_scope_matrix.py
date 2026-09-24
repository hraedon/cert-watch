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
"""

from __future__ import annotations

import contextlib
import datetime as dt
import re
import shutil
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
from tests._route_inventory import _walk

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
    *(h.hostname for h in _OTHER),
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
                h.hostname, 443, tags=h.tags, owner_name=h.owner,
                renewal_method=h.renewal_method,
            )
            if h.failed_scan:
                record_scan_history(db, ScanHistory(
                    hostname=h.hostname, port=443, status="failure",
                    error_message=f"connection refused by {h.hostname}",
                ))
            if not h.scanned:
                continue
            scans = 2 if h.rescan else 1
            for i in range(scans):
                leaf = _model(_leaf(h.hostname, h.sans, h.days + i, ca, weak=h.weak))
                entry = ScannedEntry(
                    host=h.hostname, port=443, leaf=leaf, chain=[ca_model],
                    protocol_version="TLSv1.2" if h.weak else "TLSv1.3",
                    scanned_at=_NOW - dt.timedelta(days=scans - i),
                )
                store_scanned(entry, db, _posture_eval=_evaluate_posture(db, entry))
                record_scan_history(db, ScanHistory(
                    hostname=h.hostname, port=443, status="success",
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
        for r in conn.execute("SELECT id, hostname FROM hosts"):
            out[f"host:{r['hostname']}"] = r["id"]
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


_USERS = ("pay-viewer", "pay-operator")


@dataclass(frozen=True)
class _Snapshot:
    status: int
    content_type: str
    location: str
    body: str


# Per-request noise that legitimately differs between two otherwise identical
# requests. Everything else in a response must match.
_NOISE: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r'(name="_csrf_token"\s+value=")[^"]*'), r"\1<csrf>"),
    (re.compile(r'(name="csrf-token"\s+content=")[^"]*'), r"\1<csrf>"),
    (re.compile(r'(nonce=")[^"]*'), r"\1<nonce>"),
    (re.compile(r'(data-csrf=")[^"]*'), r"\1<csrf>"),
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?"),
     "<ts>"),
    (re.compile(r"\b[0-9a-fA-F]{32,}\b"), "<hex>"),
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
        in_hosts = [h.hostname for h in _PAYMENTS]
        out_hosts = [h.hostname for h in _OTHER]
        per("{hostname}", in_hosts, out_hosts)
        per("{hostname}", in_hosts, out_hosts, "?port=443")
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
    "/api/reports/compliance.json": ("tag=payments", "tag=PAYMENTS", "tag=hr-ops"),
    "/api/reports/compliance.csv": ("tag=payments", "tag=hr-ops"),
    "/reports/compliance": ("tag=payments", "tag=Payments", "tag=hr-ops"),
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
def _client(data_dir: Path, username: str) -> Iterator[TestClient]:
    import cert_watch.routes.auth as auth_routes
    import cert_watch.security.csrf as csrf_mod

    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("CERT_WATCH_DATA_DIR", str(data_dir))
        mp.setenv("CERT_WATCH_COOKIE_SECURE", "0")
        mp.delenv("CERT_WATCH_ROLE_MAP", raising=False)
        mp.delenv("CERT_WATCH_METRICS_TOKEN", raising=False)
        mp.setattr(csrf_mod, "_COOKIE_SECURE", False)
        # The scheduler would scan the pending hosts and change the estate
        # between the baseline and full runs.
        mp.setattr("cert_watch.scheduler.Scheduler.start", lambda self: None)
        # The matrix makes hundreds of API requests from one client address.
        mp.setattr("cert_watch.security.ratelimit.check_rate_limit", lambda *a, **k: True)
        mp.setattr(auth_routes, "_COOKIE_SECURE", False)
        mp.setattr("cert_watch.caa_check.check_caa", _no_caa)
        with TestClient(_app(data_dir), follow_redirects=False) as client:
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
