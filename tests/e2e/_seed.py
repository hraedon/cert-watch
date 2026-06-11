"""Deterministic demo-estate seeding for visual baselines and ad-hoc UI checks.

The empty-state visual baselines (WS-C4) cannot catch bugs that only render on
populated rows — the 2026-06-11 UI review found several that had shipped that
way ("4078expired 11 years ago", "1 hosts", undefined gap classes). This module
seeds a small certificate estate directly through the upload store (no HTTP,
no CSRF) so a populated dashboard can be baselined.

Determinism contract: expiry *offsets* are fixed relative to seed time, so
status pills, urgency bars, stat counts, and row order are stable run-to-run.
The rendered dates and "in N days" strings are NOT stable day-to-day — visual
tests must mask the expiry column (see test_visual_regression._POPULATED_MASKS).
"""

from __future__ import annotations

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# (common name, issuer CN, days until expiry — negative = already expired)
DEMO_CERTS: list[tuple[str, str, int]] = [
    ("legacy.demo.test", "Demo Legacy CA", -400),     # expired
    ("intranet.demo.test", "Demo Internal CA", 4),    # critical (≤7d)
    ("vpn.demo.test", "Demo Internal CA", 10),        # warning (≤14d)
    ("mail.demo.test", "Demo Internal CA", 60),       # healthy
    ("ldaps.demo.test", "Demo Internal CA", 200),     # healthy, far out
]


def make_cert_pem(cn: str, issuer_cn: str, days: int) -> bytes:
    """Self-signed PEM with a CN + two SANs, expiring `days` from now."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.UTC)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Demo Estate"),
        ]
    )
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + datetime.timedelta(days=days - 365))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(cn), x509.DNSName(f"www.{cn}")]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def seed_demo_certs(data_dir: Path | str) -> int:
    """Store the demo estate into `data_dir`'s cert-watch DB. Returns count.

    Safe to call against a running server's data dir (WAL mode, one-shot
    writes), or before boot — `store_uploaded` initialises the schema.
    """
    import tempfile

    from cert_watch.upload import ParseError, store_uploaded, upload_certificate

    db = Path(data_dir) / "cert-watch.sqlite3"
    stored = 0
    with tempfile.TemporaryDirectory() as tmp:
        for cn, issuer_cn, days in DEMO_CERTS:
            pem_path = Path(tmp) / f"{cn}.pem"
            pem_path.write_bytes(make_cert_pem(cn, issuer_cn, days))
            entry = upload_certificate(pem_path)
            if isinstance(entry, ParseError):  # pragma: no cover - defensive
                raise RuntimeError(f"seed cert {cn} failed: {entry.error_message}")
            store_uploaded(entry, db)
            stored += 1
    return stored


if __name__ == "__main__":  # pragma: no cover
    # Ad-hoc use: seed a local instance's data dir for interactive UI checks.
    #   .venv/bin/python tests/e2e/_seed.py /tmp/cw-data
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "."
    n = seed_demo_certs(target)
    print(f"seeded {n} demo certificates into {target}")
