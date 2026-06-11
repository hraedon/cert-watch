from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from cert_watch.certificate_model import Certificate
from cert_watch.policy import PolicyViolation, apply_policy_overrides, evaluate_policy
from cert_watch.policy_packs import get_sc081_policy_pack


def _generate_cert_der(
    not_before: datetime,
    not_after: datetime,
    cn: str = "test.example.com",
    issuer_cn: str = "Public CA",
    self_signed: bool = False,
) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_key = key if self_signed else rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = (
        subject if self_signed
        else x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(cn)]),
            critical=False,
        )
    )
    cert = builder.sign(ca_key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


def _make_cert(
    not_before: datetime,
    validity_days: int,
    cn: str = "test.example.com",
    issuer_cn: str = "Public CA",
    self_signed: bool = False,
) -> Certificate:
    not_after = not_before + timedelta(days=validity_days)
    der = _generate_cert_der(not_before, not_after, cn, issuer_cn, self_signed)
    x509_cert = x509.load_der_x509_certificate(der)
    from cryptography.hazmat.primitives import hashes as _hashes
    fp = x509_cert.fingerprint(_hashes.SHA256()).hex()
    san_names: list[str] = []
    try:
        ext = x509_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
        )
        san_names = ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass
    return Certificate(
        subject=str(x509_cert.subject),
        issuer=str(x509_cert.issuer),
        not_before=x509_cert.not_valid_before_utc,
        not_after=x509_cert.not_valid_after_utc,
        san_dns_names=san_names,
        fingerprint_sha256=fp,
        raw_der=der,
    )


def _enabled_pack():
    pack = get_sc081_policy_pack()
    for r in pack.rules:
        r.enabled = True
    return pack


class TestSC081Milestone200:
    def test_cert_issued_after_milestone_exceeds_200_days(self):
        cert = _make_cert(datetime(2026, 4, 1, tzinfo=UTC), 300)
        pack = get_sc081_policy_pack()
        for r in pack.rules:
            if r.rule_id == "sc081_validity_200":
                r.enabled = True
        vs = evaluate_policy(
            cert, chain_status="public", chain_incomplete=False,
            protocol_version=None, hsts=None, ocsp_stapling=None,
            ruleset=pack,
        )
        sc081_vs = [v for v in vs if v.rule_id.startswith("sc081_")]
        assert len(sc081_vs) == 1
        assert sc081_vs[0].rule_id == "sc081_validity_200"
        assert "300" in sc081_vs[0].message
        assert "200" in sc081_vs[0].message

    def test_cert_issued_before_milestone_not_violated(self):
        cert = _make_cert(datetime(2026, 2, 1, tzinfo=UTC), 300)
        vs = evaluate_policy(
            cert, chain_status="public", chain_incomplete=False,
            protocol_version=None, hsts=None, ocsp_stapling=None,
            ruleset=_enabled_pack(),
        )
        sc081_vs = [v for v in vs if v.rule_id.startswith("sc081_")]
        assert sc081_vs == []


class TestSC081Milestone100:
    def test_cert_issued_after_milestone_exceeds_100_days(self):
        cert = _make_cert(datetime(2027, 4, 1, tzinfo=UTC), 150)
        vs = evaluate_policy(
            cert, chain_status="public", chain_incomplete=False,
            protocol_version=None, hsts=None, ocsp_stapling=None,
            ruleset=_enabled_pack(),
        )
        sc081_vs = [v for v in vs if v.rule_id.startswith("sc081_")]
        assert len(sc081_vs) == 1
        rule_ids = {v.rule_id for v in sc081_vs}
        assert "sc081_validity_100" in rule_ids

    def test_cert_issued_before_100_milestone_not_violated(self):
        cert = _make_cert(datetime(2027, 2, 1, tzinfo=UTC), 150)
        vs = evaluate_policy(
            cert, chain_status="public", chain_incomplete=False,
            protocol_version=None, hsts=None, ocsp_stapling=None,
            ruleset=_enabled_pack(),
        )
        sc081_vs = [v for v in vs if v.rule_id.startswith("sc081_")]
        assert "sc081_validity_100" not in {v.rule_id for v in sc081_vs}


class TestSC081Milestone47:
    def test_cert_issued_after_milestone_exceeds_47_days(self):
        cert = _make_cert(datetime(2029, 4, 1, tzinfo=UTC), 60)
        vs = evaluate_policy(
            cert, chain_status="public", chain_incomplete=False,
            protocol_version=None, hsts=None, ocsp_stapling=None,
            ruleset=_enabled_pack(),
        )
        sc081_vs = [v for v in vs if v.rule_id.startswith("sc081_")]
        assert len(sc081_vs) == 1
        rule_ids = {v.rule_id for v in sc081_vs}
        assert "sc081_validity_47" in rule_ids

    def test_cert_at_exactly_47_days_not_violated(self):
        cert = _make_cert(datetime(2029, 4, 1, tzinfo=UTC), 47)
        vs = evaluate_policy(
            cert, chain_status="public", chain_incomplete=False,
            protocol_version=None, hsts=None, ocsp_stapling=None,
            ruleset=_enabled_pack(),
        )
        sc081_vs = [v for v in vs if v.rule_id == "sc081_validity_47"]
        assert sc081_vs == []


class TestSC081PrivateCAExcluded:
    def test_private_ca_not_violated(self):
        cert = _make_cert(datetime(2026, 4, 1, tzinfo=UTC), 365)
        vs = evaluate_policy(
            cert, chain_status="private", chain_incomplete=False,
            protocol_version=None, hsts=None, ocsp_stapling=None,
            ruleset=_enabled_pack(),
        )
        sc081_vs = [v for v in vs if v.rule_id.startswith("sc081_")]
        assert sc081_vs == []

    def test_self_signed_not_violated(self):
        cert = _make_cert(
            datetime(2026, 4, 1, tzinfo=UTC), 365,
            cn="internal.example.com", issuer_cn="internal.example.com",
            self_signed=True,
        )
        vs = evaluate_policy(
            cert, chain_status="self-signed", chain_incomplete=False,
            protocol_version=None, hsts=None, ocsp_stapling=None,
            ruleset=_enabled_pack(),
        )
        sc081_vs = [v for v in vs if v.rule_id.startswith("sc081_")]
        assert sc081_vs == []

    def test_unknown_chain_status_not_violated(self):
        cert = _make_cert(datetime(2026, 4, 1, tzinfo=UTC), 365)
        vs = evaluate_policy(
            cert, chain_status=None, chain_incomplete=False,
            protocol_version=None, hsts=None, ocsp_stapling=None,
            ruleset=_enabled_pack(),
        )
        sc081_vs = [v for v in vs if v.rule_id.startswith("sc081_")]
        assert sc081_vs == []


class TestSC081PackDefaults:
    def test_pack_disabled_by_default(self):
        pack = get_sc081_policy_pack()
        for r in pack.rules:
            assert r.enabled is False

    def test_pack_name(self):
        pack = get_sc081_policy_pack()
        assert pack.name == "cab-forum-sc081"

    def test_pack_version(self):
        pack = get_sc081_policy_pack()
        assert pack.version == "1.0.0"

    def test_three_rules(self):
        pack = get_sc081_policy_pack()
        assert len(pack.rules) == 3
        ids = [r.rule_id for r in pack.rules]
        assert ids == [
            "sc081_validity_200",
            "sc081_validity_100",
            "sc081_validity_47",
        ]


class TestSC081NoPostureGradeImpact:
    def test_violations_do_not_alter_grade(self):
        cert = _make_cert(datetime(2026, 4, 1, tzinfo=UTC), 300)
        pack = _enabled_pack()
        vs = evaluate_policy(
            cert, chain_status="public", chain_incomplete=False,
            protocol_version=None, hsts=None, ocsp_stapling=None,
            ruleset=pack,
        )
        sc081_vs = [v for v in vs if v.rule_id.startswith("sc081_")]
        assert len(sc081_vs) >= 1
        for v in sc081_vs:
            assert v.grade_affecting is False
        assert apply_policy_overrides("A", sc081_vs) == "A"
        assert apply_policy_overrides("A+", sc081_vs) == "A+"
        assert apply_policy_overrides("B", sc081_vs) == "B"

    def test_mixed_violations_grade_affected_by_non_sc081(self):
        cert = _make_cert(datetime(2026, 4, 1, tzinfo=UTC), 300)
        pack = _enabled_pack()
        vs = evaluate_policy(
            cert, chain_status="public", chain_incomplete=False,
            protocol_version=None, hsts=None, ocsp_stapling=None,
            ruleset=pack,
        )
        sc081_vs = [v for v in vs if v.rule_id.startswith("sc081_")]
        vs = sc081_vs + [PolicyViolation(
            "key_size_rsa", "critical",
            "RSA key size 1024 < 2048 bits",
            "Replace certificate",
            grade_affecting=True,
        )]
        assert apply_policy_overrides("A", vs) == "F"

    def test_disabled_pack_no_violations(self):
        cert = _make_cert(datetime(2026, 4, 1, tzinfo=UTC), 300)
        pack = get_sc081_policy_pack()
        vs = evaluate_policy(
            cert, chain_status="public", chain_incomplete=False,
            protocol_version=None, hsts=None, ocsp_stapling=None,
            ruleset=pack,
        )
        sc081_vs = [v for v in vs if v.rule_id.startswith("sc081_")]
        assert sc081_vs == []
