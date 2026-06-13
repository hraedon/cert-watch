from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from freezegun import freeze_time

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


# ---------------------------------------------------------------------------
# Freeze-time boundary tests — P3.3
#
# The SC-081 rules compare cert.not_before against milestone dates
# (2026-03-15, 2027-03-15, 2029-03-15).  On the milestone date itself,
# not_before == milestone_date is NOT strictly less, so the rule DOES apply.
#
# freezegun freezes datetime.now() so each test reads as "on this date,
# evaluate the SC-081 pack".  The rule logic is purely not_before-relative
# (no current-time check), but freezing time makes the scenarios explicit
# and guards against future implementation changes.
#
# IMPORTANT: freezegun's FakeDatetime is incompatible with cryptography's
# Rust cert-signing, so certs must be created *before* entering the
# freeze_time context.  Each test creates the cert first, then freezes
# time for the evaluation.
#
# The SC-081 check uses strict `>` (validity_days > max_days), so a cert
# with validity exactly equal to max_days does NOT produce a violation.
# ---------------------------------------------------------------------------


def _sc081_violation_ids(cert: Certificate, pack=None) -> list[str]:
    """Evaluate an enabled SC-081 pack against *cert* and return the
    rule_id list of any SC-081 violations."""
    if pack is None:
        pack = _enabled_pack()
    vs = evaluate_policy(
        cert, chain_status="public", chain_incomplete=False,
        protocol_version=None, hsts=None, ocsp_stapling=None,
        ruleset=pack,
    )
    return [v.rule_id for v in vs if v.rule_id.startswith("sc081_")]


class TestSC081FreezeTimeBefore200Milestone:
    """Before 2026-03-15: no SC-081 rule applies regardless of validity."""

    def test_398_day_cert_no_violation(self):
        cert = _make_cert(datetime(2026, 1, 15, tzinfo=UTC), 398)
        with freeze_time("2026-01-15"):
            assert _sc081_violation_ids(cert) == []

    def test_500_day_cert_no_violation(self):
        cert = _make_cert(datetime(2026, 1, 15, tzinfo=UTC), 500)
        with freeze_time("2026-01-15"):
            assert _sc081_violation_ids(cert) == []

    def test_day_before_milestone_still_excluded(self):
        cert = _make_cert(datetime(2026, 3, 14, tzinfo=UTC), 365)
        with freeze_time("2026-03-14"):
            assert _sc081_violation_ids(cert) == []


class TestSC081FreezeTimeOn200Milestone:
    """On 2026-03-15: the 200-day rule first applies (not_before is NOT < milestone)."""

    def test_200_day_cert_passes(self):
        cert = _make_cert(datetime(2026, 3, 15, tzinfo=UTC), 200)
        with freeze_time("2026-03-15"):
            assert _sc081_violation_ids(cert) == []

    def test_201_day_cert_violates_200_rule(self):
        cert = _make_cert(datetime(2026, 3, 15, tzinfo=UTC), 201)
        with freeze_time("2026-03-15"):
            ids = _sc081_violation_ids(cert)
        assert ids == ["sc081_validity_200"]

    def test_365_day_cert_violates_200_rule_only(self):
        cert = _make_cert(datetime(2026, 3, 15, tzinfo=UTC), 365)
        with freeze_time("2026-03-15"):
            ids = _sc081_violation_ids(cert)
        assert "sc081_validity_200" in ids
        # 100- and 47-day milestones not yet reached for this not_before
        assert "sc081_validity_100" not in ids
        assert "sc081_validity_47" not in ids


class TestSC081FreezeTimeBetween200And100Milestones:
    """Between 2026-03-15 and 2027-03-15: only the 200-day rule applies."""

    def test_200_day_cert_passes(self):
        cert = _make_cert(datetime(2026, 9, 1, tzinfo=UTC), 200)
        with freeze_time("2026-09-01"):
            assert _sc081_violation_ids(cert) == []

    def test_365_day_cert_violates_200_only(self):
        cert = _make_cert(datetime(2026, 9, 1, tzinfo=UTC), 365)
        with freeze_time("2026-09-01"):
            ids = _sc081_violation_ids(cert)
        assert ids == ["sc081_validity_200"]

    def test_day_before_100_milestone_200_still_only_rule(self):
        cert = _make_cert(datetime(2027, 3, 14, tzinfo=UTC), 365)
        with freeze_time("2027-03-14"):
            ids = _sc081_violation_ids(cert)
        assert ids == ["sc081_validity_200"]


class TestSC081FreezeTimeOn100Milestone:
    """On 2027-03-15: the 100-day rule first applies."""

    def test_100_day_cert_passes(self):
        cert = _make_cert(datetime(2027, 3, 15, tzinfo=UTC), 100)
        with freeze_time("2027-03-15"):
            assert _sc081_violation_ids(cert) == []

    def test_101_day_cert_violates_100_rule(self):
        cert = _make_cert(datetime(2027, 3, 15, tzinfo=UTC), 101)
        with freeze_time("2027-03-15"):
            ids = _sc081_violation_ids(cert)
        assert ids == ["sc081_validity_100"]

    def test_150_day_cert_violates_100_not_200(self):
        """150 days exceeds the 100-day limit but not the 200-day limit."""
        cert = _make_cert(datetime(2027, 3, 15, tzinfo=UTC), 150)
        with freeze_time("2027-03-15"):
            ids = _sc081_violation_ids(cert)
        assert ids == ["sc081_validity_100"]

    def test_201_day_cert_violates_both_200_and_100(self):
        """201 days exceeds both the 200- and 100-day limits."""
        cert = _make_cert(datetime(2027, 3, 15, tzinfo=UTC), 201)
        with freeze_time("2027-03-15"):
            ids = _sc081_violation_ids(cert)
        assert "sc081_validity_200" in ids
        assert "sc081_validity_100" in ids
        assert "sc081_validity_47" not in ids


class TestSC081FreezeTimeBetween100And47Milestones:
    """Between 2027-03-15 and 2029-03-15: both 200- and 100-day rules apply."""

    def test_100_day_cert_passes(self):
        cert = _make_cert(datetime(2028, 1, 1, tzinfo=UTC), 100)
        with freeze_time("2028-01-01"):
            assert _sc081_violation_ids(cert) == []

    def test_150_day_cert_violates_100_only(self):
        cert = _make_cert(datetime(2028, 1, 1, tzinfo=UTC), 150)
        with freeze_time("2028-01-01"):
            ids = _sc081_violation_ids(cert)
        assert ids == ["sc081_validity_100"]

    def test_201_day_cert_violates_both(self):
        cert = _make_cert(datetime(2028, 1, 1, tzinfo=UTC), 201)
        with freeze_time("2028-01-01"):
            ids = _sc081_violation_ids(cert)
        assert "sc081_validity_200" in ids
        assert "sc081_validity_100" in ids
        assert "sc081_validity_47" not in ids

    def test_day_before_47_milestone(self):
        cert = _make_cert(datetime(2029, 3, 14, tzinfo=UTC), 150)
        with freeze_time("2029-03-14"):
            ids = _sc081_violation_ids(cert)
        assert ids == ["sc081_validity_100"]


class TestSC081FreezeTimeOn47Milestone:
    """On 2029-03-15: the 47-day rule first applies."""

    def test_47_day_cert_passes(self):
        cert = _make_cert(datetime(2029, 3, 15, tzinfo=UTC), 47)
        with freeze_time("2029-03-15"):
            assert _sc081_violation_ids(cert) == []

    def test_48_day_cert_violates_47_rule_only(self):
        cert = _make_cert(datetime(2029, 3, 15, tzinfo=UTC), 48)
        with freeze_time("2029-03-15"):
            ids = _sc081_violation_ids(cert)
        assert ids == ["sc081_validity_47"]

    def test_100_day_cert_violates_47_only(self):
        """100 days exceeds the 47-day limit but not the 100- or 200-day
        limits (the check is strict ``>``)."""
        cert = _make_cert(datetime(2029, 3, 15, tzinfo=UTC), 100)
        with freeze_time("2029-03-15"):
            ids = _sc081_violation_ids(cert)
        assert ids == ["sc081_validity_47"]

    def test_201_day_cert_violates_all_three(self):
        """201 days exceeds all three limits."""
        cert = _make_cert(datetime(2029, 3, 15, tzinfo=UTC), 201)
        with freeze_time("2029-03-15"):
            ids = _sc081_violation_ids(cert)
        assert "sc081_validity_200" in ids
        assert "sc081_validity_100" in ids
        assert "sc081_validity_47" in ids


class TestSC081FreezeTimeAfter47Milestone:
    """After 2029-03-15: all three SC-081 rules apply."""

    def test_47_day_cert_passes(self):
        cert = _make_cert(datetime(2030, 1, 1, tzinfo=UTC), 47)
        with freeze_time("2030-01-01"):
            assert _sc081_violation_ids(cert) == []

    def test_100_day_cert_violates_47_only(self):
        """100 days exceeds the 47-day limit but not the 100- or 200-day
        limits (the check is strict ``>``)."""
        cert = _make_cert(datetime(2030, 1, 1, tzinfo=UTC), 100)
        with freeze_time("2030-01-01"):
            ids = _sc081_violation_ids(cert)
        assert ids == ["sc081_validity_47"]

    def test_201_day_cert_violates_all_three(self):
        cert = _make_cert(datetime(2030, 1, 1, tzinfo=UTC), 201)
        with freeze_time("2030-01-01"):
            ids = _sc081_violation_ids(cert)
        assert "sc081_validity_200" in ids
        assert "sc081_validity_100" in ids
        assert "sc081_validity_47" in ids

    def test_each_violation_is_grade_affecting_false(self):
        cert = _make_cert(datetime(2030, 1, 1, tzinfo=UTC), 201)
        pack = _enabled_pack()
        with freeze_time("2030-01-01"):
            vs = evaluate_policy(
                cert, chain_status="public", chain_incomplete=False,
                protocol_version=None, hsts=None, ocsp_stapling=None,
                ruleset=pack,
            )
        sc081_vs = [v for v in vs if v.rule_id.startswith("sc081_")]
        assert len(sc081_vs) == 3
        for v in sc081_vs:
            assert v.grade_affecting is False
