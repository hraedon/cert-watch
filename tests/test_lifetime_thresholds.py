import math
from datetime import UTC, datetime, timedelta

import pytest

from cert_watch.alerts import (
    CHAIN_THRESHOLDS,
    LEAF_THRESHOLDS,
    SHORT_CERT_LIFETIME_DAYS,
    SHORT_LIFETIME_CHAIN_PCT,
    SHORT_LIFETIME_LEAF_PCT,
    effective_thresholds,
    evaluate_thresholds,
)
from cert_watch.certificate_model import Certificate
from cert_watch.database import SqliteAlertRepository


@pytest.fixture
def alert_repo(tmp_path):
    from cert_watch.database.schema import init_schema

    init_schema(tmp_path / "cw.sqlite3")
    return SqliteAlertRepository(tmp_path / "cw.sqlite3")


def _cert(
    *,
    validity_days: int,
    is_leaf: bool = True,
    days_remaining: int | None = None,
    fp_suffix: str = "",
) -> Certificate:
    now = datetime.now(UTC)
    not_before = now - timedelta(days=1)
    not_after = not_before + timedelta(days=validity_days)
    if days_remaining is not None:
        not_after = now + timedelta(days=days_remaining, hours=12)
        not_before = not_after - timedelta(days=validity_days)
    fp = "fp" + str(validity_days).zfill(4) + ("L" if is_leaf else "C") + fp_suffix
    return Certificate(
        subject="CN=test",
        issuer="CN=CA",
        not_before=not_before,
        not_after=not_after,
        fingerprint_sha256=fp,
        raw_der=b"",
        is_leaf=is_leaf,
    )


class TestEffectiveThresholds:
    def test_long_lived_leaf_uses_fixed(self):
        cert = _cert(validity_days=365)
        assert effective_thresholds(cert) == LEAF_THRESHOLDS

    def test_long_lived_chain_uses_fixed(self):
        cert = _cert(validity_days=365, is_leaf=False)
        assert effective_thresholds(cert) == CHAIN_THRESHOLDS

    def test_short_lived_leaf_uses_relative(self):
        cert = _cert(validity_days=47)
        result = effective_thresholds(cert)
        expected = tuple(math.ceil(47 * p / 100) for p in SHORT_LIFETIME_LEAF_PCT)
        assert result == expected
        assert result == (24, 12, 5)

    def test_short_lived_chain_uses_relative(self):
        cert = _cert(validity_days=47, is_leaf=False)
        result = effective_thresholds(cert)
        expected = tuple(math.ceil(47 * p / 100) for p in SHORT_LIFETIME_CHAIN_PCT)
        assert result == expected

    def test_exactly_90_day_cert_uses_relative(self):
        cert = _cert(validity_days=90)
        result = effective_thresholds(cert)
        assert result != LEAF_THRESHOLDS
        expected = tuple(math.ceil(90 * p / 100) for p in SHORT_LIFETIME_LEAF_PCT)
        assert result == expected
        assert result == (45, 23, 9)

    def test_91_day_cert_uses_fixed(self):
        cert = _cert(validity_days=91)
        assert effective_thresholds(cert) == LEAF_THRESHOLDS

    def test_very_short_cert_7_day(self):
        cert = _cert(validity_days=7)
        result = effective_thresholds(cert)
        expected = tuple(math.ceil(7 * p / 100) for p in SHORT_LIFETIME_LEAF_PCT)
        assert result == expected
        assert result == (4, 2, 1)

    def test_custom_thresholds_override_short(self):
        cert = _cert(validity_days=47)
        custom = (10, 5)
        assert effective_thresholds(cert, custom_thresholds=custom) == (10, 5)

    def test_custom_thresholds_override_long(self):
        cert = _cert(validity_days=365)
        custom = (20, 10)
        assert effective_thresholds(cert, custom_thresholds=custom) == (20, 10)

    def test_thresholds_are_ints(self):
        cert = _cert(validity_days=47)
        for t in effective_thresholds(cert):
            assert isinstance(t, int)

    def test_constants_exposed(self):
        assert SHORT_CERT_LIFETIME_DAYS == 90
        assert SHORT_LIFETIME_LEAF_PCT == (50, 25, 10)
        assert SHORT_LIFETIME_CHAIN_PCT == (50, 25, 10)


class TestBackwardCompatLongLived:
    def test_365_day_leaf_uses_fixed_thresholds(self, alert_repo):
        cert = _cert(validity_days=365, days_remaining=5)
        thresholds = effective_thresholds(cert)
        assert thresholds == LEAF_THRESHOLDS

    def test_365_day_leaf_alerts_at_5_days(self, alert_repo):
        cert = _cert(validity_days=365, days_remaining=5)
        alerts = evaluate_thresholds(cert, alert_repo)
        thresholds_fired = {a.threshold_days for a in alerts}
        days = cert.days_until_expiry()
        expected = min(t for t in LEAF_THRESHOLDS if days <= t)
        assert thresholds_fired == {expected}

    def test_365_day_chain_no_alerts_at_35_days(self, alert_repo):
        cert = _cert(validity_days=365, days_remaining=35, is_leaf=False)
        alerts = evaluate_thresholds(cert, alert_repo)
        assert alerts == []

    def test_365_day_chain_alerts_at_29_days(self, alert_repo):
        cert = _cert(validity_days=365, days_remaining=29, is_leaf=False)
        alerts = evaluate_thresholds(cert, alert_repo)
        thresholds_fired = {a.threshold_days for a in alerts}
        assert 30 in thresholds_fired
        assert 14 not in thresholds_fired

    def test_365_day_leaf_at_each_fixed_threshold(self, tmp_path):
        for remaining in [14, 7, 3, 1]:
            from cert_watch.database.schema import init_schema

            db = tmp_path / f"cw-r{remaining}.sqlite3"
            init_schema(db)
            repo = SqliteAlertRepository(db)
            cert = _cert(validity_days=365, days_remaining=remaining, fp_suffix=f"r{remaining}")
            alerts = evaluate_thresholds(cert, repo)
            thresholds_fired = {a.threshold_days for a in alerts}
            days = cert.days_until_expiry()
            # Only the most urgent newly-crossed threshold fires
            expected = min(t for t in LEAF_THRESHOLDS if days <= t)
            assert thresholds_fired == {expected}, (
                f"expected {{{expected}}} at remaining={remaining}, days={days}, "
                f"got {thresholds_fired}"
            )


class TestShortLivedCerts:
    def test_47_day_cert_relative_threshold_values(self):
        thresholds = effective_thresholds(_cert(validity_days=47))
        assert thresholds == (24, 12, 5)

    def test_47_day_cert_near_expiry(self, alert_repo):
        cert = _cert(validity_days=47, days_remaining=4)
        alerts = evaluate_thresholds(cert, alert_repo)
        thresholds_fired = {a.threshold_days for a in alerts}
        # Only the most urgent newly-crossed threshold fires
        assert thresholds_fired == {5}

    def test_47_day_cert_before_first_threshold(self, alert_repo):
        cert = _cert(validity_days=47, days_remaining=26)
        alerts = evaluate_thresholds(cert, alert_repo)
        assert alerts == []

    def test_47_day_cert_at_first_threshold(self, alert_repo):
        cert = _cert(validity_days=47, days_remaining=24)
        alerts = evaluate_thresholds(cert, alert_repo)
        thresholds_fired = {a.threshold_days for a in alerts}
        assert 24 in thresholds_fired
        assert 12 not in thresholds_fired

    def test_47_day_cert_past_first_before_second(self, alert_repo):
        cert = _cert(validity_days=47, days_remaining=18)
        alerts = evaluate_thresholds(cert, alert_repo)
        thresholds_fired = {a.threshold_days for a in alerts}
        assert 24 in thresholds_fired
        assert 12 not in thresholds_fired

    def test_47_day_cert_at_second_threshold(self, alert_repo):
        cert = _cert(validity_days=47, days_remaining=12)
        alerts = evaluate_thresholds(cert, alert_repo)
        thresholds_fired = {a.threshold_days for a in alerts}
        # Only the most urgent newly-crossed threshold fires
        assert thresholds_fired == {12}

    def test_47_day_cert_chain_relative(self):
        cert = _cert(validity_days=47, is_leaf=False)
        thresholds = effective_thresholds(cert)
        assert thresholds == (24, 12, 5)


class TestBoundaryConditions:
    def test_exactly_90_day_uses_relative(self, alert_repo):
        cert = _cert(validity_days=90, days_remaining=5)
        alerts = evaluate_thresholds(cert, alert_repo)
        thresholds_fired = {a.threshold_days for a in alerts}
        relative = effective_thresholds(_cert(validity_days=90))
        # Only the most urgent newly-crossed threshold fires
        assert thresholds_fired == {min(relative)}

    def test_91_day_uses_fixed(self, alert_repo):
        cert = _cert(validity_days=91, days_remaining=5)
        alerts = evaluate_thresholds(cert, alert_repo)
        thresholds_fired = {a.threshold_days for a in alerts}
        days = cert.days_until_expiry()
        expected = min(t for t in LEAF_THRESHOLDS if days <= t)
        assert thresholds_fired == {expected}

    def test_1_day_validity(self):
        cert = _cert(validity_days=1)
        result = effective_thresholds(cert)
        expected = tuple(math.ceil(1 * p / 100) for p in SHORT_LIFETIME_LEAF_PCT)
        assert result == expected
        assert result == (1, 1, 1)

    def test_zero_day_validity(self):
        cert = _cert(validity_days=0)
        result = effective_thresholds(cert)
        assert result == (0, 0, 0)

    def test_2_day_validity(self):
        cert = _cert(validity_days=2)
        result = effective_thresholds(cert)
        expected = tuple(math.ceil(2 * p / 100) for p in SHORT_LIFETIME_LEAF_PCT)
        assert result == expected


class TestCustomThresholdsOverride:
    def test_custom_overrides_short_lived(self, alert_repo):
        cert = _cert(validity_days=47, days_remaining=5)
        custom = (10,)
        alerts = evaluate_thresholds(cert, alert_repo, custom_thresholds=custom)
        thresholds_fired = {a.threshold_days for a in alerts}
        assert thresholds_fired == {10}

    def test_custom_overrides_long_lived(self, alert_repo):
        cert = _cert(validity_days=365, days_remaining=5)
        custom = (30,)
        alerts = evaluate_thresholds(cert, alert_repo, custom_thresholds=custom)
        thresholds_fired = {a.threshold_days for a in alerts}
        assert thresholds_fired == {30}

    def test_custom_empty_tuple_no_alerts(self, alert_repo):
        cert = _cert(validity_days=47, days_remaining=0)
        alerts = evaluate_thresholds(cert, alert_repo, custom_thresholds=())
        assert alerts == []


class TestEscalationOnceOnly:
    def test_no_duplicates_on_re_eval(self, alert_repo):
        cert = _cert(validity_days=47, days_remaining=4)
        first = evaluate_thresholds(cert, alert_repo)
        assert len(first) > 0
        second = evaluate_thresholds(cert, alert_repo)
        assert second == []

    def test_thresholds_never_refire(self, alert_repo):
        """Each threshold fires exactly once."""
        cert = _cert(validity_days=47, days_remaining=4)
        first = evaluate_thresholds(cert, alert_repo)
        first_ids = {a.id for a in first}
        second = evaluate_thresholds(cert, alert_repo)
        assert second == []
        assert first_ids

    def test_expired_alert_type(self, alert_repo):
        cert = _cert(validity_days=47, days_remaining=-1)
        alerts = evaluate_thresholds(cert, alert_repo)
        assert any(a.alert_type == "expired" for a in alerts)

    def test_expired_short_lived_7_day(self, alert_repo):
        cert = _cert(validity_days=7, days_remaining=-1)
        alerts = evaluate_thresholds(cert, alert_repo)
        assert any(a.alert_type == "expired" for a in alerts)
        thresholds_fired = {a.threshold_days for a in alerts}
        assert thresholds_fired == {1}

    def test_collapsed_thresholds_1_day_produces_alerts(self, alert_repo):
        cert = _cert(validity_days=1, days_remaining=0)
        alerts = evaluate_thresholds(cert, alert_repo)
        assert len(alerts) == 1
        assert all(a.threshold_days == 1 for a in alerts)

    def test_collapsed_thresholds_2_day_produces_alerts(self, alert_repo):
        cert = _cert(validity_days=2, days_remaining=0)
        alerts = evaluate_thresholds(cert, alert_repo)
        assert len(alerts) == 1
        assert all(a.threshold_days == 1 for a in alerts)

    def test_expiry_warning_type(self, alert_repo):
        cert = _cert(validity_days=47, days_remaining=3)
        alerts = evaluate_thresholds(cert, alert_repo)
        assert all(a.alert_type == "expiry_warning" for a in alerts)
