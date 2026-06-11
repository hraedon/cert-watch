from cert_watch.policy import PolicyRule, PolicySet

_MILESTONE_200_DATE = "2026-03-15"
_MILESTONE_200_DAYS = 200

_MILESTONE_100_DATE = "2027-03-15"
_MILESTONE_100_DAYS = 100

_MILESTONE_47_DATE = "2029-03-15"
_MILESTONE_47_DAYS = 47


def get_sc081_policy_pack() -> PolicySet:
    return PolicySet(
        name="cab-forum-sc081",
        version="1.0.0",
        default_severity="warning",
        rules=[
            PolicyRule(
                rule_id="sc081_validity_200",
                category="validity",
                severity="warning",
                enabled=False,
                parameters={
                    "milestone_date": _MILESTONE_200_DATE,
                    "max_days": _MILESTONE_200_DAYS,
                },
            ),
            PolicyRule(
                rule_id="sc081_validity_100",
                category="validity",
                severity="warning",
                enabled=False,
                parameters={
                    "milestone_date": _MILESTONE_100_DATE,
                    "max_days": _MILESTONE_100_DAYS,
                },
            ),
            PolicyRule(
                rule_id="sc081_validity_47",
                category="validity",
                severity="warning",
                enabled=False,
                parameters={
                    "milestone_date": _MILESTONE_47_DATE,
                    "max_days": _MILESTONE_47_DAYS,
                },
            ),
        ],
    )
