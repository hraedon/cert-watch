"""Exhaustive table test for the first-run posture decision (BC-114).

These cover the pure decision in isolation; `test_bc083_081.py` keeps the
end-to-end lifespan checks (actual provisioning, fail-closed SystemExit).
"""

from __future__ import annotations

import pytest

from cert_watch.firstrun import FirstRunPosture, first_run_action, is_network_exposed


@pytest.mark.parametrize(
    "bind_host,trust_proxy,expected",
    [
        # Loopback binds, no proxy → not exposed.
        ("127.0.0.1", False, False),
        ("::1", False, False),
        ("localhost", False, False),
        # Loopback + proxy republishing it (IIS/nginx) → exposed.
        ("127.0.0.1", True, True),
        ("::1", True, True),
        ("localhost", True, True),
        # Routable binds → exposed regardless of proxy flag.
        ("0.0.0.0", False, True),
        ("0.0.0.0", True, True),
        ("10.0.0.5", False, True),
        ("::", False, True),
    ],
)
def test_is_network_exposed(bind_host, trust_proxy, expected):
    assert is_network_exposed(bind_host, trust_proxy) is expected


# Full 2×2×2 truth table over (has_provider, allow_unauth, network_exposed).
@pytest.mark.parametrize(
    "has_provider,allow_unauth,network_exposed,expected",
    [
        # A configured provider short-circuits the whole gate.
        (True, False, False, FirstRunPosture.AUTHENTICATED),
        (True, False, True, FirstRunPosture.AUTHENTICATED),
        (True, True, False, FirstRunPosture.AUTHENTICATED),
        (True, True, True, FirstRunPosture.AUTHENTICATED),
        # No provider, not exposed → serve open (bare-loopback dev + /setup).
        (False, False, False, FirstRunPosture.SERVE_OPEN),
        # No provider, exposed, no opt-out → provision (come up authenticated).
        (False, False, True, FirstRunPosture.PROVISION_ADMIN),
        # Explicit opt-out forces open regardless of exposure.
        (False, True, False, FirstRunPosture.SERVE_OPEN),
        (False, True, True, FirstRunPosture.SERVE_OPEN),
    ],
)
def test_first_run_action_truth_table(has_provider, allow_unauth, network_exposed, expected):
    assert (
        first_run_action(
            has_provider=has_provider,
            allow_unauth=allow_unauth,
            network_exposed=network_exposed,
        )
        is expected
    )


def test_truth_table_covers_all_eight_combinations():
    """Guard against the table above silently losing a row: exactly the 8
    (has_provider, allow_unauth, network_exposed) combinations must be present."""
    import itertools

    seen = {
        first_run_action(
            has_provider=hp, allow_unauth=au, network_exposed=ne
        )
        for hp, au, ne in itertools.product([True, False], repeat=3)
    }
    # The decision only ever yields these three postures.
    assert seen == {
        FirstRunPosture.AUTHENTICATED,
        FirstRunPosture.SERVE_OPEN,
        FirstRunPosture.PROVISION_ADMIN,
    }
