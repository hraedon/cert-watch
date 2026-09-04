#!/usr/bin/env bash
# ldap-e2e.sh — run the opt-in test against a configured real LDAP/AD instance
# Required LDAP_* variables are documented in test_ldap_login_real.py.
set -euo pipefail

CW_LDAP_E2E=1 .venv/bin/pytest \
    -m ldap_e2e tests/e2e/test_ldap_login_real.py -q --no-cov -n0
