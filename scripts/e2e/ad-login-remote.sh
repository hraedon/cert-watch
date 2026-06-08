#!/usr/bin/env bash
# ad-login-remote.sh — E2E: real AD login against a DEPLOYED cert-watch instance.
#
# Unlike ldap-e2e.sh (which launches a local process), this drives the *deployed*
# instance over HTTPS — e.g. the Windows/IIS integration VM — and asserts the
# full browser-shaped flow: form login -> 303 -> session cookie -> authenticated
# GET / (no redirect loop), plus a guard on the cw_auth cookie size (the
# BC-145/v0.7.2 cookie-overflow regression).
#
# Harness-agnostic: Claude Code or opencode/kimi just run it. Credentials come
# from the durable Vault path (see reference-cert-watch-vault-ci-creds):
#   source ~/.cw-vault-ci.env && eval "$(scripts/vault-login.sh)"
#
# Usage:
#   scripts/e2e/ad-login-remote.sh
#   CW_BASE=https://host CW_CA=/path/to/ad-ca.pem scripts/e2e/ad-login-remote.sh
#
# Env:
#   CW_BASE   target base URL (default https://mvmcitest01.ad.hraedon.com)
#   CW_CA     CA bundle for TLS verification (default: skip verify, -k, since the
#             instance uses an internal AD CA this box may not trust)
#   CW_USERS  space-separated sAMAccountNames to test (default "cw-user cw-admin")
#   CW_VAULT_ENV  vault env file to source (default ~/.cw-vault-ci.env)
set -uo pipefail

CW_BASE="${CW_BASE:-https://mvmcitest01.ad.hraedon.com}"
CW_USERS="${CW_USERS:-cw-user cw-admin}"
CW_VAULT_ENV="${CW_VAULT_ENV:-$HOME/.cw-vault-ci.env}"
COOKIE_LIMIT=4000          # browsers drop a cookie above ~4096 bytes
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

CURL=(curl -s --max-time 60)
if [ -n "${CW_CA:-}" ]; then CURL+=(--cacert "$CW_CA"); else CURL+=(-k); fi

say() { printf '%s\n' "$*"; }
fail=0

# --- credentials ----------------------------------------------------------
# shellcheck disable=SC1090
source "$CW_VAULT_ENV" 2>/dev/null || { say "FATAL: cannot source $CW_VAULT_ENV"; exit 2; }
eval "$("$REPO_DIR/scripts/vault-login.sh" 2>/dev/null)"
[ -n "${VAULT_TOKEN:-}" ] || { say "FATAL: vault login produced no token"; exit 2; }

# --- one user's full login round-trip ------------------------------------
login_test() {
  local user="$1" pw jar body token code cw len
  pw="$(vault kv get -field=password "kv/cert-watch/ldap/$user" 2>/dev/null)"
  [ -n "$pw" ] || { say "[$user] FAIL: no password in Vault"; return 1; }
  jar="$(mktemp)"

  body="$("${CURL[@]}" -c "$jar" "$CW_BASE/login")"
  token="$(printf '%s' "$body" | grep -oE 'name="_csrf_token" value="[^"]+"' | sed -E 's/.*value="([^"]+)".*/\1/')"
  [ -n "$token" ] || { say "[$user] FAIL: no CSRF token on /login"; rm -f "$jar"; return 1; }

  code="$("${CURL[@]}" -b "$jar" -c "$jar" -o /dev/null -w '%{http_code}' \
    --data-urlencode "username=$user" --data-urlencode "password=$pw" \
    --data-urlencode "_csrf_token=$token" "$CW_BASE/login")"
  cw="$(grep cw_auth "$jar" | awk '{print $7}')"; len="${#cw}"

  local ok=1
  [ "$code" = "303" ]            || { say "[$user] FAIL: POST /login -> $code (want 303)"; ok=0; }
  [ -n "$cw" ]                   || { say "[$user] FAIL: no cw_auth cookie set"; ok=0; }
  [ "$len" -lt "$COOKIE_LIMIT" ] || { say "[$user] FAIL: cw_auth $len bytes >= $COOKIE_LIMIT (cookie-overflow regression)"; ok=0; }

  local home; home="$("${CURL[@]}" -b "$jar" -o /dev/null -w '%{http_code}' "$CW_BASE/")"
  [ "$home" = "200" ]           || { say "[$user] FAIL: GET / -> $home (want 200; redirect loop?)"; ok=0; }

  rm -f "$jar"
  if [ "$ok" = 1 ]; then say "[$user] PASS: login 303, cw_auth ${len}B, GET / 200"; return 0; fi
  return 1
}

say "== cert-watch AD-login E2E against $CW_BASE =="
for u in $CW_USERS; do login_test "$u" || fail=1; done
if [ "$fail" = 0 ]; then say "ALL PASS"; else say "FAILURES PRESENT"; fi
exit "$fail"
