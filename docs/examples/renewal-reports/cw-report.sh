#!/bin/sh
# Send one renewal report. The API contract is documented at:
# https://github.com/hraedon/cert-watch/blob/main/docs/renewal-reports.md
#
# Dependencies: curl, openssl (for --new-pem and idempotency), and python3.
# The API key is read from CW_RENEWAL_REPORT_KEY or from the file named by
# CW_RENEWAL_REPORT_KEY_FILE. It is never accepted as a command-line argument.

set -eu

usage() {
    echo "usage: cw-report.sh OUTCOME [--host HOST --port PORT | --cert-fingerprint SHA256]" >&2
    echo "       [--message TEXT] [--tool NAME] [--correlation ID]" >&2
    echo "       [--new-fingerprint SHA256 | --new-pem FILE]" >&2
    exit 2
}

[ "$#" -ge 1 ] || usage
outcome=$1
shift

host=${CW_HOST:-}
port=${CW_PORT:-}
cert_fingerprint=${CW_CERT_FINGERPRINT:-}
message=${CW_MESSAGE:-}
tool=${CW_TOOL:-}
correlation=${CW_CORRELATION_ID:-}
new_fingerprint=${CW_NEW_FINGERPRINT:-}
new_pem=

while [ "$#" -gt 0 ]; do
    case $1 in
        --host) [ "$#" -ge 2 ] || usage; host=$2; shift 2 ;;
        --port) [ "$#" -ge 2 ] || usage; port=$2; shift 2 ;;
        --cert-fingerprint) [ "$#" -ge 2 ] || usage; cert_fingerprint=$2; shift 2 ;;
        --message) [ "$#" -ge 2 ] || usage; message=$2; shift 2 ;;
        --tool) [ "$#" -ge 2 ] || usage; tool=$2; shift 2 ;;
        --correlation) [ "$#" -ge 2 ] || usage; correlation=$2; shift 2 ;;
        --new-fingerprint) [ "$#" -ge 2 ] || usage; new_fingerprint=$2; shift 2 ;;
        --new-pem) [ "$#" -ge 2 ] || usage; new_pem=$2; shift 2 ;;
        *) usage ;;
    esac
done

case $outcome in
    started|succeeded|failed) ;;
    *) usage ;;
esac

if [ -n "$host" ] || [ -n "$port" ]; then
    [ -n "$host" ] && [ -n "$port" ] && [ -z "$cert_fingerprint" ] || usage
else
    [ -n "$cert_fingerprint" ] || usage
fi
[ -z "$new_pem" ] || [ -z "$new_fingerprint" ] || usage

if [ -n "$new_pem" ]; then
    new_fingerprint=$(
        openssl x509 -in "$new_pem" -noout -fingerprint -sha256 |
            sed 's/.*=//; s/://g' | tr '[:upper:]' '[:lower:]'
    )
    [ -n "$new_fingerprint" ] || {
        echo "could not read a SHA-256 fingerprint from $new_pem" >&2
        exit 1
    }
fi

# Key problems are configuration errors: exit 3 so a direct caller sees them.
# The hook examples call this through cw_hook_report, which never fails the
# renewal.
if [ -n "${CW_RENEWAL_REPORT_KEY_FILE:-}" ]; then
    if [ ! -f "$CW_RENEWAL_REPORT_KEY_FILE" ] || [ ! -r "$CW_RENEWAL_REPORT_KEY_FILE" ]; then
        echo "cert-watch reporting: renewal-report key file is not a readable file" >&2
        exit 3
    fi
    # Command substitution would drop NUL bytes silently; reject them instead.
    if [ "$(tr -d '\000' <"$CW_RENEWAL_REPORT_KEY_FILE" | wc -c)" != \
        "$(wc -c <"$CW_RENEWAL_REPORT_KEY_FILE")" ]; then
        echo "cert-watch reporting: renewal-report key file contains a NUL byte" >&2
        exit 3
    fi
    # The sentinel prevents command substitution from stripping every trailing
    # newline. Remove the sentinel, then allow exactly one conventional final LF.
    api_key=$(cat -- "$CW_RENEWAL_REPORT_KEY_FILE"; printf x)
    api_key=${api_key%x}
    case $api_key in
        *'
') api_key=${api_key%?} ;;
    esac
elif [ -n "${CW_RENEWAL_REPORT_KEY:-}" ]; then
    api_key=$CW_RENEWAL_REPORT_KEY
else
    echo "cert-watch reporting: set CW_RENEWAL_REPORT_KEY or CW_RENEWAL_REPORT_KEY_FILE" >&2
    exit 3
fi
unset CW_RENEWAL_REPORT_KEY
case $api_key in
    cwk_*) key_payload=${api_key#cwk_} ;;
    *) key_payload= ;;
esac
case $key_payload in
    ''|*[!A-Za-z0-9_-]*)
        echo "cert-watch reporting: invalid renewal-report key (expected cwk_ followed by A-Z a-z 0-9 _ -)" >&2
        exit 3
        ;;
esac

base_url=${CW_BASE_URL:-http://127.0.0.1:8000}
idempotency_key=${CW_IDEMPOTENCY_KEY:-}
if [ -z "$idempotency_key" ]; then
    idempotency_key=$(openssl rand -hex 16)
fi

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/cw-report.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM
chmod 700 "$work_dir"

# Build JSON with a real encoder so messages, hostnames, and tool output cannot
# break quoting. Values travel through the environment, not process argv.
CW_JSON_OUTCOME=$outcome \
CW_JSON_HOST=$host \
CW_JSON_PORT=$port \
CW_JSON_CERT_FINGERPRINT=$cert_fingerprint \
CW_JSON_MESSAGE=$message \
CW_JSON_TOOL=$tool \
CW_JSON_CORRELATION=$correlation \
CW_JSON_NEW_FINGERPRINT=$new_fingerprint \
python3 - <<'PY' >"$work_dir/body.json"
import json
import os

body = {"outcome": os.environ["CW_JSON_OUTCOME"]}
optional = {
    "hostname": "CW_JSON_HOST",
    "cert_fingerprint": "CW_JSON_CERT_FINGERPRINT",
    "message": "CW_JSON_MESSAGE",
    "tool": "CW_JSON_TOOL",
    "correlation_id": "CW_JSON_CORRELATION",
    "new_fingerprint": "CW_JSON_NEW_FINGERPRINT",
}
for field, variable in optional.items():
    if os.environ.get(variable):
        body[field] = os.environ[variable]
if os.environ.get("CW_JSON_PORT"):
    body["port"] = int(os.environ["CW_JSON_PORT"])
print(json.dumps(body, ensure_ascii=False, separators=(",", ":")))
PY

# Keep the bearer token out of curl's argv. The temporary config is private and
# is removed by the trap; argv contains only its path. The key format check
# above already excludes quotes, backslashes and line breaks; the escaping
# below is defence in depth only.
umask 077
escaped_api_key=$(printf '%s' "$api_key" | sed 's/\\/\\\\/g; s/"/\\"/g')
{
    printf 'header = "Authorization: Bearer %s"\n' "$escaped_api_key"
} >"$work_dir/curl.conf"
unset api_key escaped_api_key

timeout_seconds=${CW_REPORT_TIMEOUT_SECONDS:-10}
response_file=$work_dir/response.json
if http_status=$(curl --config "$work_dir/curl.conf" \
    --silent --show-error --max-time "$timeout_seconds" \
    --header "Content-Type: application/json" \
    --header "Idempotency-Key: $idempotency_key" \
    --request POST --data-binary "@$work_dir/body.json" \
    --output "$response_file" --write-out '%{http_code}' \
    --url "${base_url%/}/api/renewal-reports"); then
    cat "$response_file"
    printf '\n'
else
    status=$?
    [ ! -s "$response_file" ] || cat "$response_file"
    echo "cert-watch reporting request failed" >&2
    exit "$status"
fi

case $http_status in
    2??) ;;
    *)
        echo "cert-watch returned HTTP $http_status" >&2
        exit 1
        ;;
esac
