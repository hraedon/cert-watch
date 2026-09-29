#!/bin/sh
# Certbot deploy hooks run once for each successful issuance and export
# RENEWED_LINEAGE and RENEWED_DOMAINS:
# https://eff-certbot.readthedocs.io/en/stable/using.html#renewing-certificates

set -u
hook_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
if [ ! -r "$hook_dir/hook-state.sh" ]; then
    echo "cert-watch reporting: missing $hook_dir/hook-state.sh; renewal continues" >&2
    exit 0
fi
# shellcheck disable=SC1091
. "$hook_dir/hook-state.sh"
if [ -z "${CW_REPORT_SCRIPT:-}" ] || [ -z "${RENEWED_LINEAGE:-}" ] ||
    [ -z "${RENEWED_DOMAINS:-}" ]; then
    echo "cert-watch reporting: required Certbot reporting variables are unset; renewal continues" >&2
    exit 0
fi

# Override CW_HOST when the monitored TLS name is not the first certificate
# domain (for example, a load-balancer name).
first_domain=${RENEWED_DOMAINS%% *}
host=${CW_HOST:-$first_domain}
port=${CW_PORT:-443}

if cw_hook_prepare terminal certbot "$host:$port"; then
    cw_hook_report succeeded --host "$host" --port "$port" \
        --tool certbot --correlation "$CW_HOOK_CORRELATION" \
        --new-pem "$RENEWED_LINEAGE/cert.pem"
fi
cw_hook_finish
exit 0
