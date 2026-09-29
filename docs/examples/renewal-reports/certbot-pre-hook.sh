#!/bin/sh
# Certbot hook behavior:
# https://eff-certbot.readthedocs.io/en/stable/using.html#renewing-certificates

set -u
hook_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
if [ ! -r "$hook_dir/hook-state.sh" ]; then
    echo "cert-watch reporting: missing $hook_dir/hook-state.sh; renewal continues" >&2
    exit 0
fi
# shellcheck disable=SC1091
. "$hook_dir/hook-state.sh"
if [ -z "${CW_REPORT_SCRIPT:-}" ] || [ -z "${CW_HOST:-}" ] ||
    [ -z "${CW_PORT:-}" ]; then
    echo "cert-watch reporting: CW_REPORT_SCRIPT, CW_HOST, or CW_PORT is unset; renewal continues" >&2
    exit 0
fi

if cw_hook_prepare pre certbot "$CW_HOST:$CW_PORT"; then
    cw_hook_report started --host "$CW_HOST" --port "$CW_PORT" \
        --tool certbot --correlation "$CW_HOOK_CORRELATION"
fi
exit 0
