#!/bin/sh
# acme.sh runs --renew-hook after a successful renewal; --reloadcmd runs after
# successful installation. Both behaviors are documented here:
# https://github.com/acmesh-official/acme.sh/wiki/Using-pre-hook-post-hook-renew-hook-reloadcmd
# CERT_PATH and Le_Domain are exported to renew/reload hooks by acme.sh:
# https://github.com/acmesh-official/acme.sh/blob/master/acme.sh

set -u
hook_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
if [ ! -r "$hook_dir/hook-state.sh" ]; then
    echo "cert-watch reporting: missing $hook_dir/hook-state.sh; renewal continues" >&2
    exit 0
fi
# shellcheck disable=SC1091
. "$hook_dir/hook-state.sh"
if [ -z "${CW_REPORT_SCRIPT:-}" ] || [ -z "${Le_Domain:-}" ] ||
    [ -z "${CERT_PATH:-}" ]; then
    echo "cert-watch reporting: CW_REPORT_SCRIPT, Le_Domain, or CERT_PATH is unset; renewal continues" >&2
    exit 0
fi

host=${CW_HOST:-$Le_Domain}
port=${CW_PORT:-443}
if cw_hook_prepare terminal acme.sh "$host:$port"; then
    cw_hook_report succeeded --host "$host" --port "$port" \
        --tool acme.sh --correlation "$CW_HOOK_CORRELATION" \
        --new-pem "$CERT_PATH"
fi
cw_hook_finish
exit 0
