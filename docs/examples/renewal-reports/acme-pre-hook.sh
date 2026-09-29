#!/bin/sh
# acme.sh saves --pre-hook on --issue and runs it before an actual renewal:
# https://github.com/acmesh-official/acme.sh/wiki/Using-pre-hook-post-hook-renew-hook-reloadcmd
# Le_Domain is exported to the pre-hook by the maintained implementation:
# https://github.com/acmesh-official/acme.sh/blob/master/acme.sh

set -u
hook_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
if [ ! -r "$hook_dir/hook-state.sh" ]; then
    echo "cert-watch reporting: missing $hook_dir/hook-state.sh; renewal continues" >&2
    exit 0
fi
# shellcheck disable=SC1091
. "$hook_dir/hook-state.sh"
if [ -z "${CW_REPORT_SCRIPT:-}" ] || [ -z "${Le_Domain:-}" ]; then
    echo "cert-watch reporting: CW_REPORT_SCRIPT or Le_Domain is unset; renewal continues" >&2
    exit 0
fi

host=${CW_HOST:-$Le_Domain}
port=${CW_PORT:-443}
if cw_hook_prepare pre acme.sh "$host:$port"; then
    cw_hook_report started --host "$host" --port "$port" \
        --tool acme.sh --correlation "$CW_HOOK_CORRELATION"
fi
exit 0
