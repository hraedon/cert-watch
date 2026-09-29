#!/bin/sh
# acme.sh hook lifecycle and the saved --pre-hook/--renew-hook flags:
# https://github.com/acmesh-official/acme.sh/wiki/Using-pre-hook-post-hook-renew-hook-reloadcmd
# Exit status 2 means "renewal skipped/not due" in the maintained source; it
# must not become a failed renewal report:
# https://github.com/acmesh-official/acme.sh/blob/master/acme.sh

set -u
: "${ACME_DOMAIN:?set ACME_DOMAIN to one acme.sh certificate name}"

example_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
reporting_ready=0
if [ -r "$example_dir/hook-state.sh" ]; then
    # shellcheck disable=SC1091
    . "$example_dir/hook-state.sh"
    reporting_ready=1
else
    echo "cert-watch reporting: missing hook-state.sh; renewal continues" >&2
fi
if [ -z "${CW_REPORT_SCRIPT:-}" ]; then
    echo "cert-watch reporting: CW_REPORT_SCRIPT is unset; renewal continues" >&2
fi
CW_HOST=${CW_HOST:-$ACME_DOMAIN}
CW_PORT=${CW_PORT:-443}
if [ "$reporting_ready" -eq 1 ] && [ -z "${CW_CORRELATION_ID:-}" ]; then
    CW_CORRELATION_ID=$(cw_hook_random_id 2>/dev/null) || CW_CORRELATION_ID=
    [ -n "$CW_CORRELATION_ID" ] ||
        echo "cert-watch reporting: cannot generate a correlation id; renewal continues" >&2
fi
export CW_HOST CW_PORT CW_CORRELATION_ID

"${ACME_SH_BIN:-acme.sh}" --renew -d "$ACME_DOMAIN" "$@"
renewal_status=$?
case $renewal_status in
    0) exit 0 ;;
    2)
        if [ "$reporting_ready" -eq 1 ]; then
            cw_hook_prepare terminal acme.sh "$CW_HOST:$CW_PORT" || true
            cw_hook_finish
        fi
        echo "acme.sh skipped renewal: the certificate may not be due, or ACME_DOMAIN may not exactly name an issued certificate" >&2
        exit 0
        ;;
    *)
        if [ "$reporting_ready" -eq 1 ] && [ -n "${CW_REPORT_SCRIPT:-}" ] &&
            cw_hook_prepare terminal acme.sh "$CW_HOST:$CW_PORT"; then
            cw_hook_report failed --host "$CW_HOST" --port "$CW_PORT" \
                --tool acme.sh --correlation "$CW_HOOK_CORRELATION" \
                --message "acme.sh --renew exited with status $renewal_status"
        fi
        cw_hook_finish
        exit "$renewal_status"
        ;;
esac
