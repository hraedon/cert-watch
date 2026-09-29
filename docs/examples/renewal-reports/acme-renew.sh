#!/bin/sh
# acme.sh hook lifecycle and the saved --pre-hook/--renew-hook flags:
# https://github.com/acmesh-official/acme.sh/wiki/Using-pre-hook-post-hook-renew-hook-reloadcmd
# Exit status 2 means "renewal skipped/not due" in the maintained source; it
# must not become a failed renewal report:
# https://github.com/acmesh-official/acme.sh/blob/master/acme.sh

set -u
: "${CW_REPORT_SCRIPT:?set CW_REPORT_SCRIPT to cw-report.sh}"
: "${ACME_DOMAIN:?set ACME_DOMAIN to one acme.sh certificate name}"

CW_HOST=${CW_HOST:-$ACME_DOMAIN}
CW_PORT=${CW_PORT:-443}
CW_CORRELATION_ID=${CW_CORRELATION_ID:-"acme-$ACME_DOMAIN-$(date -u +%Y%m%dT%H%M%SZ)-$$"}
export CW_HOST CW_PORT CW_CORRELATION_ID

"${ACME_SH_BIN:-acme.sh}" --renew -d "$ACME_DOMAIN" "$@"
status=$?
case $status in
    0) exit 0 ;;
    2) exit 0 ;; # not due; no attempt and therefore no report
    *)
        "$CW_REPORT_SCRIPT" failed --host "$CW_HOST" --port "$CW_PORT" \
            --tool acme.sh --correlation "$CW_CORRELATION_ID" \
            --message "acme.sh --renew exited with status $status"
        exit "$status"
        ;;
esac
