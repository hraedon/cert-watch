#!/bin/sh
# acme.sh saves --pre-hook on --issue and runs it before an actual renewal:
# https://github.com/acmesh-official/acme.sh/wiki/Using-pre-hook-post-hook-renew-hook-reloadcmd
# Le_Domain is exported to the pre-hook by the maintained implementation:
# https://github.com/acmesh-official/acme.sh/blob/master/acme.sh

set -eu
: "${CW_REPORT_SCRIPT:?set CW_REPORT_SCRIPT to cw-report.sh}"
: "${Le_Domain:?acme.sh did not set Le_Domain}"

host=${CW_HOST:-$Le_Domain}
port=${CW_PORT:-443}
"$CW_REPORT_SCRIPT" started --host "$host" --port "$port" \
    --tool acme.sh --correlation "${CW_CORRELATION_ID:-acme-$Le_Domain}"
