#!/bin/sh
# acme.sh runs --renew-hook after a successful renewal; --reloadcmd runs after
# successful installation. Both behaviors are documented here:
# https://github.com/acmesh-official/acme.sh/wiki/Using-pre-hook-post-hook-renew-hook-reloadcmd
# CERT_PATH and Le_Domain are exported to renew/reload hooks by acme.sh:
# https://github.com/acmesh-official/acme.sh/blob/master/acme.sh

set -eu
: "${CW_REPORT_SCRIPT:?set CW_REPORT_SCRIPT to cw-report.sh}"
: "${Le_Domain:?acme.sh did not set Le_Domain}"
: "${CERT_PATH:?acme.sh did not set CERT_PATH}"

host=${CW_HOST:-$Le_Domain}
port=${CW_PORT:-443}
"$CW_REPORT_SCRIPT" succeeded --host "$host" --port "$port" \
    --tool acme.sh --correlation "${CW_CORRELATION_ID:-acme-$Le_Domain}" \
    --new-pem "$CERT_PATH"
