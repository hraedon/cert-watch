#!/bin/sh
# Certbot hook behavior:
# https://eff-certbot.readthedocs.io/en/stable/using.html#renewing-certificates

set -eu
: "${CW_REPORT_SCRIPT:?set CW_REPORT_SCRIPT to cw-report.sh}"
: "${CW_HOST:?set CW_HOST to the monitored endpoint hostname}"
: "${CW_PORT:?set CW_PORT to the monitored endpoint port}"

"$CW_REPORT_SCRIPT" started --host "$CW_HOST" --port "$CW_PORT" \
    --tool certbot --correlation "${CW_CORRELATION_ID:-certbot-$CW_HOST}"
