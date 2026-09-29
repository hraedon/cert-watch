#!/bin/sh
# Certbot deploy hooks run once for each successful issuance and export
# RENEWED_LINEAGE and RENEWED_DOMAINS:
# https://eff-certbot.readthedocs.io/en/stable/using.html#renewing-certificates

set -eu
: "${CW_REPORT_SCRIPT:?set CW_REPORT_SCRIPT to cw-report.sh}"
: "${RENEWED_LINEAGE:?Certbot did not set RENEWED_LINEAGE}"
: "${RENEWED_DOMAINS:?Certbot did not set RENEWED_DOMAINS}"

# Override CW_HOST when the monitored TLS name is not the first certificate
# domain (for example, a load-balancer name).
first_domain=${RENEWED_DOMAINS%% *}
host=${CW_HOST:-$first_domain}
port=${CW_PORT:-443}

"$CW_REPORT_SCRIPT" succeeded --host "$host" --port "$port" \
    --tool certbot --correlation "${CW_CORRELATION_ID:-certbot-$host}" \
    --new-pem "$RENEWED_LINEAGE/cert.pem"
