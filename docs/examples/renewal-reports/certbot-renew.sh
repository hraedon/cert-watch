#!/bin/sh
# Certbot pre/post hooks surround attempts, while deploy hooks run only after a
# successful renewal. A wrapper is needed to report Certbot's failing exit:
# https://eff-certbot.readthedocs.io/en/stable/using.html#renewing-certificates

set -u
: "${CW_REPORT_SCRIPT:?set CW_REPORT_SCRIPT to cw-report.sh}"
: "${CW_HOST:?set CW_HOST to the monitored endpoint hostname}"
: "${CW_PORT:?set CW_PORT to the monitored endpoint port}"
: "${CERTBOT_CERT_NAME:?set CERTBOT_CERT_NAME to one Certbot certificate name}"

example_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
CW_CORRELATION_ID=${CW_CORRELATION_ID:-"certbot-$CERTBOT_CERT_NAME-$(date -u +%Y%m%dT%H%M%SZ)-$$"}
export CW_CORRELATION_ID

"${CERTBOT_BIN:-certbot}" renew --cert-name "$CERTBOT_CERT_NAME" \
    --pre-hook "$example_dir/certbot-pre-hook.sh" \
    --deploy-hook "$example_dir/certbot-deploy-hook.sh" "$@"
status=$?
if [ "$status" -ne 0 ]; then
    "$CW_REPORT_SCRIPT" failed --host "$CW_HOST" --port "$CW_PORT" \
        --tool certbot --correlation "$CW_CORRELATION_ID" \
        --message "certbot renew exited with status $status"
fi
exit "$status"
