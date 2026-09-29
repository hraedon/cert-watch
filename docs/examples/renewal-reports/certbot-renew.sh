#!/bin/sh
# Certbot pre/post hooks surround attempts, while deploy hooks run only after a
# successful renewal. A wrapper is needed to report Certbot's failing exit:
# https://eff-certbot.readthedocs.io/en/stable/using.html#renewing-certificates

set -u
: "${CERTBOT_CERT_NAME:?set CERTBOT_CERT_NAME to one Certbot certificate name}"

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
CW_HOST=${CW_HOST:-$CERTBOT_CERT_NAME}
CW_PORT=${CW_PORT:-443}
if [ "$reporting_ready" -eq 1 ] && [ -z "${CW_CORRELATION_ID:-}" ]; then
    CW_CORRELATION_ID=$(cw_hook_random_id 2>/dev/null) || CW_CORRELATION_ID=
    [ -n "$CW_CORRELATION_ID" ] ||
        echo "cert-watch reporting: cannot generate a correlation id; renewal continues" >&2
fi
export CW_HOST CW_PORT CW_CORRELATION_ID

"${CERTBOT_BIN:-certbot}" renew --cert-name "$CERTBOT_CERT_NAME" \
    --pre-hook "$example_dir/certbot-pre-hook.sh" \
    --deploy-hook "$example_dir/certbot-deploy-hook.sh" "$@"
renewal_status=$?
if [ "$renewal_status" -ne 0 ]; then
    if [ "$reporting_ready" -eq 1 ] && [ -n "${CW_REPORT_SCRIPT:-}" ] &&
        cw_hook_prepare terminal certbot "$CW_HOST:$CW_PORT"; then
        cw_hook_report failed --host "$CW_HOST" --port "$CW_PORT" \
            --tool certbot --correlation "$CW_HOOK_CORRELATION" \
            --message "certbot renew exited with status $renewal_status"
    fi
    cw_hook_finish
fi
exit "$renewal_status"
