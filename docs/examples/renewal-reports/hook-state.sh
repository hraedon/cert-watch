#!/bin/sh
# Shared correlation state for the Certbot and acme.sh hook examples.
# Source this file; it is not a hook by itself.

cw_hook_random_id() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 16
        return
    fi
    if [ -r /proc/sys/kernel/random/uuid ]; then
        tr -d '-' </proc/sys/kernel/random/uuid
        return
    fi
    return 1
}

cw_hook_prepare() {
    phase=$1
    tool=$2
    identity=$3
    state_dir=${CW_RENEWAL_STATE_DIR:-/var/lib/cert-watch-renewal-hooks}
    CW_HOOK_STATE_FILE=

    state_key=$(printf '%s' "$tool:$identity" | openssl dgst -sha256 -r 2>/dev/null |
        awk '{print $1}')
    if [ -n "$state_key" ]; then
        old_umask=$(umask)
        umask 077
        if [ ! -e "$state_dir" ] && [ ! -L "$state_dir" ]; then
            mkdir -p "$state_dir" 2>/dev/null || true
        fi
        umask "$old_umask"

        state_uid=$(stat -c '%u' -- "$state_dir" 2>/dev/null) || state_uid=
        state_mode=$(stat -c '%a' -- "$state_dir" 2>/dev/null) || state_mode=
        group_other_mode=$(printf '%s' "$state_mode" | sed 's/.*\(..\)$/\1/')
        # An unusable state directory only disables the shared correlation
        # file; the report is still sent, with a fresh random correlation.
        state_ok=1
        if [ ! -d "$state_dir" ] || [ -L "$state_dir" ] ||
            [ "$state_uid" != "$(id -u)" ]; then
            echo "cert-watch reporting: cannot use private state directory $state_dir; reporting without shared correlation" >&2
            state_ok=
        fi
        case $group_other_mode in
            [2367]?|?[2367])
                echo "cert-watch reporting: state directory is writable by group or other; reporting without shared correlation" >&2
                state_ok=
                ;;
        esac
        if [ -n "$state_ok" ]; then
            CW_HOOK_STATE_FILE=$state_dir/$state_key.correlation
            if [ -L "$CW_HOOK_STATE_FILE" ]; then
                echo "cert-watch reporting: refusing symlinked correlation state; reporting without shared correlation" >&2
                CW_HOOK_STATE_FILE=
            fi
        fi
    else
        echo "cert-watch reporting: cannot derive a correlation state name; reporting without shared correlation" >&2
    fi

    if [ -n "${CW_CORRELATION_ID:-}" ]; then
        CW_HOOK_CORRELATION=$CW_CORRELATION_ID
    elif [ "$phase" = terminal ] && [ -n "$CW_HOOK_STATE_FILE" ] &&
        [ -r "$CW_HOOK_STATE_FILE" ]; then
        IFS= read -r CW_HOOK_CORRELATION <"$CW_HOOK_STATE_FILE" ||
            CW_HOOK_CORRELATION=
    else
        CW_HOOK_CORRELATION=
    fi

    if [ -z "$CW_HOOK_CORRELATION" ]; then
        CW_HOOK_CORRELATION=$(cw_hook_random_id 2>/dev/null) || {
            echo "cert-watch reporting: cannot generate a random correlation id" >&2
            return 1
        }
    fi

    if [ "$phase" = pre ] && [ -n "$CW_HOOK_STATE_FILE" ]; then
        old_umask=$(umask)
        umask 077
        state_tmp=$(mktemp "$state_dir/.cw-correlation.XXXXXX" 2>/dev/null) || state_tmp=
        if [ -n "$state_tmp" ] &&
            printf '%s\n' "$CW_HOOK_CORRELATION" >"$state_tmp" 2>/dev/null &&
            mv -f "$state_tmp" "$CW_HOOK_STATE_FILE" 2>/dev/null; then
            :
        else
            echo "cert-watch reporting: cannot save correlation state; reporting without shared correlation" >&2
            [ -z "$state_tmp" ] || rm -f "$state_tmp"
            CW_HOOK_STATE_FILE=
        fi
        umask "$old_umask"
    fi
}

cw_hook_finish() {
    if [ -n "${CW_HOOK_STATE_FILE:-}" ]; then
        rm -f "$CW_HOOK_STATE_FILE" 2>/dev/null ||
            echo "cert-watch reporting: cannot remove correlation state" >&2
    fi
}

cw_hook_report() {
    if "${CW_REPORT_SCRIPT}" "$@"; then
        return 0
    else
        status=$?
    fi
    echo "cert-watch reporting failed with status $status; renewal continues" >&2
    return 0
}
