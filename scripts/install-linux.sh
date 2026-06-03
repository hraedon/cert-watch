#!/usr/bin/env bash
# Bare-metal Linux installer for cert-watch.
# Usage: sudo ./scripts/install-linux.sh
set -euo pipefail

PREFIX=/opt/cert-watch
DATA_DIR=/var/lib/cert-watch
SVC_USER=cert-watch
UNIT=/etc/systemd/system/cert-watch.service

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [[ $EUID -ne 0 ]]; then
    echo "Run as root (use sudo)." >&2
    exit 1
fi

command -v python3 >/dev/null || { echo "python3 required" >&2; exit 1; }

id -u "$SVC_USER" >/dev/null 2>&1 || useradd --system --home "$DATA_DIR" --shell /usr/sbin/nologin "$SVC_USER"
install -d -o "$SVC_USER" -g "$SVC_USER" -m 0750 "$DATA_DIR"
install -d -m 0755 "$PREFIX"

python3 -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install --upgrade pip
"$PREFIX/venv/bin/pip" install "$REPO_ROOT"

install -m 0644 "$REPO_ROOT/deploy/systemd/cert-watch.service" "$UNIT"
systemctl daemon-reload
systemctl enable --now cert-watch.service

echo "Installed. Logs: journalctl -u cert-watch -f"
echo "Dashboard: http://$(hostname -f):8000/"
echo
echo "First run auto-provisions an 'admin'. Get the one-time password with:"
echo "  sudo cat $DATA_DIR/initial-admin-password"
echo "For production, configure AUTH_PROVIDER (LDAP/OAuth) in $UNIT and restart."
