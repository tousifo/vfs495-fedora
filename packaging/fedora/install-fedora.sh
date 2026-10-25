#!/usr/bin/env bash
# VFS495 fingerprint login — Fedora installer (see packaging/fedora/README.md).
# Installs the capture bridge service + fprintd drop-in. Does NOT modify PAM,
# PAM change is a separate clearly-flagged step (check authselect, ask user).
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
REPO="$(dirname "$SRC")"
BRIDGE_SRC="$REPO/tools/vfs495_bridge_fedora.py"
BRIDGE_DST=/usr/local/libexec/vfs495-fedora-bridge.py

if [ ! -e "$REPO/runtime/bin/validity-sensor-unlocked" ]; then
  echo "ERROR: $REPO/runtime/bin/validity-sensor-unlocked missing."
  echo "       Build the capture harness first: $REPO/runtime/README.md"; exit 1
fi
command -v systemctl >/dev/null 2>&1 || { echo "ERROR: systemctl missing"; exit 1; }

install -Dm644 "$SRC/fprintd.service.d/virtimg.conf" /etc/systemd/system/fprintd.service.d/virtimg.conf

install -Dm755 "$BRIDGE_SRC" "$BRIDGE_DST"

cat > /etc/systemd/system/vfs495-bridge.service < "$SRC/vfs495-bridge.service"

systemctl daemon-reload
systemctl enable --now vfs495-bridge.service
systemctl try-restart fprintd.service || true

echo
echo "Installed. NOTE: PAM still needs 'with-fingerprint' in the authselect profile:"
echo "  authselect current        # MUST list with-fingerprint"
echo "  If it is not there, review the authselect line in packaging/fedora/README.md and run it with --force."
echo "Then: fprintd-enroll  (6 prompt swipes, promptly)"
