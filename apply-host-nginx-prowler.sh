#!/usr/bin/env bash
# Run on 192.168.9.188 with sudo to expose Prowler at https://192.168.9.188:9443/
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="/etc/nginx/sites-available/nyxstrike"
MARKER="# VRIKA_PROWLER_9443"
SNIPPET="$ROOT/nginx/nyxstrike-prowler.conf.snippet"

if [[ $EUID -ne 0 ]]; then
  echo "Re-run with sudo: sudo bash $0"
  exit 1
fi

if grep -q "$MARKER" "$TARGET"; then
  echo "Prowler nginx block already present in $TARGET"
else
  echo "" >> "$TARGET"
  echo "$MARKER" >> "$TARGET"
  cat "$SNIPPET" >> "$TARGET"
  echo "Appended Prowler server block to $TARGET"
fi

nginx -t
systemctl reload nginx
echo "Done. Prowler: https://192.168.9.188:9443/  |  Vrika: https://192.168.9.188/"
