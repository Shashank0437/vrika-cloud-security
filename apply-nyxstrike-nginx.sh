#!/usr/bin/env bash
# Install the full nyxstrike :443 config (Prowler + Vrika) and reload nginx.
# Run on the server after git pull:
#   sudo bash apply-nyxstrike-nginx.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE="$ROOT/nyxstrike.conf.clean"
AVAILABLE="/etc/nginx/sites-available/nyxstrike"
ENABLED="/etc/nginx/sites-enabled/nyxstrike"

if [[ $EUID -ne 0 ]]; then
  echo "Re-run with sudo: sudo bash $0"
  exit 1
fi

if [[ ! -f "$SOURCE" ]]; then
  echo "Missing $SOURCE — git pull on the server first."
  exit 1
fi

install -m 0644 "$SOURCE" "$AVAILABLE"
install -m 0644 "$SOURCE" "$ENABLED"

nginx -t
systemctl reload nginx

echo "Installed nyxstrike nginx config:"
echo "  $AVAILABLE"
echo "  $ENABLED"
echo "Prowler: https://192.168.9.188/prowler/"
