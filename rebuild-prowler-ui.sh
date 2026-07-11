#!/usr/bin/env bash
# Rebuild and restart Prowler UI after git pull (basePath / auth fixes).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
COMPOSE="docker compose -f docker-compose.yml -f docker-compose.vrika.yml"

$COMPOSE build ui
$COMPOSE up -d ui nginx --force-recreate

echo "Waiting for UI health..."
for i in $(seq 1 30); do
  if curl -sf "http://127.0.0.1:8090/prowler/api/health" >/dev/null 2>&1; then
    echo "UI healthy"
    break
  fi
  sleep 5
done

curl -sI "http://127.0.0.1:8090/prowler/sign-in" | head -5
echo ""
echo "Open: https://192.168.9.188/prowler/sign-in"
