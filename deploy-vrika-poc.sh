#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
if [[ ! -f .env ]]; then
  echo "Missing .env — copy .env.vrika.example to .env and set secrets first."
  exit 1
fi
COMPOSE="docker compose -f docker-compose.yml -f docker-compose.vrika.yml"
$COMPOSE up -d
echo "Waiting for health..."
sleep 15
curl -sf "http://127.0.0.1:8090/health" && echo "prowler internal: ok" || echo "prowler internal: not ready"
$COMPOSE ps
echo ""
echo "Next: sudo bash apply-nyxstrike-nginx.sh"
echo "Then open: https://192.168.9.188/prowler/"
