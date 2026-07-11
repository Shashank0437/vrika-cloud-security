#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
if [[ ! -f .env ]]; then
  echo "Missing .env — copy .env.vrika.example to .env and set secrets first."
  exit 1
fi
COMPOSE="docker compose -f docker-compose.yml -f docker-compose.vrika.yml"
$COMPOSE up -d
echo "Waiting for health..."
sleep 20
curl -sf "http://127.0.0.1/health" && echo "nginx: ok" || echo "nginx: not ready yet"
curl -sf -o /dev/null -w "api docs: %{http_code}\n" "http://127.0.0.1/api/v1/docs" || true
curl -sf -o /dev/null -w "ui root: %{http_code}\n" "http://127.0.0.1/" || true
$COMPOSE ps
