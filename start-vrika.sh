#!/usr/bin/env bash
# Start Prowler for Vrika (no host port conflicts with vrika-server redis/mongo).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if [[ ! -f .env ]]; then
  echo "Missing .env — copy .env.vrika.example to .env first."
  exit 1
fi

COMPOSE="docker compose -f docker-compose.yml -f docker-compose.vrika.yml"

# Remove partial containers from a failed plain `docker compose up -d`
$COMPOSE down --remove-orphans 2>/dev/null || true

$COMPOSE up -d

echo "Waiting for stack..."
for i in $(seq 1 36); do
  if curl -sf "http://127.0.0.1:8090/health" >/dev/null 2>&1; then
    echo "Prowler ready: https://192.168.9.188/prowler/"
    exit 0
  fi
  sleep 5
done

echo "Stack started but /health not ready yet — check: $COMPOSE ps"
$COMPOSE ps
