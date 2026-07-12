#!/usr/bin/env bash
# Rebuild and restart Prowler UI after git pull (basePath / auth fixes).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
COMPOSE="docker compose -f docker-compose.yml -f docker-compose.vrika.yml"

if grep -rq 'from "../providers"' ui/app/ 2>/dev/null; then
  echo "ERROR: ui/app still uses '../providers' import. Run: git pull" >&2
  exit 1
fi

# Stray copies under ui/ (outside app/, lib/, components/) break `pnpm run build` typecheck.
while IFS= read -r -d '' f; do
  if ! git ls-files --error-unmatch "$f" >/dev/null 2>&1; then
    echo "ERROR: remove untracked stray file (breaks Docker typecheck): $f" >&2
    echo "  rm -f \"$f\"" >&2
    exit 1
  fi
done < <(find ui -maxdepth 1 \( -name '*.ts' -o -name '*.tsx' \) -print0 2>/dev/null)

# --no-cache: avoid stale COPY layers serving old layout.tsx after git pull.
$COMPOSE build --no-cache ui
$COMPOSE up -d ui nginx --force-recreate

echo "Waiting for UI health..."
for _ in $(seq 1 30); do
  if curl -sf "http://127.0.0.1:8090/prowler/api/health" >/dev/null 2>&1; then
    echo "UI healthy"
    break
  fi
  sleep 5
done

curl -sI "http://127.0.0.1:8090/prowler/sign-in" | head -5
echo ""
echo "Open: https://192.168.9.188/prowler/sign-in"
