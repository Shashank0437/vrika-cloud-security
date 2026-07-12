#!/usr/bin/env bash
# One-shot: pull latest, clean stray UI files, migrate tenant data, backfill, verify.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SOURCE_TENANT_ID="${SOURCE_TENANT_ID:-292fcdbc-9bc0-4c09-895d-46efe9341977}"
TARGET_TENANT_ID="${TARGET_TENANT_ID:-80281f43-521e-457e-ab59-3ca1df936a59}"
COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.vrika.yml)
PG_USER="${POSTGRES_ADMIN_USER:-prowler_admin}"
PG_DB="${POSTGRES_DB:-prowler_db}"

echo "=== git pull ==="
git fetch origin
git merge origin/main

echo "=== remove stray ui/*.ts(x) not in git ==="
while IFS= read -r -d '' f; do
  if ! git ls-files --error-unmatch "$f" >/dev/null 2>&1; then
    echo "  rm $f"
    rm -f "$f"
  fi
done < <(find ui -maxdepth 1 \( -name '*.ts' -o -name '*.tsx' \) -print0 2>/dev/null || true)

need_migrate=0
src_findings="$("${COMPOSE[@]}" exec -T postgres psql -U "$PG_USER" -d "$PG_DB" -tAc \
  "SELECT COUNT(*) FROM findings WHERE tenant_id = '$SOURCE_TENANT_ID'::uuid;" | tr -d '[:space:]')"
tgt_findings="$("${COMPOSE[@]}" exec -T postgres psql -U "$PG_USER" -d "$PG_DB" -tAc \
  "SELECT COUNT(*) FROM findings WHERE tenant_id = '$TARGET_TENANT_ID'::uuid;" | tr -d '[:space:]')"

echo "Source findings: $src_findings | Target findings: $tgt_findings"

if [[ "$src_findings" != "0" ]]; then
  need_migrate=1
elif [[ "$tgt_findings" == "0" ]]; then
  echo "ERROR: Source empty but TARGET has no findings — check tenant UUIDs." >&2
  exit 1
else
  echo "Migration already done (source empty, target has data). Skipping migrate."
fi

if [[ "$need_migrate" == "1" ]]; then
  echo "=== migrate ==="
  CONFIRM=YES SOURCE_TENANT_ID="$SOURCE_TENANT_ID" TARGET_TENANT_ID="$TARGET_TENANT_ID" \
    bash scripts/migrate-prowler-tenant-data.sh migrate
else
  echo "=== backfill only ==="
  TARGET_TENANT_ID="$TARGET_TENANT_ID" bash scripts/migrate-prowler-tenant-data.sh backfill
fi

echo "=== final counts ==="
"${COMPOSE[@]}" exec -T postgres psql -U "$PG_USER" -d "$PG_DB" -c "
SELECT
  (SELECT COUNT(*) FROM scans WHERE tenant_id = '$TARGET_TENANT_ID'::uuid) AS scans,
  (SELECT COUNT(*) FROM findings WHERE tenant_id = '$TARGET_TENANT_ID'::uuid) AS findings,
  (SELECT COUNT(*) FROM scan_summaries WHERE tenant_id = '$TARGET_TENANT_ID'::uuid) AS summaries;
"

echo "=== RLS check via Django ==="
"${COMPOSE[@]}" exec -T api uv run python manage.py shell -c "
from api.db_utils import rls_transaction
from api.models import Finding, Scan
tid = '$TARGET_TENANT_ID'
with rls_transaction(tid):
    print('RLS findings', Finding.objects.count())
    print('RLS scans', Scan.objects.count())
"

echo "Done. Hard-refresh: https://192.168.9.188/dashboard/cloud-security"
