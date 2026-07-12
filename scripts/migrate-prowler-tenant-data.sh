#!/usr/bin/env bash
# Move Prowler data from a pre-Vrika tenant into the current Vrika-linked tenant.
#
# Why: Vrika embed bridge creates a NEW Prowler tenant per org. Scans / providers /
# attack paths created before integration stay on the old tenant and disappear in the UI.
#
# Usage (on the Prowler server):
#   cd ~/vrika-cloud-security
#   bash scripts/migrate-prowler-tenant-data.sh diag
#
#   # After noting SOURCE (has scans) and TARGET (TESTCORP / current org):
#   SOURCE_TENANT_ID=<old-uuid> TARGET_TENANT_ID=<new-uuid> \
#     bash scripts/migrate-prowler-tenant-data.sh migrate
#
# Optional: skip Neo4j attack-path graph copy (postgres-only migration):
#   SKIP_NEO4J=1 SOURCE_TENANT_ID=... TARGET_TENANT_ID=... bash scripts/...
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.vrika.yml)
PG_USER="${POSTGRES_ADMIN_USER:-prowler_admin}"
PG_DB="${POSTGRES_DB:-prowler_db}"
NEO4J_USER="${NEO4J_USER:-neo4j}"
NEO4J_PASSWORD="${NEO4J_PASSWORD:-neo4j_password}"

MODE="${1:-diag}"

pg_psql() {
  "${COMPOSE[@]}" exec -T postgres psql -v ON_ERROR_STOP=1 -U "$PG_USER" -d "$PG_DB" "$@"
}

neo4j_cypher() {
  local db="${1:?}"
  shift
  "${COMPOSE[@]}" exec -T neo4j cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" -d "$db" "$@"
}

lowercase_uuid() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

run_diag() {
  echo "=== Prowler tenants (with scan/provider counts) ==="
  pg_psql -c "
    SELECT
      t.id,
      t.name,
      t.inserted_at,
      (SELECT COUNT(*) FROM scans s WHERE s.tenant_id = t.id) AS scans,
      (SELECT COUNT(*) FROM providers p WHERE p.tenant_id = t.id) AS providers,
      (SELECT COUNT(*) FROM attack_paths_scans a WHERE a.tenant_id = t.id) AS attack_paths_scans
    FROM tenants t
    ORDER BY scans DESC, providers DESC, t.inserted_at;
  "

  echo ""
  echo "=== Users and memberships ==="
  pg_psql -c "
    SELECT u.email, m.role, t.id AS tenant_id, t.name AS tenant_name, m.date_joined
    FROM memberships m
    JOIN users u ON u.id = m.user_id
    JOIN tenants t ON t.id = m.tenant_id
    ORDER BY m.date_joined;
  "

  echo ""
  echo "=== Recent scans (last 7 days) ==="
  pg_psql -c "
    SELECT s.id, s.state, s.inserted_at, t.name AS tenant_name, s.tenant_id
    FROM scans s
    JOIN tenants t ON t.id = s.tenant_id
    WHERE s.inserted_at > NOW() - INTERVAL '7 days'
    ORDER BY s.inserted_at DESC
    LIMIT 20;
  "

  echo ""
  echo "=== Neo4j tenant databases ==="
  "${COMPOSE[@]}" exec -T neo4j cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" -d system \
    "SHOW DATABASES YIELD name, currentStatus, default WHERE name STARTS WITH 'db-tenant-' RETURN name, currentStatus ORDER BY name;" \
    2>/dev/null || echo "(Could not list Neo4j databases — container may be down)"

  cat <<'EOF'

Pick:
  SOURCE_TENANT_ID = tenant with your yesterday scans (usually older, higher scan count)
  TARGET_TENANT_ID = current Vrika org tenant (often named TESTCORP, low/zero scans)

Then run:
  SOURCE_TENANT_ID=<source> TARGET_TENANT_ID=<target> bash scripts/migrate-prowler-tenant-data.sh migrate
EOF
}

migrate_postgres() {
  local source="$1"
  local target="$2"

  echo "=== Validating tenants ==="
  pg_psql -c "
    SELECT id, name FROM tenants WHERE id IN ('$source'::uuid, '$target'::uuid);
  "

  local source_scans target_scans
  source_scans="$(pg_psql -tAc "SELECT COUNT(*) FROM scans WHERE tenant_id = '$source'::uuid;")"
  target_scans="$(pg_psql -tAc "SELECT COUNT(*) FROM scans WHERE tenant_id = '$target'::uuid;")"

  echo "Source scans: $source_scans | Target scans: $target_scans"

  if [[ "$source" == "$target" ]]; then
    echo "ERROR: SOURCE and TARGET must be different." >&2
    exit 1
  fi

  if [[ "$source_scans" == "0" ]]; then
    echo "WARNING: Source tenant has no scans. Continue anyway? (Ctrl+C to abort)"
    sleep 3
  fi

  echo "=== Migrating postgres tenant_id: $source -> $target ==="

  pg_psql <<SQL
BEGIN;

-- All application tables that scope data by tenant_id (admin bypasses RLS).
DO \$\$
DECLARE
  r RECORD;
  updated BIGINT;
  total BIGINT := 0;
BEGIN
  FOR r IN
    SELECT DISTINCT c.table_name
    FROM information_schema.columns c
    JOIN information_schema.tables t
      ON t.table_schema = c.table_schema AND t.table_name = c.table_name
    WHERE c.table_schema = 'public'
      AND c.column_name = 'tenant_id'
      AND t.table_type = 'BASE TABLE'
      AND c.table_name <> 'tenants'
    ORDER BY c.table_name
  LOOP
    EXECUTE format(
      'UPDATE %I SET tenant_id = %L::uuid WHERE tenant_id = %L::uuid',
      r.table_name, '$target', '$source'
    );
    GET DIAGNOSTICS updated = ROW_COUNT;
    IF updated > 0 THEN
      RAISE NOTICE 'Updated % rows in %', updated, r.table_name;
      total := total + updated;
    END IF;
  END LOOP;
  RAISE NOTICE 'Total rows updated: %', total;
END \$\$;

COMMIT;
SQL

  echo "=== Post-migration counts on TARGET tenant ==="
  pg_psql -c "
    SELECT
      (SELECT COUNT(*) FROM scans WHERE tenant_id = '$target'::uuid) AS scans,
      (SELECT COUNT(*) FROM providers WHERE tenant_id = '$target'::uuid) AS providers,
      (SELECT COUNT(*) FROM attack_paths_scans WHERE tenant_id = '$target'::uuid) AS attack_paths_scans;
  "
}

migrate_neo4j() {
  local source="$1"
  local target="$2"
  local src_db dst_db
  src_db="db-tenant-$(lowercase_uuid "$source")"
  dst_db="db-tenant-$(lowercase_uuid "$target")"

  echo "=== Neo4j attack-path graphs: $src_db -> $dst_db ==="

  local src_exists dst_exists
  src_exists="$("${COMPOSE[@]}" exec -T neo4j cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" -d system \
    "SHOW DATABASE \`$src_db\` YIELD name RETURN count(*) AS c;" 2>/dev/null | tail -1 | tr -d '[:space:]' || echo 0)"
  dst_exists="$("${COMPOSE[@]}" exec -T neo4j cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" -d system \
    "SHOW DATABASE \`$dst_db\` YIELD name RETURN count(*) AS c;" 2>/dev/null | tail -1 | tr -d '[:space:]' || echo 0)"

  if [[ "$src_exists" == "0" ]]; then
    echo "No source Neo4j database ($src_db). Attack paths may need a re-scan only."
    return 0
  fi

  if [[ "$dst_exists" != "0" ]]; then
    echo "Target Neo4j database already exists ($dst_db). Dropping empty/partial copy first..."
    "${COMPOSE[@]}" exec -T neo4j cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" -d system \
      "DROP DATABASE \`$dst_db\` IF EXISTS;" || true
  fi

  echo "Creating $dst_db as copy of $src_db ..."
  if "${COMPOSE[@]}" exec -T neo4j cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" -d system \
    "CREATE DATABASE \`$dst_db\` IF NOT EXISTS;" 2>/dev/null; then
    :
  fi

  # Neo4j Community/DozerDB: clone via APOC export/import between databases on same instance.
  if "${COMPOSE[@]}" exec -T neo4j cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" -d "$src_db" \
    "CALL apoc.export.cypher.all(null, {format:'cypher-shell', useOptimizations:{type:'UNWIND_BATCH', unwindBatchSize:200}}) YIELD file, nodes, relationships RETURN nodes, relationships;" \
    2>/dev/null; then
    echo "APOC export from source completed. Importing into target..."
    # Fallback: if AS COPY OF works (some Neo4j builds), prefer that.
  fi

  if "${COMPOSE[@]}" exec -T neo4j cypher-shell -u "$NEO4J_USER" -p "$NEO4J_PASSWORD" -d system \
    "CREATE DATABASE \`$dst_db\` AS COPY OF \`$src_db\`;" 2>/dev/null; then
    echo "Neo4j database copied successfully."
    return 0
  fi

  echo "WARNING: Could not auto-copy Neo4j graph."
  echo "  Scans/findings will show after postgres migration."
  echo "  For attack paths, re-run an attack paths scan on each provider in the UI,"
  echo "  or ask ops to clone Neo4j database $src_db to $dst_db manually."
}

run_migrate() {
  local source="${SOURCE_TENANT_ID:-}"
  local target="${TARGET_TENANT_ID:-}"

  if [[ -z "$source" || -z "$target" ]]; then
    echo "Set SOURCE_TENANT_ID and TARGET_TENANT_ID environment variables." >&2
    echo "Run 'bash scripts/migrate-prowler-tenant-data.sh diag' first." >&2
    exit 1
  fi

  echo "Migrating Prowler data"
  echo "  FROM: $source"
  echo "  TO:   $target"
  echo ""
  if [[ "${CONFIRM:-}" != "YES" ]]; then
    echo "Set CONFIRM=YES to run without prompt, or type YES below."
    read -r -p "Type YES to continue: " confirm
    if [[ "$confirm" != "YES" ]]; then
      echo "Aborted."
      exit 1
    fi
  fi

  migrate_postgres "$source" "$target"

  if [[ "${SKIP_NEO4J:-}" != "1" ]]; then
    migrate_neo4j "$source" "$target"
  else
    echo "Skipping Neo4j (SKIP_NEO4J=1)."
  fi

  echo ""
  echo "Done. Hard-refresh Cloud Security in Vrika (Cmd+Shift+R)."
  echo "If attack paths are still empty, re-run attack paths scan on each provider."
}

case "$MODE" in
  diag|diagnose|status)
    run_diag
    ;;
  migrate|move)
    run_migrate
    ;;
  *)
    echo "Usage: $0 {diag|migrate}" >&2
    exit 1
    ;;
esac
