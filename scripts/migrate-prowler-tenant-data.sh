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
#   # Rebuild overview dashboard tables (UI reads scan_summaries, not raw findings):
#   TARGET_TENANT_ID=<testcorp-uuid> bash scripts/migrate-prowler-tenant-data.sh backfill
#
# Example (merge old Prowler tenant into Vrika TESTCORP org):
#   SOURCE_TENANT_ID=292fcdbc-9bc0-4c09-895d-46efe9341977 \
#   TARGET_TENANT_ID=80281f43-521e-457e-ab59-3ca1df936a59 \
#   CONFIRM=YES bash scripts/migrate-prowler-tenant-data.sh migrate
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
  echo "=== Findings + overview tables by tenant ==="
  pg_psql -c "
    SELECT
      t.id AS tenant_id,
      t.name AS tenant_name,
      (SELECT COUNT(*) FROM findings f WHERE f.tenant_id = t.id) AS findings,
      (SELECT COUNT(*) FROM scan_summaries ss WHERE ss.tenant_id = t.id) AS scan_summaries,
      (SELECT COUNT(*) FROM threatscore_snapshots ts WHERE ts.tenant_id = t.id) AS threatscore_snapshots
    FROM tenants t
    WHERE EXISTS (SELECT 1 FROM scans s WHERE s.tenant_id = t.id)
       OR EXISTS (SELECT 1 FROM findings f WHERE f.tenant_id = t.id)
    ORDER BY findings DESC;
  "

  echo ""
  echo "=== Scan states by tenant ==="
  pg_psql -c "
    SELECT t.name, s.tenant_id, s.state, COUNT(*) AS count
    FROM scans s
    JOIN tenants t ON t.id = s.tenant_id
    GROUP BY t.name, s.tenant_id, s.state
    ORDER BY count DESC;
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

If DB has scans/findings but UI still shows 0:
  TARGET_TENANT_ID=<target> bash scripts/migrate-prowler-tenant-data.sh backfill
EOF
}

run_backfill() {
  local target="${TARGET_TENANT_ID:-}"
  if [[ -z "$target" ]]; then
    echo "Set TARGET_TENANT_ID (TESTCORP tenant uuid)." >&2
    exit 1
  fi

  echo "=== Overview data for TARGET before backfill ==="
  pg_psql -c "
    SELECT
      (SELECT COUNT(*) FROM scans WHERE tenant_id = '$target'::uuid AND state = 'completed') AS completed_scans,
      (SELECT COUNT(*) FROM findings WHERE tenant_id = '$target'::uuid) AS findings,
      (SELECT COUNT(*) FROM scan_summaries WHERE tenant_id = '$target'::uuid) AS scan_summaries;
  "

  echo "=== Queueing overview reaggregation (scan_summaries, severity charts, etc.) ==="
  "${COMPOSE[@]}" exec -T api uv run python manage.py shell -c "
from tasks.tasks import reaggregate_all_finding_group_summaries_task
result = reaggregate_all_finding_group_summaries_task.delay(tenant_id='$target')
print('Queued task id:', result.id)
"

  echo ""
  echo "Wait 1-3 minutes for worker to finish, then hard-refresh Cloud Security."
  echo "Watch worker logs: docker compose -f docker-compose.yml -f docker-compose.vrika.yml logs -f worker"
}

merge_duplicate_providers() {
  local source="$1"
  local target="$2"

  echo "=== Merging duplicate cloud providers (keep TESTCORP + add OLD data) ==="
  pg_psql <<SQL
BEGIN;

DO \$\$
DECLARE
  pair RECORD;
  r RECORD;
  updated BIGINT;
BEGIN
  FOR pair IN
    SELECT sp.id AS source_provider_id, tp.id AS target_provider_id
    FROM providers sp
    JOIN providers tp
      ON tp.provider = sp.provider AND tp.uid = sp.uid
    WHERE sp.tenant_id = '$source'::uuid
      AND tp.tenant_id = '$target'::uuid
  LOOP
    RAISE NOTICE 'Re-pointing data from source provider % to target provider %',
      pair.source_provider_id, pair.target_provider_id;

    FOR r IN
      SELECT DISTINCT c.table_name, c.column_name
      FROM information_schema.columns c
      JOIN information_schema.tables t
        ON t.table_schema = c.table_schema AND t.table_name = c.table_name
      WHERE c.table_schema = 'public'
        AND c.column_name = 'provider_id'
        AND c.data_type = 'uuid'
        AND t.table_type = 'BASE TABLE'
        AND c.table_name <> 'providers'
      ORDER BY c.table_name
    LOOP
      EXECUTE format(
        'UPDATE %I SET %I = %L::uuid WHERE %I = %L::uuid',
        r.table_name, r.column_name,
        pair.target_provider_id, r.column_name, pair.source_provider_id
      );
      GET DIAGNOSTICS updated = ROW_COUNT;
      IF updated > 0 THEN
        RAISE NOTICE '  Updated % rows in %.%', updated, r.table_name, r.column_name;
      END IF;
    END LOOP;

    DELETE FROM provider_secrets WHERE provider_id = pair.source_provider_id;
    DELETE FROM integration_provider_mappings WHERE provider_id = pair.source_provider_id;
    DELETE FROM provider_group_memberships WHERE provider_id = pair.source_provider_id;
    DELETE FROM providers WHERE id = pair.source_provider_id;
    RAISE NOTICE 'Removed duplicate source provider %', pair.source_provider_id;
  END LOOP;
END \$\$;

COMMIT;
SQL
}

merge_duplicate_resources() {
  local source="$1"
  local target="$2"

  echo "=== Merging duplicate resources (same provider + uid) ==="
  pg_psql <<SQL
BEGIN;

DO \$\$
DECLARE
  pair RECORD;
  r RECORD;
  updated BIGINT;
BEGIN
  FOR pair IN
    SELECT sr.id AS source_resource_id, tr.id AS target_resource_id
    FROM resources sr
    JOIN resources tr
      ON tr.provider_id = sr.provider_id AND tr.uid = sr.uid
    WHERE sr.tenant_id = '$source'::uuid
      AND tr.tenant_id = '$target'::uuid
  LOOP
    RAISE NOTICE 'Re-pointing data from source resource % to target resource %',
      pair.source_resource_id, pair.target_resource_id;

    FOR r IN
      SELECT DISTINCT c.table_name, c.column_name
      FROM information_schema.columns c
      JOIN information_schema.tables t
        ON t.table_schema = c.table_schema AND t.table_name = c.table_name
      WHERE c.table_schema = 'public'
        AND c.column_name = 'resource_id'
        AND c.data_type = 'uuid'
        AND t.table_type = 'BASE TABLE'
        AND c.table_name <> 'resources'
      ORDER BY c.table_name
    LOOP
      EXECUTE format(
        'UPDATE %I SET %I = %L::uuid WHERE %I = %L::uuid',
        r.table_name, r.column_name,
        pair.target_resource_id, r.column_name, pair.source_resource_id
      );
      GET DIAGNOSTICS updated = ROW_COUNT;
      IF updated > 0 THEN
        RAISE NOTICE '  Updated % rows in %.%', updated, r.table_name, r.column_name;
      END IF;
    END LOOP;

    DELETE FROM resource_tag_mappings a
    USING resource_tag_mappings b
    WHERE a.id > b.id
      AND a.tenant_id = b.tenant_id
      AND a.resource_id = b.resource_id
      AND a.tag_id = b.tag_id;

    DELETE FROM resource_finding_mappings a
    USING resource_finding_mappings b
    WHERE a.id > b.id
      AND a.tenant_id = b.tenant_id
      AND a.resource_id = b.resource_id
      AND a.finding_id = b.finding_id;

    DELETE FROM resource_scan_summaries a
    USING resource_scan_summaries b
    WHERE a.id > b.id
      AND a.tenant_id = b.tenant_id
      AND a.scan_id = b.scan_id
      AND a.resource_id = b.resource_id;

    DELETE FROM resources WHERE id = pair.source_resource_id;
    RAISE NOTICE 'Removed duplicate source resource %', pair.source_resource_id;
  END LOOP;
END \$\$;

COMMIT;
SQL
}

merge_duplicate_resource_tags() {
  local source="$1"
  local target="$2"

  echo "=== Merging duplicate resource tags (same key + value) ==="
  pg_psql <<SQL
BEGIN;

DO \$\$
DECLARE
  st RECORD;
  target_tag_id UUID;
  updated BIGINT;
BEGIN
  FOR st IN
    SELECT id, key, value
    FROM resource_tags
    WHERE tenant_id = '$source'::uuid
  LOOP
    SELECT id INTO target_tag_id
    FROM resource_tags
    WHERE tenant_id = '$target'::uuid
      AND key = st.key
      AND value = st.value
    LIMIT 1;

    IF target_tag_id IS NOT NULL THEN
      UPDATE resource_tag_mappings
      SET tag_id = target_tag_id
      WHERE tag_id = st.id;
      GET DIAGNOSTICS updated = ROW_COUNT;
      IF updated > 0 THEN
        RAISE NOTICE '  Remapped % mappings from tag % to %', updated, st.id, target_tag_id;
      END IF;

      DELETE FROM resource_tag_mappings a
      USING resource_tag_mappings b
      WHERE a.id > b.id
        AND a.tenant_id = b.tenant_id
        AND a.resource_id = b.resource_id
        AND a.tag_id = b.tag_id;

      DELETE FROM resource_tags WHERE id = st.id;
      RAISE NOTICE 'Removed duplicate source tag % (%, %)', st.id, st.key, st.value;
    END IF;
  END LOOP;
END \$\$;

COMMIT;
SQL
}

merge_duplicate_roles() {
  local source="$1"
  local target="$2"

  echo "=== Merging duplicate roles (same name) ==="
  pg_psql <<SQL
BEGIN;

DO \$\$
DECLARE
  pair RECORD;
  r RECORD;
  updated BIGINT;
BEGIN
  FOR pair IN
    SELECT sr.id AS source_role_id, tr.id AS target_role_id, sr.name AS role_name
    FROM roles sr
    JOIN roles tr
      ON tr.name = sr.name
    WHERE sr.tenant_id = '$source'::uuid
      AND tr.tenant_id = '$target'::uuid
  LOOP
    RAISE NOTICE 'Re-pointing data from source role % (%) to target role %',
      pair.role_name, pair.source_role_id, pair.target_role_id;

    FOR r IN
      SELECT DISTINCT c.table_name, c.column_name
      FROM information_schema.columns c
      JOIN information_schema.tables t
        ON t.table_schema = c.table_schema AND t.table_name = c.table_name
      WHERE c.table_schema = 'public'
        AND c.column_name = 'role_id'
        AND c.data_type = 'uuid'
        AND t.table_type = 'BASE TABLE'
        AND c.table_name <> 'roles'
      ORDER BY c.table_name
    LOOP
      EXECUTE format(
        'UPDATE %I SET %I = %L::uuid WHERE %I = %L::uuid',
        r.table_name, r.column_name,
        pair.target_role_id, r.column_name, pair.source_role_id
      );
      GET DIAGNOSTICS updated = ROW_COUNT;
      IF updated > 0 THEN
        RAISE NOTICE '  Updated % rows in %.%', updated, r.table_name, r.column_name;
      END IF;
    END LOOP;

    DELETE FROM role_provider_group_relationship a
    USING role_provider_group_relationship b
    WHERE a.id > b.id
      AND a.role_id = b.role_id
      AND a.provider_group_id = b.provider_group_id;

    DELETE FROM role_user_relationship a
    USING role_user_relationship b
    WHERE a.id > b.id
      AND a.role_id = b.role_id
      AND a.user_id = b.user_id;

    DELETE FROM role_invitation_relationship a
    USING role_invitation_relationship b
    WHERE a.id > b.id
      AND a.role_id = b.role_id
      AND a.invitation_id = b.invitation_id;

    DELETE FROM roles WHERE id = pair.source_role_id;
    RAISE NOTICE 'Removed duplicate source role %', pair.role_name;
  END LOOP;
END \$\$;

COMMIT;
SQL
}

dedupe_tenant_join_rows() {
  local source="$1"
  local target="$2"

  echo "=== Deduplicating join rows already present on TARGET ==="
  pg_psql <<SQL
BEGIN;

DELETE FROM resource_tag_mappings src
USING resource_tag_mappings tgt
WHERE src.tenant_id = '$source'::uuid
  AND tgt.tenant_id = '$target'::uuid
  AND src.resource_id = tgt.resource_id
  AND src.tag_id = tgt.tag_id;

DELETE FROM resource_finding_mappings src
USING resource_finding_mappings tgt
WHERE src.tenant_id = '$source'::uuid
  AND tgt.tenant_id = '$target'::uuid
  AND src.resource_id = tgt.resource_id
  AND src.finding_id = tgt.finding_id;

DELETE FROM resource_scan_summaries src
USING resource_scan_summaries tgt
WHERE src.tenant_id = '$source'::uuid
  AND tgt.tenant_id = '$target'::uuid
  AND src.scan_id = tgt.scan_id
  AND src.resource_id = tgt.resource_id;

COMMIT;
SQL
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

  echo "=== Additive merge: OLD tenant data -> TESTCORP (keeps existing TESTCORP rows) ==="

  merge_duplicate_providers "$source" "$target"
  merge_duplicate_resources "$source" "$target"
  merge_duplicate_resource_tags "$source" "$target"
  merge_duplicate_roles "$source" "$target"
  dedupe_tenant_join_rows "$source" "$target"

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
      (SELECT COUNT(*) FROM findings WHERE tenant_id = '$target'::uuid) AS findings,
      (SELECT COUNT(*) FROM providers WHERE tenant_id = '$target'::uuid) AS providers,
      (SELECT COUNT(*) FROM attack_paths_scans WHERE tenant_id = '$target'::uuid) AS attack_paths_scans,
      (SELECT COUNT(*) FROM scan_summaries WHERE tenant_id = '$target'::uuid) AS scan_summaries;
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
    echo "Target Neo4j database already exists ($dst_db). Keeping both; source graph copied if supported."
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
  echo "=== Backfilling overview tables for dashboard ==="
  TARGET_TENANT_ID="$target" run_backfill

  echo ""
  echo "=== Verify SOURCE is now empty ==="
  pg_psql -c "
    SELECT
      (SELECT COUNT(*) FROM findings WHERE tenant_id = '$source'::uuid) AS source_findings_left,
      (SELECT COUNT(*) FROM findings WHERE tenant_id = '$target'::uuid) AS target_findings;
  "

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
  backfill|reaggregate)
    run_backfill
    ;;
  *)
    echo "Usage: $0 {diag|migrate|backfill}" >&2
    exit 1
    ;;
esac
