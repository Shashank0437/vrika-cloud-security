const ALLOWED_TOOLS = new Set([
  "prowler_hub_list_checks",
  "prowler_hub_semantic_search_checks",
  "prowler_hub_get_check_details",
  "prowler_hub_get_check_code",
  "prowler_hub_get_check_fixer",
  "prowler_hub_list_compliances",
  "prowler_hub_semantic_search_compliances",
  "prowler_hub_get_compliance_details",
  "prowler_hub_list_providers",
  "prowler_hub_get_provider_services",
  "prowler_docs_search",
  "prowler_docs_get_document",
  "prowler_app_search_security_findings",
  "prowler_app_get_finding_details",
  "prowler_app_get_findings_overview",
  "prowler_app_list_finding_groups",
  "prowler_app_get_finding_group_details",
  "prowler_app_list_finding_group_resources",
  "prowler_app_search_providers",
  "prowler_app_list_scans",
  "prowler_app_get_scan",
  "prowler_app_get_mutelist",
  "prowler_app_list_mute_rules",
  "prowler_app_get_mute_rule",
  "prowler_app_get_compliance_overview",
  "prowler_app_get_compliance_framework_state_details",
  "prowler_app_list_resources",
  "prowler_app_get_resource",
  "prowler_app_get_resource_events",
  "prowler_app_get_resources_overview",
  "prowler_app_list_attack_paths_queries",
  "prowler_app_list_attack_paths_scans",
  "prowler_app_run_attack_paths_query",
  "prowler_app_get_attack_paths_cartography_schema",
]);

// Published MCP images also use prowler_* for App tools. Only alias known,
// read-only tools; a namespace match must never grant access to new tools.
export function getCanonicalToolName(name: string): string {
  if (name.startsWith("prowler_")) {
    const candidate = `prowler_app_${name.slice("prowler_".length)}`;
    if (ALLOWED_TOOLS.has(candidate)) return candidate;
  }
  return name;
}

export function isAllowedTool(name: string): boolean {
  return ALLOWED_TOOLS.has(getCanonicalToolName(name));
}
