from api.attack_paths.queries.findings import return_paths_with_findings
from api.attack_paths.queries.types import AttackPathsQueryDefinition

AZURE_QUERIES = [
    AttackPathsQueryDefinition(
        id="azure-resource-findings",
        name="Azure Resources with Failed Findings",
        short_description="Trace subscription resources to failed security checks.",
        description="Find failed checks on the selected subscription's ingested resources. "
        "A failed finding is a risk indicator, not proof of an exploitable path.",
        provider="azure",
        cypher="""
            MATCH path = (:AzureSubscription {id: $provider_uid})-[:RESOURCE*0..1]->(resource)
                -[:HAS_FINDING]->(finding:ProwlerFinding {status: 'FAIL'})
            WHERE finding.muted = false

        """
        + return_paths_with_findings("path"),
    ),
    AttackPathsQueryDefinition(
        id="azure-vm-identity-role-assignments",
        name="VM Findings and Managed Identity Role Assignments",
        short_description="Trace risky VMs through managed identities to assigned roles.",
        description="Show VMs with unmuted failed checks and the unconditional direct RBAC "
        "assignments of their managed identities, including collected inherited grants. "
        "Group-derived grants, PIM eligibility and deny effects are not evaluated by this query.",
        provider="azure",
        cypher="""
            MATCH path = (:AzureSubscription {id: $provider_uid})-[:RESOURCE]->(vm:AzureVirtualMachine)
                -[:RUNS_AS]->(:AzurePrincipal)-[:HAS_ROLE_ASSIGNMENT]->(assignment:AzureRoleAssignment)
                -[:ROLE_ASSIGNED]->(role:AzureRoleDefinition)
            WHERE assignment.condition IS NULL
            MATCH finding_path = (vm)-[:HAS_FINDING]->(finding:ProwlerFinding {status: 'FAIL'})
            WHERE finding.muted = false

        """
        + return_paths_with_findings("path", "finding_path"),
    ),
    AttackPathsQueryDefinition(
        id="azure-privileged-role-assignments",
        name="Privileged Azure Role Assignments",
        short_description="Find direct Owner, Contributor and access-administrator assignments.",
        description="Show unconditional assignments of built-in privileged roles "
        "covering this subscription, including collected ancestor grants. Role IDs, not editable display names, determine matches. "
        "This is configured RBAC privilege, not an effective-permission calculation.",
        provider="azure",
        cypher="""
            MATCH root_path = (:AzureSubscription {id: $provider_uid})-[:RESOURCE]->(assignment:AzureRoleAssignment)
            MATCH path = (:AzurePrincipal)-[:HAS_ROLE_ASSIGNMENT]->(assignment)
                -[:ROLE_ASSIGNED]->(role:AzureRoleDefinition)
            WHERE assignment.condition IS NULL AND role.name IN [
                '8e3af657-a8ff-443c-a75c-2fe8c4bcb635',
                'b24988ac-6180-42a0-ab88-20f7382dd24c',
                '18d7d88d-d35e-4fbf-a5c3-7773c20a72d9',
                'f1a07417-d97a-45cb-824c-7a7467783830'
            ]


        """
        + return_paths_with_findings("root_path", "path"),
    ),
    AttackPathsQueryDefinition(
        id="azure-public-blob-containers",
        name="Blob Containers Configured for Public Access",
        short_description="Find public blob containers with permissive account network settings.",
        description="Require Blob/Container public access, account-level public access enabled, "
        "public networking enabled and a default Allow network rule. This checks configuration; "
        "it does not probe reachability or evaluate network security perimeters.",
        provider="azure",
        cypher="""
            MATCH path = (:AzureSubscription {id: $provider_uid})-[:RESOURCE]->(account:AzureStorageAccount)
                -[:CONTAINS]->(container:AzureStorageBlobContainer)
            WHERE container.public_access IN ['Blob', 'Container']
                AND account.allow_blob_public_access = true
                AND account.public_network_access = 'Enabled'
                AND account.network_default_action = 'Allow'
        """
        + return_paths_with_findings("path"),
    ),
    AttackPathsQueryDefinition(
        id="azure-identity-sensitive-resource-scopes",
        name="Managed Identity Role Scopes Covering Vaults and Storage",
        short_description="Trace VM identities to role scopes containing sensitive resources.",
        description="Show unconditional RBAC assignments whose scopes contain a Key Vault "
        "or storage account. SCOPE_CONTAINS means scope membership, not permission to "
        "read secrets or data; inspect the assigned role's actions. Denies and PIM "
        "activation requirements are not evaluated.",
        provider="azure",
        cypher="""
            MATCH path = (:AzureSubscription {id: $provider_uid})-[:RESOURCE]->(:AzureVirtualMachine)
                -[:RUNS_AS]->(:AzurePrincipal)-[:HAS_ROLE_ASSIGNMENT]->(assignment:AzureRoleAssignment)
                -[:SCOPE_CONTAINS]->(target)
            WHERE assignment.condition IS NULL
                AND (target:AzureKeyVault OR target:AzureStorageAccount)
            MATCH role_path = (assignment)-[:ROLE_ASSIGNED]->(:AzureRoleDefinition)

        """
        + return_paths_with_findings("path", "role_path"),
    ),
]


_PERMISSION_ANALYSES = [
    ("role_assignment_write", "RBAC Role Assignment Changes", "AzureScope"),
    ("role_definition_write", "Custom Role Definition Changes", "AzureRoleDefinition"),
    ("vm_run_command", "VM Run Command Grants", "AzureVirtualMachine"),
    ("vm_extension_write", "VM Extension Modification", "AzureVirtualMachine"),
    ("web_write", "App Service Configuration Changes", "AzureWebApp"),
    ("web_publish", "App Service Publishing Grants", "AzureWebApp"),
    (
        "aks_admin_credentials",
        "AKS Administrator Credential Retrieval",
        "AzureAKSCluster",
    ),
    ("storage_list_keys", "Storage Account Key Retrieval", "AzureStorageAccount"),
    ("storage_blob_read", "Storage Blob Data Read Grants", "AzureStorageAccount"),
    ("vault_secret_read", "Key Vault Secret Data Read Grants", "AzureKeyVault"),
    ("vault_policy_write", "Key Vault Access Policy Changes", "AzureKeyVault"),
    ("sql_admin_write", "SQL Server Administrator Changes", "AzureSQLServer"),
]

for capability, title, target_label in _PERMISSION_ANALYSES:
    scope_edge = "SCOPED_AT" if target_label == "AzureScope" else "SCOPE_CONTAINS"
    target_filter = {
        "role_definition_write": "WHERE target.custom_role = true",
        "vault_secret_read": "WHERE target.rbac_authorization = true",
        "vault_policy_write": "WHERE target.rbac_authorization = false",
    }.get(capability, "")
    AZURE_QUERIES.append(
        AttackPathsQueryDefinition(
            id=f"azure-permission-{capability.replace('_', '-')}",
            name=title,
            short_description="Inspect scoped actions in built-in and custom Azure roles.",
            description="Matches role Actions/DataActions with NotActions/NotDataActions "
            "applied per permission block. Includes collected inherited assignments; "
            "conditional assignments are excluded. These are candidate grants, not "
            "effective access: denies, activation state, service configuration and network "
            "controls can prevent use. Management-plane access does not imply data access.",
            provider="azure",
            cypher=f"""
                MATCH (s:AzureSubscription {{id: $provider_uid}})-[:RESOURCE]->(a:AzureRoleAssignment)
                MATCH role_path = (a)-[:ROLE_ASSIGNED]->(role:AzureRoleDefinition)
                WHERE a.condition IS NULL AND role.{capability} = true
                MATCH path = (:AzurePrincipal)-[:HAS_ROLE_ASSIGNMENT]->(a)
                    -[:{scope_edge}]->(target:{target_label})
                {target_filter}

            """
            + return_paths_with_findings("path", "role_path"),
        )
    )

AZURE_QUERIES += [
    AttackPathsQueryDefinition(
        id="azure-inherited-rbac",
        name="Inherited RBAC Assignments",
        short_description="Inspect ancestor assignments returned for this subscription.",
        description="Preserves original management-group/root scope and conditions. "
        "No other subscriptions are enumerated, and effective access is not inferred.",
        provider="azure",
        cypher="""
            MATCH path = (:AzureSubscription {id: $provider_uid})-[:RESOURCE]->(a:AzureRoleAssignment)
                -[:ROLE_ASSIGNED]->(:AzureRoleDefinition)
            WHERE a.inherited_to_subscription = true
        """
        + return_paths_with_findings("path"),
    ),
    AttackPathsQueryDefinition(
        id="azure-group-role-paths",
        name="Directory Group Membership and RBAC",
        short_description="Trace transitive group members to their group's assigned roles.",
        description="Only groups referenced by subscription role assignments are expanded. "
        "Microsoft Graph read permissions are required; membership does not override "
        "conditions, deny assignments or service-specific controls.",
        provider="azure",
        cypher="""
            MATCH (:AzureSubscription {id: $provider_uid})-[:RESOURCE]->(a:AzureRoleAssignment)
            MATCH path = (:AzurePrincipal)-[:TRANSITIVE_MEMBER_OF]->(:AzurePrincipal)
                -[:HAS_ROLE_ASSIGNMENT]->(a)-[:ROLE_ASSIGNED]->(:AzureRoleDefinition)

        """
        + return_paths_with_findings("path"),
    ),
    AttackPathsQueryDefinition(
        id="azure-workload-sensitive-data",
        name="Workload Identities with Data-Read Grants",
        short_description="Trace VM, App Service and AKS identities to scoped data permissions.",
        description="Shows unconditional data actions for Storage and RBAC-enabled Key Vaults. "
        "Does not fetch data or prove access; deny assignments, ABAC, network controls and "
        "workload identity usability must be evaluated separately.",
        provider="azure",
        cypher="""
            MATCH (:AzureSubscription {id: $provider_uid})-[:RESOURCE]->(w)
            MATCH path = (w)-[:RUNS_AS]->(:AzurePrincipal)-[:HAS_ROLE_ASSIGNMENT]->(a:AzureRoleAssignment)
                -[:SCOPE_CONTAINS]->(target)
            MATCH role_path = (a)-[:ROLE_ASSIGNED]->(r:AzureRoleDefinition)
            WHERE a.condition IS NULL
                AND ((target:AzureStorageAccount AND r.storage_blob_read = true)
                  OR (target:AzureKeyVault AND target.rbac_authorization = true AND r.vault_secret_read = true))

        """
        + return_paths_with_findings("path", "role_path"),
    ),
    AttackPathsQueryDefinition(
        id="azure-vault-access-policies",
        name="Key Vault Legacy Secret Access Policies",
        short_description="Inspect explicit secret-get policies on non-RBAC vaults.",
        description="Application-restricted policies are excluded. Network restrictions, "
        "identity authentication and other controls can still block access. No secret values are read.",
        provider="azure",
        cypher="""
            MATCH (:AzureSubscription {id: $provider_uid})-[:RESOURCE]->(v:AzureKeyVault)
            MATCH path = (:AzurePrincipal)-[:HAS_VAULT_POLICY]->(p:AzureVaultAccessPolicy)-[:SCOPE_CONTAINS]->(v)
            WHERE v.rbac_authorization = false AND p.secret_get = true AND p.application_id IS NULL

        """
        + return_paths_with_findings("path"),
    ),
    AttackPathsQueryDefinition(
        id="azure-vm-command-identity-chain",
        name="VM Command Grants to Managed Identity Data Access",
        short_description="Correlate VM command permissions with the VM identity's sensitive-data grants.",
        description="A candidate multi-step path, not proof of executable access. Requires usable "
        "Run Command, the VM identity, and its data role. Conditional assignments are excluded; "
        "deny assignments, Key Vault mode, network restrictions and runtime controls may block the path.",
        provider="azure",
        cypher="""
            MATCH (:AzureSubscription {id: $provider_uid})-[:RESOURCE]->(a:AzureRoleAssignment)
            MATCH path = (:AzurePrincipal)-[:HAS_ROLE_ASSIGNMENT]->(a)-[:SCOPE_CONTAINS]->(vm:AzureVirtualMachine)
                -[:RUNS_AS]->(:AzurePrincipal)-[:HAS_ROLE_ASSIGNMENT]->(data:AzureRoleAssignment)
                -[:SCOPE_CONTAINS]->(target)
            MATCH command_role = (a)-[:ROLE_ASSIGNED]->(r:AzureRoleDefinition)
            MATCH data_role = (data)-[:ROLE_ASSIGNED]->(dr:AzureRoleDefinition)
            WHERE a.condition IS NULL AND data.condition IS NULL AND r.vm_run_command = true
                AND ((target:AzureStorageAccount AND dr.storage_blob_read = true)
                  OR (target:AzureKeyVault AND target.rbac_authorization = true AND dr.vault_secret_read = true))

        """
        + return_paths_with_findings("path", "command_role", "data_role"),
    ),
    AttackPathsQueryDefinition(
        id="azure-public-vm-nsg-candidates",
        name="Public-IP VMs with Broad NSG Allow Rules",
        short_description="Correlate public-IP NICs with NIC or subnet NSG ingress rules.",
        description="Exposure candidates only. Rule priority, destination/port matching, "
        "combined NIC/subnet restrictions, routes and running services are not fully evaluated. "
        "A public IP and an allow rule are not proof of internet reachability.",
        provider="azure",
        cypher="""
            MATCH (:AzureSubscription {id: $provider_uid})-[:RESOURCE]->(vm:AzureVirtualMachine)
            MATCH ip_path = (vm)-[:USES_NIC]->(nic:AzureNetworkInterface)-[:HAS_PUBLIC_IP]->(ip:AzurePublicIPAddress)
            MATCH rule_path = (nic)-[:IN_SUBNET*0..1]->(attachment)-[:USES_NSG]->(:AzureNetworkSecurityGroup)
                -[:HAS_RULE]->(rule:AzureNSGRule)
            WHERE ip.ip_address IS NOT NULL AND rule.direction = 'Inbound'
                AND rule.access = 'Allow' AND rule.world_source = true

        """
        + return_paths_with_findings("ip_path", "rule_path"),
    ),
    AttackPathsQueryDefinition(
        id="azure-public-sql-configuration",
        name="SQL Servers with World-Open Firewall Rules",
        short_description="Find enabled public networking with a full IPv4 firewall range.",
        description="Configuration evidence, not a reachability or authentication test. "
        "The special 0.0.0.0-to-0.0.0.0 Azure-services rule is not treated as world-open.",
        provider="azure",
        cypher="""
            MATCH path = (:AzureSubscription {id: $provider_uid})-[:RESOURCE]->(s:AzureSQLServer)
                -[:HAS_FIREWALL_RULE]->(r:AzureSQLFirewallRule)
            WHERE s.public_network_access = 'Enabled' AND r.world_range = true
        """
        + return_paths_with_findings("path"),
    ),
    AttackPathsQueryDefinition(
        id="azure-pim-eligible-roles",
        name="PIM Eligible Roles Requiring Activation",
        short_description="Inspect role eligibility separately from assigned-role paths.",
        description="Eligibility is not active access. Review start/end times, activation, "
        "approval and MFA requirements. Eligibility nodes never create HAS_ROLE_ASSIGNMENT edges.",
        provider="azure",
        cypher="""
            MATCH root_path = (:AzureSubscription {id: $provider_uid})-[:RESOURCE]->(e:AzureEligibleRole)
            MATCH path = (:AzurePrincipal)-[:ELIGIBLE_FOR]->(e)
        """
        + return_paths_with_findings("root_path", "path"),
    ),
    AttackPathsQueryDefinition(
        id="azure-deny-assignments",
        name="Deny Assignments Requiring Review",
        short_description="Inspect collected deny scopes, principals and permission exclusions.",
        description="Deny evidence is retained for investigation, not fully evaluated against "
        "candidate allow paths. An empty result is not proof that no deny applies if collection failed.",
        provider="azure",
        cypher="""
            MATCH path = (:AzureSubscription {id: $provider_uid})-[:RESOURCE]->(:AzureDenyAssignment)

        """
        + return_paths_with_findings("path"),
    ),
    AttackPathsQueryDefinition(
        id="azure-conditional-rbac",
        name="Conditional RBAC Assignments Requiring Review",
        short_description="Inspect ABAC conditions excluded from unconditional candidate paths.",
        description="Conditions are preserved without assuming they evaluate to true.",
        provider="azure",
        cypher="""
            MATCH path = (:AzureSubscription {id: $provider_uid})-[:RESOURCE]->(a:AzureRoleAssignment)
            WHERE a.condition IS NOT NULL
        """
        + return_paths_with_findings("path"),
    ),
    AttackPathsQueryDefinition(
        id="azure-collection-coverage",
        name="Azure Collection Coverage and Permission Errors",
        short_description="Distinguish empty results from unavailable collection services.",
        description="Read failures remain visible here and in scan errors. A collected service "
        "can legitimately be empty; unavailable data must not be interpreted as absence of risk.",
        provider="azure",
        cypher="""
            MATCH path = (:AzureSubscription {id: $provider_uid})-[:RESOURCE]->(:CloudCollectionStatus)

        """
        + return_paths_with_findings("path"),
    ),
]
