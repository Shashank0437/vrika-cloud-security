from api.attack_paths.queries.findings import return_paths_with_findings
from api.attack_paths.queries.types import AttackPathsQueryDefinition

GCP_QUERIES = [
    AttackPathsQueryDefinition(
        id="gcp-resource-findings",
        name="GCP Resources with Failed Findings",
        short_description="Trace project resources to their failed security checks.",
        description="Find failed checks on the selected project's ingested resources. "
        "A failed finding is a risk indicator, not proof of an exploitable path.",
        provider="gcp",
        cypher="""
            MATCH path = (project:GCPProject {id: $provider_uid})-[:RESOURCE*0..1]->(resource)
                -[:HAS_FINDING]->(finding:ProwlerFinding {status: 'FAIL'})
            WHERE finding.muted = false

        """
        + return_paths_with_findings("path"),
    ),
    AttackPathsQueryDefinition(
        id="gcp-compute-service-account-bindings",
        name="Compute Findings and Service Account IAM Bindings",
        short_description="Trace risky VMs through attached service accounts to IAM bindings.",
        description="Show VMs with unmuted failed checks, their attached service accounts, "
        "and direct unconditional IAM bindings on ingested resources or the project. "
        "OAuth scopes, deny policies, organization inheritance and group membership "
        "are not evaluated; these are configured grants, not proven effective access.",
        provider="gcp",
        cypher="""
            MATCH path = (:GCPProject {id: $provider_uid})-[:RESOURCE]->(vm:GCPInstance)
                -[:RUNS_AS]->(:GCPServiceAccount)-[:HAS_ALLOW_POLICY]->(binding:GCPPolicyBinding)
                -[:APPLIES_TO]->(target)
            WHERE binding.has_condition = false
            MATCH finding_path = (vm)-[:HAS_FINDING]->(finding:ProwlerFinding {status: 'FAIL'})
            WHERE finding.muted = false

        """
        + return_paths_with_findings("path", "finding_path"),
    ),
    AttackPathsQueryDefinition(
        id="gcp-public-iam-bindings",
        name="Public IAM Bindings",
        short_description="Find unconditional bindings to allUsers or allAuthenticatedUsers.",
        description="Show direct public IAM configuration on ingested resources. "
        "allAuthenticatedUsers requires a Google identity and is not anonymous access. "
        "Public access prevention and inherited deny policies can override these grants.",
        provider="gcp",
        cypher="""
            MATCH path = (:GCPProject {id: $provider_uid})-[:RESOURCE]->(binding:GCPPolicyBinding)
                -[:APPLIES_TO]->(resource)
            WHERE binding.is_public = true AND binding.has_condition = false
        """
        + return_paths_with_findings("path"),
    ),
    AttackPathsQueryDefinition(
        id="gcp-service-account-token-creator",
        name="Direct Service Account Token Creator Grants",
        short_description="Trace direct unconditional Token Creator grants to service accounts.",
        description="Show principals directly assigned roles/iam.serviceAccountTokenCreator "
        "on a service account. Conditional and project-inherited bindings are excluded. "
        "Deny policies and group membership are not evaluated.",
        provider="gcp",
        cypher="""
            MATCH root_path = (:GCPProject {id: $provider_uid})-[:RESOURCE]->(binding:GCPPolicyBinding)
            WHERE binding.role = 'roles/iam.serviceAccountTokenCreator'
                AND binding.has_condition = false
            MATCH path = (principal:GCPPrincipal)-[:HAS_ALLOW_POLICY]->(binding)
                -[:APPLIES_TO]->(target:GCPServiceAccount)

        """
        + return_paths_with_findings("root_path", "path"),
    ),
    AttackPathsQueryDefinition(
        id="gcp-broad-project-roles",
        name="Project Owner and Editor Grants",
        short_description="Find direct unconditional Owner or Editor bindings on this project.",
        description="Trace principals to direct roles/owner and roles/editor project bindings. "
        "This identifies broad configured privileges; it does not evaluate deny policies "
        "or expand groups and organization-inherited grants.",
        provider="gcp",
        cypher="""
            MATCH path = (principal:GCPPrincipal)-[:HAS_ALLOW_POLICY]->(binding:GCPPolicyBinding)
                -[:APPLIES_TO]->(project:GCPProject {id: $provider_uid})
            WHERE binding.role IN ['roles/owner', 'roles/editor']
                AND binding.has_condition = false

        """
        + return_paths_with_findings("path"),
    ),
]


_PERMISSION_ANALYSES = [
    ("token_create", "Service Account Token Creation", "GCPServiceAccount"),
    ("sign_blob", "Service Account Blob Signing", "GCPServiceAccount"),
    ("sign_jwt", "Service Account JWT Signing", "GCPServiceAccount"),
    ("key_create", "Service Account Key Creation", "GCPServiceAccount"),
    ("act_as", "Service Account Act-As Grants", "GCPServiceAccount"),
    ("sa_policy_write", "Service Account IAM Policy Changes", "GCPServiceAccount"),
    ("project_policy_write", "Project IAM Policy Changes", "GCPProject"),
    ("role_update", "Custom IAM Role Modification", "GCPRole"),
    ("storage_read", "Storage Object Read Grants", "GCPBucket"),
    ("secret_read", "Secret Version Read Grants", "GCPSecretManagerSecret"),
    ("bigquery_read", "BigQuery Data Read Grants", "GCPBigQueryDataset"),
    ("vm_metadata_write", "VM Metadata Modification", "GCPInstance"),
    ("vm_identity_write", "VM Service Account Replacement", "GCPInstance"),
    ("run_update", "Cloud Run Service Modification", "GCPCloudRunService"),
    ("function_update", "Cloud Function Modification", "GCPCloudFunction"),
    ("cluster_credentials", "GKE Credential Retrieval Grants", "GCPGKECluster"),
]

for capability, title, target_label in _PERMISSION_ANALYSES:
    target_filter = (
        "WHERE target.id STARTS WITH 'projects/' + $provider_uid + '/roles/'"
        if capability == "role_update"
        else ""
    )
    GCP_QUERIES.append(
        AttackPathsQueryDefinition(
            id=f"gcp-permission-{capability.replace('_', '-')}",
            name=title,
            short_description="Inspect configured permissions from predefined and custom IAM roles.",
            description="Trace unconditional IAM role permissions to resources inside their "
            "scope, including collected project/folder/organization grants. This is a "
            "candidate permission path, not proven effective access: deny policies, "
            "principal access boundaries, OAuth scopes and service-specific prerequisites "
            "can block use. Workload modification/actAs alone does not establish escalation.",
            provider="gcp",
            cypher=f"""
                MATCH (root:GCPProject {{id: $provider_uid}})-[:RESOURCE]->(b:GCPPolicyBinding)
                MATCH role_path = (b)-[:GRANTS_ROLE]->(role:GCPRole)
                WHERE b.has_condition = false AND role.{capability} = true
                    AND role.deleted = false AND coalesce(role.stage, '') <> 'DISABLED'
                MATCH path = (principal:GCPPrincipal)-[:HAS_ALLOW_POLICY]->(b)
                    -[:SCOPE_CONTAINS]->(target:{target_label})
                {target_filter}

            """
            + return_paths_with_findings("path", "role_path"),
        )
    )

GCP_QUERIES += [
    AttackPathsQueryDefinition(
        id="gcp-inherited-iam",
        name="Inherited Folder and Organization IAM",
        short_description="Inspect ancestor grants inherited by this connected project.",
        description="Shows allow policies read only from the connected project's ancestors. "
        "Conditions remain visible; inherited grants are not a calculation of effective access.",
        provider="gcp",
        cypher="""
            MATCH path = (principal:GCPPrincipal)-[:HAS_ALLOW_POLICY]->(b:GCPPolicyBinding)
                -[:INHERITED_BY]->(:GCPProject {id: $provider_uid})
            OPTIONAL MATCH role_path = (b)-[:GRANTS_ROLE]->(:GCPRole)

        """
        + return_paths_with_findings("path", "role_path"),
    ),
    AttackPathsQueryDefinition(
        id="gcp-group-permission-paths",
        name="Group Membership and IAM Grants",
        short_description="Trace collected group memberships into IAM bindings.",
        description="Shows up to eight membership hops for groups referenced by collected "
        "IAM policies. Missing Cloud Identity read permissions leave membership incomplete. "
        "Deny policies and conditions are not evaluated.",
        provider="gcp",
        cypher="""
            MATCH (:GCPProject {id: $provider_uid})-[:RESOURCE]->(b:GCPPolicyBinding)
            MATCH path = (:GCPPrincipal)-[:MEMBER_OF*1..8]->(:GCPPrincipal)-[:HAS_ALLOW_POLICY]->(b)

        """
        + return_paths_with_findings("path"),
    ),
    AttackPathsQueryDefinition(
        id="gcp-workload-sensitive-data",
        name="Workload Identities with Sensitive Data Grants",
        short_description="Trace compute, serverless and GKE node identities to data-read grants.",
        description="Correlates attached identities with unconditional role permissions "
        "covering buckets, secrets or datasets. This is configured access, not verified "
        "data access; denies, OAuth scopes, network controls and API state still apply.",
        provider="gcp",
        cypher="""
            MATCH (:GCPProject {id: $provider_uid})-[:RESOURCE]->(w)
            MATCH path = (w)-[:RUNS_AS]->(:GCPServiceAccount)-[:HAS_ALLOW_POLICY]->(b:GCPPolicyBinding)
                -[:SCOPE_CONTAINS]->(target)
            MATCH role_path = (b)-[:GRANTS_ROLE]->(role:GCPRole)
            WHERE b.has_condition = false AND role.deleted = false
                AND coalesce(role.stage, '') <> 'DISABLED'
                AND ((target:GCPBucket AND role.storage_read = true)
                  OR (target:GCPSecretManagerSecret AND role.secret_read = true)
                  OR (target:GCPBigQueryDataset AND role.bigquery_read = true))

        """
        + return_paths_with_findings("path", "role_path"),
    ),
    AttackPathsQueryDefinition(
        id="gcp-impersonation-data-chain",
        name="Service Account Impersonation to Sensitive Data",
        short_description="Correlate token-creation grants with the target service account's data grants.",
        description="Candidate multi-step chain requiring both token creation and a target "
        "service account data-read grant. Conditions are excluded. Denies, OAuth scopes, "
        "network restrictions and service prerequisites can still prevent exploitation.",
        provider="gcp",
        cypher="""
            MATCH (p:GCPProject {id: $provider_uid})-[:RESOURCE]->(b:GCPPolicyBinding)
            MATCH path = (:GCPPrincipal)-[:HAS_ALLOW_POLICY]->(b)-[:SCOPE_CONTAINS]->(sa:GCPServiceAccount)
                -[:HAS_ALLOW_POLICY]->(data:GCPPolicyBinding)-[:SCOPE_CONTAINS]->(target)
            MATCH first_role = (b)-[:GRANTS_ROLE]->(r:GCPRole)
            MATCH second_role = (data)-[:GRANTS_ROLE]->(dr:GCPRole)
            WHERE b.has_condition = false AND data.has_condition = false
                AND r.token_create = true AND r.deleted = false AND dr.deleted = false
                AND coalesce(r.stage, '') <> 'DISABLED' AND coalesce(dr.stage, '') <> 'DISABLED'
                AND ((target:GCPBucket AND dr.storage_read = true)
                  OR (target:GCPSecretManagerSecret AND dr.secret_read = true)
                  OR (target:GCPBigQueryDataset AND dr.bigquery_read = true))

        """
        + return_paths_with_findings("path", "first_role", "second_role"),
    ),
    AttackPathsQueryDefinition(
        id="gcp-public-vm-firewall-candidates",
        name="Public-IP VMs Targeted by Broad Ingress Rules",
        short_description="Correlate public IPs with matching VPC firewall allow-rule targets.",
        description="Matches VPC networks and firewall target tags/service accounts. "
        "Higher-priority denies, hierarchical firewall policies, routes, port/service state "
        "and IPv4/IPv6 compatibility are not resolved: these are exposure candidates, not confirmed reachability.",
        provider="gcp",
        cypher="""
            MATCH path = (:GCPProject {id: $provider_uid})-[:RESOURCE]->(f:GCPFirewall)
                -[:TARGETS_CONFIGURATION]->(vm:GCPInstance)
            WHERE f.disabled = false AND f.direction = 'INGRESS' AND f.world_source = true
                AND f.allows_traffic = true AND vm.has_public_ip = true

        """
        + return_paths_with_findings("path"),
    ),
    AttackPathsQueryDefinition(
        id="gcp-public-sql-configuration",
        name="Cloud SQL with World-Open Authorized Networks",
        short_description="Find public IPv4 configuration combined with unrestricted authorized networks.",
        description="Configuration evidence only. Expired authorized networks, database "
        "authentication, connector enforcement and other controls can prevent access.",
        provider="gcp",
        cypher="""
            MATCH path = (:GCPProject {id: $provider_uid})-[:RESOURCE]->(sql:GCPCloudSQLInstance)
            WHERE sql.public_ipv4_enabled = true AND sql.world_authorized_network = true

        """
        + return_paths_with_findings("path"),
    ),
    AttackPathsQueryDefinition(
        id="gcp-public-bigquery-acls",
        name="BigQuery Datasets with Public ACL Entries",
        short_description="Find dataset ACL entries for allUsers or allAuthenticatedUsers.",
        description="Dataset ACL configuration is not proof of anonymous data access. "
        "allAuthenticatedUsers requires authentication; organization and perimeter controls may restrict use.",
        provider="gcp",
        cypher="""
            MATCH path = (:GCPProject {id: $provider_uid})-[:RESOURCE]->(dataset:GCPBigQueryDataset)
            WHERE dataset.public_acl = true
        """
        + return_paths_with_findings("path"),
    ),
    AttackPathsQueryDefinition(
        id="gcp-serverless-and-gke-identities",
        name="Serverless and GKE Node Identities",
        short_description="Inspect Cloud Run, Cloud Functions and GKE node-pool identity attachments.",
        description="GKE node identities do not establish pod Workload Identity permissions. "
        "Missing or implicit default identity values are not guessed.",
        provider="gcp",
        cypher="""
            MATCH path = (:GCPProject {id: $provider_uid})-[:RESOURCE]->(w)-[:RUNS_AS]->(:GCPServiceAccount)
            WHERE w:GCPCloudRunService OR w:GCPCloudFunction OR w:GCPGKENodePool

        """
        + return_paths_with_findings("path"),
    ),
    AttackPathsQueryDefinition(
        id="gcp-conditional-iam",
        name="Conditional IAM Grants Requiring Review",
        short_description="Inspect bindings excluded from unconditional permission paths.",
        description="Conditions are preserved as evidence, not evaluated or assumed true.",
        provider="gcp",
        cypher="""
            MATCH path = (:GCPProject {id: $provider_uid})-[:RESOURCE]->(b:GCPPolicyBinding)
            WHERE b.has_condition = true
        """
        + return_paths_with_findings("path"),
    ),
    AttackPathsQueryDefinition(
        id="gcp-user-managed-service-account-keys",
        name="User-Managed Service Account Keys",
        short_description="Inspect non-disabled user-managed key metadata and attached IAM grants.",
        description="No key material is fetched. Non-disabled does not mean currently valid: "
        "review valid-after/valid-before timestamps. Key possession is not inferred.",
        provider="gcp",
        cypher="""
            MATCH path = (:GCPProject {id: $provider_uid})-[:RESOURCE]->(s:GCPServiceAccount)
                -[:HAS_KEY]->(k:GCPServiceAccountKey)
            WHERE k.disabled = false
            OPTIONAL MATCH role_path = (s)-[:HAS_ALLOW_POLICY]->(:GCPPolicyBinding)

        """
        + return_paths_with_findings("path", "role_path"),
    ),
    AttackPathsQueryDefinition(
        id="gcp-external-forwarding-rules",
        name="External Forwarding Rule Configuration",
        short_description="Inspect external load-balancer/forwarding endpoints and target references.",
        description="An external forwarding rule is configuration evidence, not proof "
        "that its backend is healthy or reachable. Backend policies and routing are not resolved.",
        provider="gcp",
        cypher="""
            MATCH path = (:GCPProject {id: $provider_uid})-[:RESOURCE]->(f:GCPForwardingRule)
            WHERE f.scheme IN ['EXTERNAL', 'EXTERNAL_MANAGED'] AND f.ip_address IS NOT NULL
        """
        + return_paths_with_findings("path"),
    ),
    AttackPathsQueryDefinition(
        id="gcp-project-deny-policies",
        name="Project IAM Deny Policy Evidence",
        short_description="Inspect directly attached project deny rules alongside candidate allow paths.",
        description="Deny rules are retained but not evaluated against every allow path. "
        "Ancestor denies and principal access boundaries are not included.",
        provider="gcp",
        cypher="""
            MATCH path = (:GCPProject {id: $provider_uid})-[:RESOURCE]->(:GCPDenyPolicy)

        """
        + return_paths_with_findings("path"),
    ),
    AttackPathsQueryDefinition(
        id="gcp-collection-coverage",
        name="GCP Collection Coverage and Permission Errors",
        short_description="Distinguish empty results from unavailable collection services.",
        description="A collected service can contain zero resources. Errors indicate incomplete "
        "coverage, not absence of risk; review missing APIs and permissions before interpreting other queries.",
        provider="gcp",
        cypher="""
            MATCH path = (:GCPProject {id: $provider_uid})-[:RESOURCE]->(:CloudCollectionStatus)

        """
        + return_paths_with_findings("path"),
    ),
]
