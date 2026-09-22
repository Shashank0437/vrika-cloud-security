"""GCP metadata collection; edges describe configuration, not effective access."""

import json

from cartography.intel.gcp.clients import build_client
from google.api_core.exceptions import GoogleAPICallError
from google.auth.exceptions import GoogleAuthError
from googleapiclient.errors import HttpError
from tasks.jobs.attack_paths.inventory import collect_each, load_resources

CLOUD_ERRORS = (HttpError, GoogleAPICallError, GoogleAuthError)

# Capabilities are based on role definitions, including custom roles, not names.
PERMISSIONS = {
    "iam.serviceAccounts.getAccessToken": "token_create",
    "iam.serviceAccounts.signBlob": "sign_blob",
    "iam.serviceAccounts.signJwt": "sign_jwt",
    "iam.serviceAccountKeys.create": "key_create",
    "iam.serviceAccounts.actAs": "act_as",
    "iam.serviceAccounts.setIamPolicy": "sa_policy_write",
    "resourcemanager.projects.setIamPolicy": "project_policy_write",
    "iam.roles.update": "role_update",
    "storage.objects.get": "storage_read",
    "secretmanager.versions.access": "secret_read",
    "bigquery.tables.getData": "bigquery_read",
    "cloudkms.cryptoKeyVersions.useToDecrypt": "kms_decrypt",
    "compute.instances.setMetadata": "vm_metadata_write",
    "compute.instances.setServiceAccount": "vm_identity_write",
    "run.services.update": "run_update",
    "cloudfunctions.functions.update": "function_update",
    "container.clusters.getCredentials": "cluster_credentials",
}


def _load(session, project, label, rows, tag):
    load_resources(session, "GCPProject", project, label, rows, tag)


def _pages(resource, method, key, **kwargs):
    from tasks.jobs.attack_paths.gcp import _list_pages

    return _list_pages(resource, method, key, **kwargs)


def sync_roles(session, credentials, project, tag):
    client = build_client("iam", "v1", credentials=credentials)
    names = [
        row["role"]
        for row in session.run(
            "MATCH (:GCPProject {id: $project})-[:RESOURCE]->(b:GCPPolicyBinding) "
            "RETURN DISTINCT b.role AS role",
            project=project,
        )
    ]

    def collect(name):
        resource = client.roles()
        if name.startswith("projects/"):
            resource = client.projects().roles()
        elif name.startswith("organizations/"):
            resource = client.organizations().roles()
        role = resource.get(name=name).execute(num_retries=3)
        permissions = role.get("includedPermissions", [])
        _load(
            session,
            project,
            "GCPRole",
            [
                {
                    "id": name,
                    "name": name,
                    "title": role.get("title"),
                    "stage": role.get("stage"),
                    "deleted": role.get("deleted", False),
                    **{
                        capability: permission in permissions
                        for permission, capability in PERMISSIONS.items()
                    },
                }
            ],
            tag,
        )
        session.run(
            """
            MATCH (p:GCPProject {id: $project})-[:RESOURCE]->(b:GCPPolicyBinding {role: $role})
            MATCH (p)-[:RESOURCE]->(r:GCPRole {id: $role})
            MERGE (b)-[:GRANTS_ROLE]->(r)
            """,
            project=project,
            role=name,
        ).consume()

    collect_each(names, collect, CLOUD_ERRORS)


def sync_ancestors(session, credentials, project, tag):
    from tasks.jobs.attack_paths.gcp import load_policies

    crm = build_client("cloudresourcemanager", "v1", credentials=credentials)
    ancestors = (
        crm.projects().getAncestry(projectId=project, body={}).execute(num_retries=3)
    )
    parents = [
        row["resourceId"]
        for row in ancestors.get("ancestor", [])
        if row["resourceId"]["type"] in ("folder", "organization")
    ]

    def collect(parent):
        kind = parent["type"]
        name = f"{kind}s/{parent['id']}"
        client = build_client("cloudresourcemanager", "v3", credentials=credentials)
        resource = client.folders() if kind == "folder" else client.organizations()
        policy = resource.getIamPolicy(
            resource=name,
            body={"options": {"requestedPolicyVersion": 3}},
        ).execute(num_retries=3)
        label = "GCPFolder" if kind == "folder" else "GCPOrganization"
        _load(session, project, label, [{"id": name, "name": name}], tag)
        load_policies(
            session,
            project,
            tag,
            [
                {
                    "policies": [
                        {
                            "attached_resource": f"//cloudresourcemanager.googleapis.com/{name}",
                            "policy": policy,
                        }
                    ],
                }
            ],
        )
        session.run(
            """
            MATCH (p:GCPProject {id: $project})-[:RESOURCE]->(b:GCPPolicyBinding)
            WHERE b.resource = $resource
            SET b.inherited = true
            MERGE (b)-[:INHERITED_BY]->(p)
            """,
            project=project,
            resource=f"//cloudresourcemanager.googleapis.com/{name}",
        ).consume()

    collect_each(parents, collect, CLOUD_ERRORS)


def sync_groups(session, credentials, project, tag):
    client = build_client("cloudidentity", "v1", credentials=credentials)
    pending = [
        row["email"]
        for row in session.run(
            "MATCH (:GCPProject {id: $project})-[:RESOURCE]->(g:GCPPrincipal {kind: 'group'}) "
            "RETURN g.email AS email",
            project=project,
        )
    ]
    visited = set()

    def collect(email):
        if email in visited:
            return
        visited.add(email)
        group = client.groups().lookup(groupKey_id=email).execute(num_retries=3)
        members = _pages(
            client.groups().memberships(),
            "list",
            "memberships",
            parent=group["name"],
            view="FULL",
        )
        for member in members:
            member_email = (member.get("preferredMemberKey") or {}).get("id")
            if not member_email:
                continue
            kind = (
                "group"
                if member.get("type") == "GROUP"
                else member.get("type", "unknown").lower()
            )
            _load(
                session,
                project,
                "GCPPrincipal",
                [{"id": member_email, "email": member_email, "kind": kind}],
                tag,
            )
            session.run(
                """
                MATCH (p:GCPProject {id: $project})-[:RESOURCE]->(m:GCPPrincipal {email: $member})
                MATCH (p)-[:RESOURCE]->(g:GCPPrincipal {email: $group})
                MERGE (m)-[:MEMBER_OF]->(g)
                """,
                project=project,
                member=member_email,
                group=email,
            ).consume()
            if kind == "group":
                pending.append(member_email)

    collect_each(pending, collect, CLOUD_ERRORS)


def _link_identity(session, project):
    session.run(
        """
        MATCH (p:GCPProject {id: $project})-[:RESOURCE]->(w)
        WHERE w.service_account IS NOT NULL
        MATCH (p)-[:RESOURCE]->(s:GCPServiceAccount {email: w.service_account})
        MERGE (w)-[:RUNS_AS]->(s)
        """,
        project=project,
    ).consume()


def sync_run(session, credentials, project, tag):
    client = build_client("run", "v2", credentials=credentials)
    rows = _pages(
        client.projects().locations().services(),
        "list",
        "services",
        parent=f"projects/{project}/locations/-",
    )
    _load(
        session,
        project,
        "GCPCloudRunService",
        [
            {
                "id": row["name"],
                "name": row["name"],
                "uri": row.get("uri"),
                "ingress": row.get("ingress"),
                "service_account": (row.get("template") or {}).get("serviceAccount"),
                "invoker_iam_disabled": row.get("invokerIamDisabled", False),
            }
            for row in rows
        ],
        tag,
    )
    _link_identity(session, project)


def sync_functions(session, credentials, project, tag):
    client = build_client("cloudfunctions", "v2", credentials=credentials)
    rows = _pages(
        client.projects().locations().functions(),
        "list",
        "functions",
        parent=f"projects/{project}/locations/-",
    )
    _load(
        session,
        project,
        "GCPCloudFunction",
        [
            {
                "id": row["name"],
                "name": row["name"],
                "service_account": (row.get("serviceConfig") or {}).get(
                    "serviceAccountEmail"
                ),
                "ingress": (row.get("serviceConfig") or {}).get("ingressSettings"),
                "uri": (row.get("serviceConfig") or {}).get("uri"),
                "environment": row.get("environment"),
            }
            for row in rows
        ],
        tag,
    )
    _link_identity(session, project)


def sync_gke(session, credentials, project, tag):
    client = build_client("container", "v1", credentials=credentials)
    response = (
        client.projects()
        .locations()
        .clusters()
        .list(parent=f"projects/{project}/locations/-")
        .execute(num_retries=3)
    )
    rows = []
    pools = []
    for cluster in response.get("clusters", []):
        name = f"projects/{project}/locations/{cluster['location']}/clusters/{cluster['name']}"
        private = cluster.get("privateClusterConfig") or {}
        rows.append(
            {
                "id": name,
                "name": cluster["name"],
                "endpoint": cluster.get("endpoint"),
                "private_endpoint": private.get("enablePrivateEndpoint"),
                "authorized_networks": (
                    cluster.get("masterAuthorizedNetworksConfig") or {}
                ).get("enabled"),
                "workload_pool": (cluster.get("workloadIdentityConfig") or {}).get(
                    "workloadPool"
                ),
            }
        )
        for pool in cluster.get("nodePools", []):
            account = (pool.get("config") or {}).get("serviceAccount")
            # "default" is not an email and must not be guessed.
            pools.append(
                {
                    "id": f"{name}/nodePools/{pool['name']}",
                    "name": pool["name"],
                    "cluster_id": name,
                    "service_account": account,
                }
            )
    _load(session, project, "GCPGKECluster", rows, tag)
    _load(session, project, "GCPGKENodePool", pools, tag)
    session.run(
        "MATCH (p:GCPProject {id: $project})-[:RESOURCE]->(pool:GCPGKENodePool) "
        "MATCH (p)-[:RESOURCE]->(c:GCPGKECluster {id: pool.cluster_id}) "
        "MERGE (c)-[:CONTAINS]->(pool)",
        project=project,
    ).consume()
    _link_identity(session, project)


def sync_sql(session, credentials, project, tag):
    client = build_client("sqladmin", "v1beta4", credentials=credentials)
    rows = _pages(client.instances(), "list", "items", project=project)
    _load(
        session,
        project,
        "GCPCloudSQLInstance",
        [
            {
                "id": f"projects/{project}/instances/{row['name']}",
                "name": row["name"],
                "_prowler_uid": row.get("connectionName", row["name"]),
                "database_version": row.get("databaseVersion"),
                "public_ipv4_enabled": (
                    (row.get("settings") or {}).get("ipConfiguration") or {}
                ).get("ipv4Enabled"),
                "ssl_mode": (
                    (row.get("settings") or {}).get("ipConfiguration") or {}
                ).get("sslMode"),
                "authorized_networks_json": json.dumps(
                    ((row.get("settings") or {}).get("ipConfiguration") or {}).get(
                        "authorizedNetworks", []
                    )
                ),
                "world_authorized_network": any(
                    entry.get("value") in ("0.0.0.0/0", "::/0")
                    for entry in (
                        (row.get("settings") or {}).get("ipConfiguration") or {}
                    ).get("authorizedNetworks", [])
                ),
            }
            for row in rows
        ],
        tag,
    )


def sync_bigquery(session, credentials, project, tag):
    client = build_client("bigquery", "v2", credentials=credentials)
    datasets = _pages(
        client.datasets(), "list", "datasets", projectId=project, all=True
    )

    def collect(dataset):
        row = (
            client.datasets()
            .get(projectId=project, datasetId=dataset["datasetReference"]["datasetId"])
            .execute(num_retries=3)
        )
        dataset_id = f"{project}:{row['datasetReference']['datasetId']}"
        _load(
            session,
            project,
            "GCPBigQueryDataset",
            [
                {
                    "id": dataset_id,
                    "name": row["datasetReference"]["datasetId"],
                    "location": row.get("location"),
                    "public_acl": any(
                        entry.get("specialGroup")
                        in ("allUsers", "allAuthenticatedUsers")
                        for entry in row.get("access", [])
                    ),
                    "access_json": json.dumps(row.get("access", [])),
                }
            ],
            tag,
        )

    collect_each(datasets, collect, CLOUD_ERRORS)


def sync_firewalls(session, credentials, project, tag):
    client = build_client("compute", "v1", credentials=credentials)
    rows = _pages(client.firewalls(), "list", "items", project=project)
    from tasks.jobs.attack_paths.gcp import normalize_uid

    _load(
        session,
        project,
        "GCPFirewall",
        [
            {
                "id": normalize_uid(row["selfLink"]),
                "name": row["name"],
                "network": normalize_uid(row["network"]),
                "direction": row.get("direction", "INGRESS"),
                "disabled": row.get("disabled", False),
                "priority": row.get("priority", 1000),
                "world_source": any(
                    value in ("0.0.0.0/0", "::/0")
                    for value in row.get("sourceRanges", [])
                ),
                "allows_traffic": bool(row.get("allowed")),
                "rules_json": json.dumps(
                    {
                        key: row.get(key, [])
                        for key in (
                            "allowed",
                            "denied",
                            "sourceRanges",
                            "targetTags",
                            "targetServiceAccounts",
                        )
                    }
                ),
            }
            for row in rows
        ],
        tag,
    )
    # Match network and targets; higher priority denies and hierarchical policies
    # are not resolved, so this is deliberately not a CAN_ACCESS edge.
    for row in rows:
        session.run(
            """
            MATCH (p:GCPProject {id: $project})-[:RESOURCE]->(vm:GCPInstance)
            MATCH (p)-[:RESOURCE]->(firewall:GCPFirewall {id: $id})
            WHERE $network IN vm.network_ids
                AND ($untargeted OR any(tag IN $tags WHERE tag IN vm.target_tags)
                     OR any(email IN $accounts WHERE email IN vm.service_account_emails))
            MERGE (firewall)-[:TARGETS_CONFIGURATION]->(vm)
            """,
            project=project,
            id=normalize_uid(row["selfLink"]),
            network=normalize_uid(row["network"]),
            tags=row.get("targetTags", []),
            accounts=row.get("targetServiceAccounts", []),
            untargeted=not row.get("targetTags")
            and not row.get("targetServiceAccounts"),
        ).consume()


def sync_keys(session, credentials, project, tag):
    client = build_client("iam", "v1", credentials=credentials)
    emails = [
        row["email"]
        for row in session.run(
            "MATCH (:GCPProject {id: $project})-[:RESOURCE]->(s:GCPServiceAccount) RETURN s.email AS email",
            project=project,
        )
    ]

    def collect(email):
        response = (
            client.projects()
            .serviceAccounts()
            .keys()
            .list(
                name=f"projects/{project}/serviceAccounts/{email}",
                keyTypes="USER_MANAGED",
            )
            .execute(num_retries=3)
        )
        _load(
            session,
            project,
            "GCPServiceAccountKey",
            [
                {
                    "id": row["name"],
                    "name": row["name"],
                    "service_account": email,
                    "disabled": row.get("disabled", False),
                    "valid_after": row.get("validAfterTime"),
                    "valid_before": row.get("validBeforeTime"),
                    "key_origin": row.get("keyOrigin"),
                }
                for row in response.get("keys", [])
            ],
            tag,
        )
        session.run(
            "MATCH (p:GCPProject {id: $project})-[:RESOURCE]->(k:GCPServiceAccountKey {service_account: $email}) "
            "MATCH (p)-[:RESOURCE]->(s:GCPServiceAccount {email: $email}) "
            "MERGE (s)-[:HAS_KEY]->(k)",
            project=project,
            email=email,
        ).consume()

    collect_each(emails, collect, CLOUD_ERRORS)


def sync_forwarding_rules(session, credentials, project, tag):
    from tasks.jobs.attack_paths.gcp import normalize_uid

    client = build_client("compute", "v1", credentials=credentials)
    resource = client.forwardingRules()
    request = resource.aggregatedList(project=project)
    rows = []
    while request is not None:
        response = request.execute(num_retries=3)
        rows.extend(
            rule
            for item in response.get("items", {}).values()
            for rule in item.get("forwardingRules", [])
        )
        request = resource.aggregatedList_next(request, response)
    rows.extend(
        _pages(client.globalForwardingRules(), "list", "items", project=project)
    )
    _load(
        session,
        project,
        "GCPForwardingRule",
        [
            {
                "id": normalize_uid(row["selfLink"]),
                "name": row["name"],
                "ip_address": row.get("IPAddress"),
                "protocol": row.get("IPProtocol"),
                "scheme": row.get("loadBalancingScheme"),
                "target": row.get("target"),
                "ports_json": json.dumps(row.get("ports", [row.get("portRange")])),
            }
            for row in rows
        ],
        tag,
    )


def sync_deny_policies(session, credentials, project, tag):
    client = build_client("iam", "v2", credentials=credentials)
    root = session.run(
        "MATCH (p:GCPProject {id: $project}) RETURN p.projectnumber AS number",
        project=project,
    ).single()
    if root["number"] is None:
        raise ValueError("GCP project number is required to collect deny policies")
    parent = f"policies/cloudresourcemanager.googleapis.com%2Fprojects%2F{root['number']}/denypolicies"
    rows = _pages(client.policies(), "listPolicies", "policies", parent=parent)

    def collect(summary):
        row = client.policies().get(name=summary["name"]).execute(num_retries=3)
        _load(
            session,
            project,
            "GCPDenyPolicy",
            [
                {
                    "id": row["name"],
                    "name": row.get("displayName", row["name"]),
                    "rules_json": json.dumps(row.get("rules", [])),
                    "attachment_scope": f"projects/{root['number']}",
                }
            ],
            tag,
        )

    collect_each(rows, collect, CLOUD_ERRORS)


def steps(session, credentials, project, tag):
    return [
        (name, lambda sync=sync: sync(session, credentials, project, tag))
        for name, sync in [
            ("ancestor_iam", sync_ancestors),
            ("iam_roles", sync_roles),
            ("directory_groups", sync_groups),
            ("cloud_run", sync_run),
            ("cloud_functions", sync_functions),
            ("gke", sync_gke),
            ("cloud_sql", sync_sql),
            ("bigquery", sync_bigquery),
            ("firewalls", sync_firewalls),
            ("service_account_keys", sync_keys),
            ("forwarding_rules", sync_forwarding_rules),
            ("project_deny_policies", sync_deny_policies),
        ]
    ]
