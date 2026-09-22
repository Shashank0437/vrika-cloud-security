"""Azure management/directory metadata for permission-path investigation."""

import json
from fnmatch import fnmatchcase
from urllib.parse import urlsplit

import requests
from azure.core.exceptions import AzureError, HttpResponseError
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.containerservice import ContainerServiceClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.web import WebSiteManagementClient
from tasks.jobs.attack_paths.inventory import collect_each, load_resources

CLOUD_ERRORS = (AzureError, requests.RequestException)
CAPABILITIES = {
    "role_assignment_write": ("Microsoft.Authorization/roleAssignments/write", False),
    "role_definition_write": ("Microsoft.Authorization/roleDefinitions/write", False),
    "vm_run_command": ("Microsoft.Compute/virtualMachines/runCommand/action", False),
    "vm_extension_write": ("Microsoft.Compute/virtualMachines/extensions/write", False),
    "web_write": ("Microsoft.Web/sites/write", False),
    "web_publish": ("Microsoft.Web/sites/publish/action", False),
    "aks_admin_credentials": (
        "Microsoft.ContainerService/managedClusters/listClusterAdminCredential/action",
        False,
    ),
    "storage_list_keys": ("Microsoft.Storage/storageAccounts/listKeys/action", False),
    "storage_blob_read": (
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
        True,
    ),
    "vault_secret_read": ("Microsoft.KeyVault/vaults/secrets/getSecret/action", True),
    "vault_policy_write": ("Microsoft.KeyVault/vaults/accessPolicies/write", False),
    "identity_assign": (
        "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action",
        False,
    ),
    "sql_admin_write": ("Microsoft.Sql/servers/administrators/write", False),
}


def role_allows(permissions, action, data=False):
    allow_key, deny_key = (
        ("data_actions", "not_data_actions") if data else ("actions", "not_actions")
    )
    action = action.lower()
    return any(
        any(
            fnmatchcase(action, pattern.lower()) for pattern in block.get(allow_key, [])
        )
        and not any(
            fnmatchcase(action, pattern.lower()) for pattern in block.get(deny_key, [])
        )
        for block in permissions
    )


def _load(session, subscription, label, rows, tag):
    load_resources(session, "AzureSubscription", subscription, label, rows, tag)


def load_identities(session, subscription, rows, tag):
    identities = []
    for row in rows:
        identity = row.get("identity") or {}
        principal_ids = [identity.get("principal_id")]
        principal_ids.extend(
            value.get("principal_id")
            for value in (identity.get("user_assigned_identities") or {}).values()
        )
        principal_ids.extend(
            value.get("object_id")
            for value in (row.get("identity_profile") or {}).values()
        )
        identities.extend(
            {"resource": row["id"].lower(), "principal": principal.lower()}
            for principal in principal_ids
            if principal
        )
    session.run(
        """
        MATCH (root:AzureSubscription {id: $subscription})
        UNWIND $identities AS identity
        MATCH (root)-[:RESOURCE]->(w {id: identity.resource})
        MERGE (p:AzurePrincipal {id: identity.principal})
        ON CREATE SET p.firstseen = $tag
        SET p.lastupdated = $tag
        MERGE (root)-[:RESOURCE]->(p)
        MERGE (w)-[:RUNS_AS]->(p)
        """,
        subscription=subscription,
        identities=identities,
        tag=tag,
    ).consume()


def sync_web(session, credentials, subscription, tag, kwargs):
    client = WebSiteManagementClient(credentials, subscription, **kwargs)
    rows = [row.as_dict() for row in client.web_apps.list()]
    _load(
        session,
        subscription,
        "AzureWebApp",
        [
            {
                "id": row["id"].lower(),
                "name": row["name"],
                "kind": row.get("kind"),
                "https_only": row.get("https_only"),
                "public_network_access": row.get("public_network_access"),
                "default_host_name": row.get("default_host_name"),
            }
            for row in rows
        ],
        tag,
    )
    load_identities(session, subscription, rows, tag)


def sync_aks(session, credentials, subscription, tag, kwargs):
    client = ContainerServiceClient(credentials, subscription, **kwargs)
    rows = [row.as_dict() for row in client.managed_clusters.list()]
    _load(
        session,
        subscription,
        "AzureAKSCluster",
        [
            {
                "id": row["id"].lower(),
                "name": row["name"],
                "private_cluster": (row.get("api_server_access_profile") or {}).get(
                    "enable_private_cluster"
                ),
                "local_accounts_disabled": row.get("disable_local_accounts"),
                "azure_rbac_enabled": (row.get("aad_profile") or {}).get(
                    "enable_azure_rbac"
                ),
                "authorized_ip_ranges_json": json.dumps(
                    (row.get("api_server_access_profile") or {}).get(
                        "authorized_ip_ranges", []
                    )
                ),
            }
            for row in rows
        ],
        tag,
    )
    load_identities(session, subscription, rows, tag)


def sync_sql(session, credentials, subscription, tag, kwargs):
    client = SqlManagementClient(credentials, subscription, **kwargs)
    servers = [row.as_dict() for row in client.servers.list()]
    _load(
        session,
        subscription,
        "AzureSQLServer",
        [
            {
                "id": row["id"].lower(),
                "name": row["name"],
                "public_network_access": row.get("public_network_access"),
                "minimal_tls_version": row.get("minimal_tls_version"),
            }
            for row in servers
        ],
        tag,
    )

    def collect(server):
        server_id = server["id"].lower()
        rules = [
            row.as_dict()
            for row in client.firewall_rules.list_by_server(
                server_id.split("/")[4], server["name"]
            )
        ]
        _load(
            session,
            subscription,
            "AzureSQLFirewallRule",
            [
                {
                    "id": row["id"].lower(),
                    "name": row["name"],
                    "server_id": server_id,
                    "start_ip": row.get("start_ip_address"),
                    "end_ip": row.get("end_ip_address"),
                    "world_range": row.get("start_ip_address") == "0.0.0.0"
                    and row.get("end_ip_address") == "255.255.255.255",
                }
                for row in rules
            ],
            tag,
        )
        session.run(
            "MATCH (s:AzureSQLServer {id: $id}), (r:AzureSQLFirewallRule {server_id: $id}) "
            "MERGE (s)-[:HAS_FIREWALL_RULE]->(r)",
            id=server_id,
        ).consume()

    collect_each(servers, collect, CLOUD_ERRORS)


def sync_network(session, credentials, subscription, tag, kwargs):
    client = NetworkManagementClient(credentials, subscription, **kwargs)

    # Independent stages let a denied NSG read coexist with usable NIC inventory.
    def nics():
        rows = [row.as_dict() for row in client.network_interfaces.list_all()]
        _load(
            session,
            subscription,
            "AzureNetworkInterface",
            [
                {
                    "id": row["id"].lower(),
                    "name": row["name"],
                }
                for row in rows
            ],
            tag,
        )
        links = []
        for row in rows:
            for config in row.get("ip_configurations", []):
                links.append(
                    {
                        "nic": row["id"].lower(),
                        "subnet": (config.get("subnet") or {}).get("id", "").lower(),
                        "public_ip": (config.get("public_ip_address") or {})
                        .get("id", "")
                        .lower(),
                        "nsg": (row.get("network_security_group") or {})
                        .get("id", "")
                        .lower(),
                    }
                )
        session.run(
            """
            MATCH (p:AzureSubscription {id: $subscription})
            UNWIND $links AS link
            MATCH (p)-[:RESOURCE]->(nic:AzureNetworkInterface {id: link.nic})
            OPTIONAL MATCH (p)-[:RESOURCE]->(vm:AzureVirtualMachine)
            WHERE link.nic IN vm.network_interface_ids
            FOREACH (_ IN CASE WHEN vm IS NULL THEN [] ELSE [1] END | MERGE (vm)-[:USES_NIC]->(nic))
            FOREACH (_ IN CASE WHEN link.subnet = '' THEN [] ELSE [1] END |
                MERGE (subnet:AzureSubnet {id: link.subnet})
                SET subnet.lastupdated = $tag
                MERGE (p)-[:RESOURCE]->(subnet) MERGE (nic)-[:IN_SUBNET]->(subnet))
            FOREACH (_ IN CASE WHEN link.public_ip = '' THEN [] ELSE [1] END |
                MERGE (ip:AzurePublicIPAddress {id: link.public_ip})
                SET ip.lastupdated = $tag
                MERGE (p)-[:RESOURCE]->(ip) MERGE (nic)-[:HAS_PUBLIC_IP]->(ip))
            FOREACH (_ IN CASE WHEN link.nsg = '' THEN [] ELSE [1] END |
                MERGE (nsg:AzureNetworkSecurityGroup {id: link.nsg})
                SET nsg.lastupdated = $tag
                MERGE (p)-[:RESOURCE]->(nsg) MERGE (nic)-[:USES_NSG]->(nsg))
            """,
            subscription=subscription,
            links=links,
            tag=tag,
        ).consume()

    def subnets():
        rows = [row.as_dict() for row in client.virtual_networks.list_all()]
        links = [
            {
                "subnet": subnet["id"].lower(),
                "nsg": subnet["network_security_group"]["id"].lower(),
            }
            for row in rows
            for subnet in row.get("subnets", [])
            if subnet.get("network_security_group")
        ]
        session.run(
            """
            MATCH (p:AzureSubscription {id: $subscription})
            UNWIND $links AS link
            MERGE (s:AzureSubnet {id: link.subnet}) SET s.lastupdated = $tag
            MERGE (g:AzureNetworkSecurityGroup {id: link.nsg}) SET g.lastupdated = $tag
            MERGE (p)-[:RESOURCE]->(s) MERGE (p)-[:RESOURCE]->(g)
            MERGE (s)-[:USES_NSG]->(g)
            """,
            subscription=subscription,
            links=links,
            tag=tag,
        ).consume()

    def nsgs():
        rows = [row.as_dict() for row in client.network_security_groups.list_all()]
        _load(
            session,
            subscription,
            "AzureNetworkSecurityGroup",
            [{"id": row["id"].lower(), "name": row["name"]} for row in rows],
            tag,
        )
        rules = []
        for row in rows:
            for rule in row.get("security_rules", []) + row.get(
                "default_security_rules", []
            ):
                sources = rule.get("source_address_prefixes") or [
                    rule.get("source_address_prefix")
                ]
                rules.append(
                    {
                        "id": rule["id"].lower(),
                        "name": rule["name"],
                        "nsg_id": row["id"].lower(),
                        "access": rule.get("access"),
                        "direction": rule.get("direction"),
                        "priority": rule.get("priority"),
                        "protocol": rule.get("protocol"),
                        "world_source": any(
                            source in ("*", "Internet", "0.0.0.0/0", "::/0")
                            for source in sources
                        ),
                        "source_json": json.dumps(sources),
                        "destination_json": json.dumps(
                            rule.get("destination_address_prefixes")
                            or [rule.get("destination_address_prefix")]
                        ),
                        "ports_json": json.dumps(
                            rule.get("destination_port_ranges")
                            or [rule.get("destination_port_range")]
                        ),
                    }
                )
        _load(session, subscription, "AzureNSGRule", rules, tag)
        session.run(
            "MATCH (p:AzureSubscription {id: $subscription})-[:RESOURCE]->(r:AzureNSGRule) "
            "MATCH (p)-[:RESOURCE]->(g:AzureNetworkSecurityGroup {id: r.nsg_id}) "
            "MERGE (g)-[:HAS_RULE]->(r)",
            subscription=subscription,
        ).consume()

    def public_ips():
        rows = [row.as_dict() for row in client.public_ip_addresses.list_all()]
        _load(
            session,
            subscription,
            "AzurePublicIPAddress",
            [
                {
                    "id": row["id"].lower(),
                    "name": row["name"],
                    "ip_address": row.get("ip_address"),
                }
                for row in rows
            ],
            tag,
        )

    functions = {
        "interfaces": nics,
        "subnets": subnets,
        "security_groups": nsgs,
        "public_ips": public_ips,
    }
    collect_each(functions, lambda name: functions[name](), CLOUD_ERRORS)


def sync_denies(session, credentials, subscription, tag, kwargs):
    client = AuthorizationManagementClient(credentials, subscription, **kwargs)
    rows = [
        row.as_dict()
        for row in client.deny_assignments.list_for_scope(
            f"/subscriptions/{subscription}"
        )
    ]
    _load(
        session,
        subscription,
        "AzureDenyAssignment",
        [
            {
                "id": row["id"].lower(),
                "name": row.get("deny_assignment_name"),
                "scope": row.get("scope", "").lower(),
                "do_not_apply_to_child_scopes": row.get("do_not_apply_to_child_scopes"),
                "permissions_json": json.dumps(row.get("permissions", [])),
                "principals_json": json.dumps(row.get("principals", [])),
                "excluded_principals_json": json.dumps(
                    row.get("exclude_principals", [])
                ),
            }
            for row in rows
        ],
        tag,
    )


def sync_pim(session, credentials, subscription, tag, kwargs):
    client = AuthorizationManagementClient(credentials, subscription, **kwargs)
    rows = [
        row.as_dict()
        for row in client.role_eligibility_schedule_instances.list_for_scope(
            f"/subscriptions/{subscription}"
        )
    ]
    _load(
        session,
        subscription,
        "AzureEligibleRole",
        [
            {
                "id": row["id"].lower(),
                "principal_id": row.get("principal_id", "").lower(),
                "role_definition_id": row.get("role_definition_id", "").lower(),
                "scope": row.get("scope", "").lower(),
                "start_date_time": str(row.get("start_date_time", "")),
                "end_date_time": str(row.get("end_date_time", "")),
                "access_state": "eligible_requires_activation",
            }
            for row in rows
        ],
        tag,
    )
    session.run(
        """
        MATCH (s:AzureSubscription {id: $subscription})-[:RESOURCE]->(e:AzureEligibleRole)
        WHERE e.principal_id <> ''
        MERGE (p:AzurePrincipal {id: e.principal_id}) SET p.lastupdated = $tag
        MERGE (s)-[:RESOURCE]->(p) MERGE (p)-[:ELIGIBLE_FOR]->(e)
        """,
        subscription=subscription,
        tag=tag,
    ).consume()


def sync_directory(session, credentials, subscription, tag, region):
    host = region.graph_host.rstrip("/")
    scope = region.graph_scope

    # Do not send directory credentials to a foreign pagination URL.
    def get(path):
        url = f"{host}/v1.0/{path}"
        rows = []
        while url:
            if (
                urlsplit(url).scheme != "https"
                or urlsplit(url).netloc != urlsplit(host).netloc
            ):
                raise ValueError("Microsoft Graph returned a foreign pagination URL")
            token = credentials.get_token(scope).token
            response = requests.get(
                url, headers={"Authorization": f"Bearer {token}"}, timeout=30
            )
            if response.status_code >= 400:
                raise HttpResponseError(
                    f"Microsoft Graph {path}: HTTP {response.status_code}: {response.text[:1000]}"
                )
            data = response.json()
            rows.extend(data.get("value", [data]))
            url = data.get("@odata.nextLink")
        return rows

    groups = [
        row["id"]
        for row in session.run(
            "MATCH (:AzureSubscription {id: $subscription})-[:RESOURCE]->(p:AzurePrincipal) "
            "WHERE toLower(p.type) = 'group' RETURN p.id AS id",
            subscription=subscription,
        )
    ]

    def collect(group):
        # Transitive membership avoids bounded-depth queries and cycles.
        rows = get(f"groups/{group}/transitiveMembers?$select=id,displayName")
        _load(
            session,
            subscription,
            "AzurePrincipal",
            [
                {
                    "id": row["id"].lower(),
                    "name": row.get("displayName"),
                    "type": row.get("@odata.type", "").removeprefix(
                        "#microsoft.graph."
                    ),
                }
                for row in rows
            ],
            tag,
        )
        session.run(
            """
            MATCH (s:AzureSubscription {id: $subscription})-[:RESOURCE]->(g:AzurePrincipal {id: $group})
            UNWIND $members AS id
            MATCH (s)-[:RESOURCE]->(m:AzurePrincipal {id: id})
            MERGE (m)-[:TRANSITIVE_MEMBER_OF]->(g)
            """,
            subscription=subscription,
            group=group,
            members=[row["id"].lower() for row in rows],
        ).consume()

    collect_each(groups, collect, CLOUD_ERRORS)


def steps(session, credentials, subscription, tag, kwargs, region):
    result = [
        (name, lambda sync=sync: sync(session, credentials, subscription, tag, kwargs))
        for name, sync in [
            ("app_service", sync_web),
            ("aks", sync_aks),
            ("sql", sync_sql),
            ("network", sync_network),
            ("deny_assignments", sync_denies),
            ("pim_eligibility", sync_pim),
        ]
    ]
    result.append(
        (
            "directory_groups",
            lambda: sync_directory(session, credentials, subscription, tag, region),
        )
    )
    return result
