from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from api.attack_paths.queries.azure import AZURE_QUERIES
from api.attack_paths.queries.gcp import GCP_QUERIES
from azure.core.exceptions import HttpResponseError
from tasks.jobs.attack_paths import azure, azure_extended, gcp, gcp_extended
from tasks.jobs.attack_paths.inventory import CollectionError, collect_each, run_steps


@pytest.mark.parametrize(
    ("blocks", "action", "data", "expected"),
    [
        (
            [{"actions": ["*"], "not_actions": ["Microsoft.Authorization/*"]}],
            "Microsoft.Authorization/roleAssignments/write",
            False,
            False,
        ),
        (
            [{"actions": ["*"]}],
            "Microsoft.KeyVault/vaults/secrets/getSecret/action",
            True,
            False,
        ),
        (
            [
                {
                    "data_actions": ["Microsoft.KeyVault/*"],
                    "not_data_actions": ["*/secrets/*"],
                }
            ],
            "Microsoft.KeyVault/vaults/secrets/getSecret/action",
            True,
            False,
        ),
        (
            [
                {"actions": ["*"], "not_actions": ["*/write"]},
                {"actions": ["Microsoft.Authorization/roleAssignments/write"]},
            ],
            "microsoft.authorization/roleAssignments/write",
            False,
            True,
        ),
        (
            [{"data_actions": ["Microsoft.Storage/*/read"]}],
            "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
            True,
            True,
        ),
    ],
)
def test_azure_role_permission_block_semantics(blocks, action, data, expected):
    assert azure_extended.role_allows(blocks, action, data) == expected


def test_partial_child_failure_does_not_skip_siblings():
    visited = []

    def collect(value):
        visited.append(value)
        if value == "denied":
            raise HttpResponseError("Forbidden")

    with pytest.raises(CollectionError, match="denied"):
        collect_each(["first", "denied", "last"], collect, (HttpResponseError,))
    assert visited == ["first", "denied", "last"]


def test_collection_error_visible_and_other_steps_continue(graph):
    graph.run("CREATE (:AzureSubscription {id: 's'})").consume()
    visited = []

    def denied():
        raise HttpResponseError("Missing Network/read")

    errors = run_steps(
        graph,
        "AzureSubscription",
        "s",
        [("network", denied), ("other", lambda: visited.append(True))],
        (HttpResponseError,),
        1,
        lambda _: None,
    )
    assert "network" in errors and visited == [True]
    rows = {
        row["n"]["service"]: row["n"]
        for row in graph.run("MATCH (n:CloudCollectionStatus) RETURN n")
    }
    assert rows["network"]["status"] == "error"
    assert rows["other"]["status"] == "collected"


def _query(catalog, query_id):
    return next(query.cypher for query in catalog if query.id == query_id)


def test_gcp_custom_role_conditional_and_scope_boundaries(graph):
    graph.run("""
        CREATE (p:GCPProject {id: 'p'}), (other:GCPProject {id: 'other'}),
          (sa:GCPServiceAccount:GCPPrincipal {id: 'sa', email: 'sa@p'}),
          (u:GCPPrincipal {id: 'user', email: 'user@p'}),
          (b:GCPPolicyBinding {id: 'b', role: 'projects/p/roles/custom', has_condition: false}),
          (p)-[:RESOURCE]->(sa), (p)-[:RESOURCE]->(b), (p)-[:RESOURCE]->(u),
          (u)-[:HAS_ALLOW_POLICY]->(b), (b)-[:SCOPE_CONTAINS]->(sa)
    """).consume()
    client = MagicMock()
    client.projects().roles().get().execute.return_value = {
        "title": "Custom",
        "includedPermissions": ["iam.serviceAccounts.getAccessToken"],
    }
    with patch.object(gcp_extended, "build_client", return_value=client):
        gcp_extended.sync_roles(graph, object(), "p", 1)
    query = _query(GCP_QUERIES, "gcp-permission-token-create")
    assert list(graph.run(query, provider_uid="p"))
    assert not list(graph.run(query, provider_uid="other"))
    graph.run("MATCH (b:GCPPolicyBinding) SET b.has_condition = true").consume()
    assert not list(graph.run(query, provider_uid="p"))
    graph.run(
        "MATCH (b:GCPPolicyBinding), (r:GCPRole) SET b.has_condition = false, r.deleted = true"
    ).consume()
    assert not list(graph.run(query, provider_uid="p"))


def test_azure_pim_never_becomes_active_rbac(graph):
    graph.run("CREATE (:AzureSubscription {id: 's'})").consume()
    client = MagicMock()
    client.role_eligibility_schedule_instances.list_for_scope.return_value = [
        SimpleNamespace(
            as_dict=lambda: {
                "id": "/subscriptions/s/eligible/one",
                "principal_id": "USER",
                "role_definition_id": "ROLE",
                "scope": "/subscriptions/s",
            }
        )
    ]
    with patch.object(
        azure_extended, "AuthorizationManagementClient", return_value=client
    ):
        azure_extended.sync_pim(graph, object(), "s", 1, {})
    assert list(
        graph.run(_query(AZURE_QUERIES, "azure-pim-eligible-roles"), provider_uid="s")
    )
    assert (
        graph.run("MATCH ()-[r:HAS_ROLE_ASSIGNMENT]->() RETURN count(r) AS n").single()[
            "n"
        ]
        == 0
    )


def test_azure_custom_permissions_data_mode_and_conditions(graph):
    graph.run("""
        CREATE (s:AzureSubscription {id: 's'}),
          (v:AzureKeyVault {id: '/subscriptions/s/vault/v', rbac_authorization: true}),
          (s)-[:RESOURCE]->(v)
    """).consume()
    client = MagicMock()
    client.role_definitions.get_by_id.return_value = SimpleNamespace(
        as_dict=lambda: {
            "id": "/subscriptions/s/roles/custom",
            "name": "custom",
            "role_type": "CustomRole",
            "permissions": [
                {"data_actions": ["Microsoft.KeyVault/vaults/secrets/getSecret/action"]}
            ],
        }
    )
    azure._load_rbac(
        graph,
        client,
        "s",
        1,
        [
            {
                "id": "/subscriptions/s/assignments/a",
                "role_definition_id": "/subscriptions/s/roles/custom",
                "principal_id": "USER",
                "scope": "/subscriptions/s",
                "principal_type": "User",
            }
        ],
    )
    graph.run("""
        MATCH (s:AzureSubscription {id: 's'})-[:RESOURCE]->(a:AzureRoleAssignment),
              (s)-[:RESOURCE]->(v:AzureKeyVault)
        MERGE (a)-[:SCOPE_CONTAINS]->(v)
    """).consume()
    query = _query(AZURE_QUERIES, "azure-permission-vault-secret-read")
    assert list(graph.run(query, provider_uid="s"))
    assert not list(graph.run(query, provider_uid="other"))
    graph.run("MATCH (v:AzureKeyVault) SET v.rbac_authorization = false").consume()
    assert not list(graph.run(query, provider_uid="s"))
    graph.run(
        "MATCH (v:AzureKeyVault), (a:AzureRoleAssignment) SET v.rbac_authorization = true, a.condition = 'condition'"
    ).consume()
    assert not list(graph.run(query, provider_uid="s"))


def test_gcp_cloudasset_failure_does_not_block_project_iam(graph):
    graph.run("CREATE (:GCPProject {id: 'p'})").consume()
    client = MagicMock()
    client.projects().getIamPolicy().execute.return_value = {
        "bindings": [{"role": "roles/viewer", "members": ["user:reader@example.com"]}],
    }
    with patch.object(gcp, "build_client", return_value=client):
        gcp._sync_project_policy(graph, object(), "p", 1)
    assert (
        graph.run("MATCH (n:GCPPolicyBinding) RETURN count(n) AS n").single()["n"] == 1
    )


def test_gcp_workload_and_network_collectors(graph):
    graph.run("""
        CREATE (p:GCPProject {id: 'p'}),
          (sa:GCPServiceAccount {id: 'sa', email: 'sa@p'}),
          (vm:GCPInstance {id: 'vm', has_public_ip: true, network_ids: ['projects/p/global/networks/vpc'],
            target_tags: ['web'], service_account_emails: ['sa@p']}),
          (p)-[:RESOURCE]->(sa), (p)-[:RESOURCE]->(vm)
    """).consume()
    client = MagicMock()
    services = client.projects().locations().services()
    services.list().execute.return_value = {
        "services": [
            {
                "name": "projects/p/locations/r/services/run",
                "template": {"serviceAccount": "sa@p"},
            }
        ]
    }
    services.list_next.return_value = None
    firewalls = client.firewalls()
    firewalls.list().execute.return_value = {
        "items": [
            {
                "name": "web",
                "selfLink": "https://www.googleapis.com/compute/v1/projects/p/global/firewalls/web",
                "network": "https://www.googleapis.com/compute/v1/projects/p/global/networks/vpc",
                "targetTags": ["web"],
                "sourceRanges": ["0.0.0.0/0"],
                "allowed": [{"IPProtocol": "tcp", "ports": ["443"]}],
            }
        ]
    }
    firewalls.list_next.return_value = None
    with patch.object(gcp_extended, "build_client", return_value=client):
        gcp_extended.sync_run(graph, object(), "p", 1)
        gcp_extended.sync_firewalls(graph, object(), "p", 1)
    assert list(
        graph.run(
            _query(GCP_QUERIES, "gcp-serverless-and-gke-identities"), provider_uid="p"
        )
    )
    query = _query(GCP_QUERIES, "gcp-public-vm-firewall-candidates")
    assert list(graph.run(query, provider_uid="p"))
    graph.run("MATCH (f:GCPFirewall) SET f.disabled = true").consume()
    assert not list(graph.run(query, provider_uid="p"))
    assert (
        graph.run("MATCH ()-[r:CAN_ACCESS]->() RETURN count(r) AS n").single()["n"] == 0
    )


def test_gcp_optional_inventory_and_deny_metadata(graph):
    graph.run("""
        CREATE (p:GCPProject {id: 'p', projectnumber: '123'}),
          (s:GCPServiceAccount {id: 's', email: 'sa@p'}), (p)-[:RESOURCE]->(s)
    """).consume()
    client = MagicMock()
    functions = client.projects().locations().functions()
    functions.list().execute.return_value = {
        "functions": [
            {
                "name": "projects/p/locations/r/functions/f",
                "serviceConfig": {
                    "serviceAccountEmail": "sa@p",
                    "ingressSettings": "ALLOW_INTERNAL_ONLY",
                },
            }
        ]
    }
    functions.list_next.return_value = None
    client.projects().locations().clusters().list().execute.return_value = {
        "clusters": [
            {
                "name": "cluster",
                "location": "r",
                "privateClusterConfig": {"enablePrivateEndpoint": True},
                "nodePools": [{"name": "pool", "config": {"serviceAccount": "sa@p"}}],
            }
        ]
    }
    client.instances().list().execute.return_value = {
        "items": [
            {
                "name": "sql",
                "settings": {
                    "ipConfiguration": {
                        "ipv4Enabled": True,
                        "authorizedNetworks": [{"value": "0.0.0.0/0"}],
                    }
                },
            }
        ]
    }
    client.instances().list_next.return_value = None
    client.datasets().list().execute.return_value = {
        "datasets": [{"datasetReference": {"datasetId": "data"}}]
    }
    client.datasets().list_next.return_value = None
    client.datasets().get().execute.return_value = {
        "datasetReference": {"datasetId": "data"},
        "access": [{"specialGroup": "allAuthenticatedUsers"}],
    }
    client.policies().listPolicies().execute.return_value = {
        "policies": [{"name": "policy"}]
    }
    client.policies().listPolicies_next.return_value = None
    client.policies().get().execute.return_value = {
        "name": "policy",
        "rules": [
            {
                "denyRule": {
                    "deniedPermissions": [
                        "iam.googleapis.com/serviceAccounts.getAccessToken"
                    ]
                }
            }
        ],
    }
    with patch.object(gcp_extended, "build_client", return_value=client):
        for sync in [
            gcp_extended.sync_functions,
            gcp_extended.sync_gke,
            gcp_extended.sync_sql,
            gcp_extended.sync_bigquery,
            gcp_extended.sync_deny_policies,
        ]:
            sync(graph, object(), "p", 1)
    client.policies().listPolicies.assert_called_with(
        parent="policies/cloudresourcemanager.googleapis.com%2Fprojects%2F123/denypolicies"
    )
    for name in [
        "gcp-serverless-and-gke-identities",
        "gcp-public-sql-configuration",
        "gcp-public-bigquery-acls",
        "gcp-project-deny-policies",
    ]:
        assert list(graph.run(_query(GCP_QUERIES, name), provider_uid="p")), name
    assert (
        graph.run(
            "MATCH (:GCPGKECluster)-[:CONTAINS]->(:GCPGKENodePool)-[:RUNS_AS]->(:GCPServiceAccount) RETURN count(*) AS n"
        ).single()["n"]
        == 1
    )


def test_gcp_ancestor_collection_and_group_cycles(graph):
    graph.run("CREATE (:GCPProject {id: 'p'})").consume()
    client = MagicMock()
    client.projects().getAncestry().execute.return_value = {
        "ancestor": [{"resourceId": {"type": "organization", "id": "123"}}],
    }
    client.organizations().getIamPolicy().execute.return_value = {
        "bindings": [{"role": "roles/viewer", "members": ["group:g@example.com"]}],
    }
    client.groups().lookup().execute.return_value = {"name": "groups/g"}
    client.groups().memberships().list().execute.return_value = {
        "memberships": [
            {"preferredMemberKey": {"id": "user@example.com"}, "type": "USER"},
            {"preferredMemberKey": {"id": "g@example.com"}, "type": "GROUP"},
        ]
    }
    client.groups().memberships().list_next.return_value = None
    with patch.object(gcp_extended, "build_client", return_value=client):
        gcp_extended.sync_ancestors(graph, object(), "p", 1)
        gcp_extended.sync_groups(graph, object(), "p", 1)
    assert list(graph.run(_query(GCP_QUERIES, "gcp-inherited-iam"), provider_uid="p"))
    assert list(
        graph.run(_query(GCP_QUERIES, "gcp-group-permission-paths"), provider_uid="p")
    )
    assert (
        client.groups().lookup.call_count == 2
    )  # fixture configuration + one actual lookup
    assert not list(
        graph.run(_query(GCP_QUERIES, "gcp-inherited-iam"), provider_uid="other")
    )


def test_azure_workload_network_and_sql_collectors(graph):
    graph.run("""
        CREATE (s:AzureSubscription {id: 's'}),
          (vm:AzureVirtualMachine {id: '/subscriptions/s/vm', network_interface_ids: ['/subscriptions/s/nic']}),
          (s)-[:RESOURCE]->(vm)
    """).consume()

    def model(row):
        return SimpleNamespace(as_dict=lambda: row)

    web = MagicMock()
    web.web_apps.list.return_value = [
        model(
            {
                "id": "/subscriptions/s/web",
                "name": "web",
                "identity": {"principal_id": "IDENTITY"},
            }
        )
    ]
    aks = MagicMock()
    aks.managed_clusters.list.return_value = [
        model(
            {
                "id": "/subscriptions/s/aks",
                "name": "aks",
                "identity_profile": {"kubeletidentity": {"object_id": "KUBELET"}},
            }
        )
    ]
    network = MagicMock()
    network.network_interfaces.list_all.return_value = [
        model(
            {
                "id": "/subscriptions/s/nic",
                "name": "nic",
                "network_security_group": {"id": "/subscriptions/s/nsg"},
                "ip_configurations": [
                    {
                        "public_ip_address": {"id": "/subscriptions/s/ip"},
                        "subnet": {"id": "/subscriptions/s/subnet"},
                    }
                ],
            }
        )
    ]
    network.virtual_networks.list_all.return_value = []
    network.network_security_groups.list_all.return_value = [
        model(
            {
                "id": "/subscriptions/s/nsg",
                "name": "nsg",
                "security_rules": [
                    {
                        "id": "/subscriptions/s/nsg/rule",
                        "name": "allow",
                        "direction": "Inbound",
                        "access": "Allow",
                        "source_address_prefix": "Internet",
                        "destination_port_range": "443",
                    }
                ],
            }
        )
    ]
    network.public_ip_addresses.list_all.return_value = [
        model({"id": "/subscriptions/s/ip", "name": "ip", "ip_address": "203.0.113.1"})
    ]
    sql = MagicMock()
    sql.servers.list.return_value = [
        model(
            {
                "id": "/subscriptions/s/resourcegroups/r/sql/server",
                "name": "sql",
                "public_network_access": "Enabled",
            }
        )
    ]
    sql.firewall_rules.list_by_server.return_value = [
        model(
            {
                "id": "/subscriptions/s/resourcegroups/r/sql/server/rule",
                "name": "azure-services",
                "start_ip_address": "0.0.0.0",
                "end_ip_address": "0.0.0.0",
            }
        )
    ]
    with (
        patch.object(azure_extended, "WebSiteManagementClient", return_value=web),
        patch.object(azure_extended, "ContainerServiceClient", return_value=aks),
        patch.object(azure_extended, "NetworkManagementClient", return_value=network),
        patch.object(azure_extended, "SqlManagementClient", return_value=sql),
    ):
        for sync in [
            azure_extended.sync_web,
            azure_extended.sync_aks,
            azure_extended.sync_network,
            azure_extended.sync_sql,
        ]:
            sync(graph, object(), "s", 1, {})
    query = _query(AZURE_QUERIES, "azure-public-vm-nsg-candidates")
    assert list(graph.run(query, provider_uid="s"))
    graph.run("MATCH (r:AzureNSGRule) SET r.access = 'Deny'").consume()
    assert not list(graph.run(query, provider_uid="s"))
    assert not list(
        graph.run(
            _query(AZURE_QUERIES, "azure-public-sql-configuration"), provider_uid="s"
        )
    )
    assert graph.run("MATCH ()-[r:RUNS_AS]->() RETURN count(r) AS n").single()["n"] == 2


def test_azure_graph_pagination_is_scoped_and_permission_errors_visible(graph):
    graph.run("""
        CREATE (s:AzureSubscription {id: 's'}),
          (g:AzurePrincipal {id: 'group', type: 'Group'}),
          (s)-[:RESOURCE]->(g)
    """).consume()
    credential = MagicMock()
    credential.get_token.return_value.token = "test-token"
    response = MagicMock(status_code=200)
    response.json.return_value = {
        "value": [{"id": "member", "@odata.type": "#microsoft.graph.user"}]
    }
    region = SimpleNamespace(
        graph_host="https://graph.microsoft.us",
        graph_scope="https://graph.microsoft.us/.default",
    )
    with patch.object(azure_extended.requests, "get", return_value=response) as request:
        azure_extended.sync_directory(graph, credential, "s", 1, region)
    assert request.call_args.args[0].startswith(
        "https://graph.microsoft.us/v1.0/groups/group/"
    )
    credential.get_token.assert_called_with("https://graph.microsoft.us/.default")
    assert (
        graph.run(
            "MATCH (:AzurePrincipal {id: 'member'})-[:TRANSITIVE_MEMBER_OF]->(:AzurePrincipal {id: 'group'}) RETURN count(*) AS n"
        ).single()["n"]
        == 1
    )
    response.json.return_value = {
        "value": [],
        "@odata.nextLink": "https://foreign.example/steal",
    }
    with patch.object(azure_extended.requests, "get", return_value=response):
        with pytest.raises(ValueError, match="foreign"):
            azure_extended.sync_directory(graph, credential, "s", 1, region)
    response.status_code = 403
    response.text = "Authorization_RequestDenied"
    with patch.object(azure_extended.requests, "get", return_value=response):
        with pytest.raises(CollectionError, match="403"):
            azure_extended.sync_directory(graph, credential, "s", 1, region)
