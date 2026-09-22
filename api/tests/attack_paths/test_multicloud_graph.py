"""Run only against an explicitly selected disposable Neo4j."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from api.attack_paths.queries.registry import get_queries_for_provider
from azure.core.exceptions import HttpResponseError
from google.cloud.asset_v1.types import IamPolicySearchResult
from googleapiclient.errors import HttpError
from httplib2 import Response
from tasks.jobs.attack_paths import azure, findings, gcp, sync
from tasks.jobs.attack_paths.config import PROVIDER_CONFIGS

UPDATE_TAG = 1790000001


def _model(data):
    return SimpleNamespace(as_dict=lambda: data)


def _list_response(resource, key, rows):
    resource.list.return_value.execute.return_value = {key: rows}
    resource.list_next.return_value = None


def _finding(uid):
    return {
        "id": f"finding-{uid}",
        "uid": f"finding-{uid}",
        "status": "FAIL",
        "muted": False,
        "check_id": "test-check",
        "resource_uid": uid,
        "resource_short_uid": uid,
        "severity": "high",
    }


@pytest.fixture
def gcp_cloud():
    project = "test-project"
    email = f"vm@{project}.iam.gserviceaccount.com"
    clients = {
        name: MagicMock()
        for name in (
            "cloudresourcemanager",
            "iam",
            "compute",
            "storage",
            "secretmanager",
        )
    }
    clients["cloudresourcemanager"].projects().get().execute.return_value = {
        "projectId": project,
        "projectNumber": "123",
        "name": "Test",
        "parent": {},
    }
    clients["cloudresourcemanager"].projects().getIamPolicy().execute.return_value = {
        "bindings": [{"role": "roles/editor", "members": [f"serviceAccount:{email}"]}],
    }
    _list_response(
        clients["iam"].projects().serviceAccounts(),
        "accounts",
        [
            {"uniqueId": "987", "email": email},
        ],
    )
    instances = clients["compute"].instances()
    instances.aggregatedList().execute.return_value = {
        "items": {
            "zones/z": {
                "instances": [
                    {
                        "name": "vm",
                        "id": "456",
                        "serviceAccounts": [{"email": email, "scopes": []}],
                    },
                ]
            }
        }
    }
    instances.aggregatedList_next.return_value = None
    _list_response(clients["storage"].buckets(), "items", [{"id": "test-bucket"}])
    _list_response(
        clients["secretmanager"].projects().secrets(),
        "secrets",
        [
            {"name": "projects/123/secrets/secret"},
        ],
    )
    policies = [
        IamPolicySearchResult(
            resource="//storage.googleapis.com/projects/_/buckets/test-bucket",
            policy={
                "bindings": [
                    {"role": "roles/storage.objectViewer", "members": ["allUsers"]}
                ]
            },
        ),
        IamPolicySearchResult(
            resource=f"//iam.googleapis.com/projects/{project}/serviceAccounts/{email}",
            policy={
                "bindings": [
                    {
                        "role": "roles/iam.serviceAccountTokenCreator",
                        "members": ["user:user@example.com"],
                    }
                ]
            },
        ),
    ]
    sdk = SimpleNamespace(projects={project: object()}, session=object())
    for client in clients.values():
        client.reset_mock()
    with (
        patch.object(
            gcp, "build_client", side_effect=lambda name, version, **kw: clients[name]
        ) as build,
        patch.object(gcp, "AssetServiceClient") as asset,
        patch(
            "tasks.jobs.attack_paths.db_utils.update_attack_paths_scan_progress"
        ) as progress,
        patch.object(gcp.gcp_extended, "steps", return_value=[]),
    ):
        asset.return_value.search_all_iam_policies.return_value = policies
        yield project, sdk, clients, build, asset, progress


def test_gcp_ingestion_findings_and_all_queries(graph, gcp_cloud):
    project, sdk, clients, build, asset, progress = gcp_cloud
    provider = SimpleNamespace(uid=project, provider="gcp")
    config = SimpleNamespace(update_tag=UPDATE_TAG)
    assert gcp.start_gcp_ingestion(graph, config, provider, sdk, object()) == {}
    assert all(
        call.kwargs["credentials"] is sdk.session for call in build.call_args_list
    )
    asset.return_value.search_all_iam_policies.assert_called_once_with(
        request={"scope": f"projects/{project}"},
    )
    clients["compute"].instances().aggregatedList.assert_called_once_with(
        project=project
    )
    assert progress.call_args.args[1] == 93
    assert findings.add_resource_label(graph, "gcp", project) > 0
    findings.load_findings(graph, iter([[_finding("456")]]), provider, config)
    assert (
        graph.run(
            "MATCH (:GCPInstance)-[:HAS_FINDING]->(f:ProwlerFinding) RETURN count(f) AS n",
        ).single()["n"]
        == 1
    )
    for index, query in enumerate(get_queries_for_provider("gcp")):
        result = list(graph.run(query.cypher, provider_uid=project))
        if index < 5:
            assert result, query.id
        assert not list(graph.run(query.cypher, provider_uid="another-project")), (
            query.id
        )
    # A public IP alone must not become a confirmed exposure edge.
    assert (
        graph.run("MATCH ()-[r:CAN_ACCESS]->() RETURN count(r) AS n").single()["n"] == 0
    )


@pytest.fixture
def azure_cloud():
    subscription = "11111111-1111-1111-1111-111111111111"
    root = f"/subscriptions/{subscription}"
    vm_id = f"{root}/resourceGroups/R/providers/Microsoft.Compute/virtualMachines/VM"
    storage_id = (
        f"{root}/resourceGroups/R/providers/Microsoft.Storage/storageAccounts/account"
    )
    role_id = f"{root}/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
    sdk = SimpleNamespace(
        session=object(),
        identity=SimpleNamespace(subscriptions={subscription: "Test"}),
        region_config=SimpleNamespace(
            base_url="https://management.azure.com",
            credential_scopes=["https://management.azure.com/.default"],
        ),
    )
    with (
        patch.object(azure, "SubscriptionClient") as subscriptions,
        patch.object(azure, "ComputeManagementClient") as compute,
        patch.object(azure, "StorageManagementClient") as storage,
        patch.object(azure, "KeyVaultManagementClient") as vaults,
        patch.object(azure, "AuthorizationManagementClient") as authorization,
        patch("tasks.jobs.attack_paths.db_utils.update_attack_paths_scan_progress"),
        patch.object(azure.azure_extended, "steps", return_value=[]),
    ):
        subscriptions.return_value.subscriptions.get.return_value = SimpleNamespace(
            subscription_id=subscription,
            tenant_id="tenant",
            id=root,
            display_name="Test",
            state="Enabled",
        )
        compute.return_value.virtual_machines.list_all.return_value = [
            _model(
                {
                    "id": vm_id,
                    "name": "VM",
                    "identity": {"principal_id": "IDENTITY"},
                    "zones": ["1"],
                }
            )
        ]
        storage.return_value.storage_accounts.list.return_value = [
            _model(
                {
                    "id": storage_id,
                    "name": "account",
                    "allow_blob_public_access": True,
                    "public_network_access": "Enabled",
                    "network_rule_set": {"default_action": "Allow"},
                }
            )
        ]
        storage.return_value.blob_containers.list.return_value = [
            _model(
                {
                    "id": storage_id + "/blobServices/default/containers/public",
                    "name": "public",
                    "public_access": "Blob",
                }
            )
        ]
        vaults.return_value.vaults.list_by_subscription.return_value = [
            _model(
                {
                    "id": f"{root}/resourceGroups/R/providers/Microsoft.KeyVault/vaults/secret",
                    "name": "secret",
                }
            )
        ]
        vaults.return_value.vaults.get.return_value = _model({"properties": {}})
        authorization.return_value.role_assignments.list_for_subscription.return_value = [
            _model(
                {
                    "id": root
                    + "/providers/Microsoft.Authorization/roleAssignments/assignment",
                    "role_definition_id": role_id,
                    "principal_id": "IDENTITY",
                    "principal_type": "ServicePrincipal",
                    "scope": root,
                }
            )
        ]
        authorization.return_value.role_definitions.get_by_id.return_value = _model(
            {
                "id": role_id,
                "name": role_id.split("/")[-1],
                "role_name": "Owner",
                "permissions": [{"actions": ["*"], "not_actions": []}],
                "assignable_scopes": [root],
            }
        )
        yield (
            subscription,
            sdk,
            vm_id,
            (subscriptions, compute, storage, vaults, authorization),
        )


def test_azure_ingestion_findings_and_all_queries(graph, azure_cloud):
    subscription, sdk, vm_id, clients = azure_cloud
    provider = SimpleNamespace(uid=subscription, provider="azure")
    config = SimpleNamespace(update_tag=UPDATE_TAG)
    assert azure.start_azure_ingestion(graph, config, provider, sdk, object()) == {}
    clients[0].return_value.subscriptions.get.assert_called_once_with(subscription)
    for client in clients:
        assert client.call_args.args[0] is sdk.session
    assert findings.add_resource_label(graph, "azure", subscription) > 0
    finding = _finding(vm_id)
    finding["resource_short_uid"] = azure.normalize_uid(vm_id)
    findings.load_findings(graph, iter([[finding]]), provider, config)
    assert (
        graph.run(
            "MATCH (:AzureVirtualMachine)-[:HAS_FINDING]->(f:ProwlerFinding) RETURN count(f) AS n",
        ).single()["n"]
        == 1
    )
    for index, query in enumerate(get_queries_for_provider("azure")):
        result = list(graph.run(query.cypher, provider_uid=subscription))
        if index < 5:
            assert result, query.id
        assert not list(graph.run(query.cypher, provider_uid="other-subscription")), (
            query.id
        )


def test_scoped_finding_alias_ambiguity_does_not_link_arbitrary_resource(graph):
    graph.run(
        "CREATE (:GCPProject {id: 'p'})-[:RESOURCE]->(:GCPInstance {id: 'one', _prowler_uid: '123'}), "
        "(:GCPProject {id: 'p'})-[:RESOURCE]->(:GCPInstance {id: 'two', _prowler_uid: '123'})",
    ).consume()
    findings.add_resource_label(graph, "gcp", "p")
    findings.load_findings(
        graph,
        iter([[_finding("123")]]),
        SimpleNamespace(provider="gcp"),
        SimpleNamespace(update_tag=UPDATE_TAG),
    )
    assert graph.run("MATCH (f:ProwlerFinding) RETURN count(f) AS n").single()["n"] == 0


def test_cloud_service_errors_are_visible_and_total_failure_is_fatal(graph, gcp_cloud):
    project, sdk, clients, *_ = gcp_cloud
    clients["compute"].instances().aggregatedList().execute.side_effect = HttpError(
        Response({"status": "403"}),
        b'{"error":{"message":"Permission denied"}}',
    )
    errors = gcp.start_gcp_ingestion(
        graph,
        SimpleNamespace(update_tag=UPDATE_TAG),
        SimpleNamespace(uid=project),
        sdk,
        object(),
    )
    assert "compute" in errors
    with (
        patch.object(
            gcp,
            "_sync_service_accounts",
            side_effect=clients["compute"]
            .instances()
            .aggregatedList()
            .execute.side_effect,
        ),
        patch.object(
            gcp,
            "_sync_storage",
            side_effect=clients["compute"]
            .instances()
            .aggregatedList()
            .execute.side_effect,
        ),
        patch.object(
            gcp,
            "_sync_secrets",
            side_effect=clients["compute"]
            .instances()
            .aggregatedList()
            .execute.side_effect,
        ),
        patch.object(
            gcp,
            "_sync_policies",
            side_effect=clients["compute"]
            .instances()
            .aggregatedList()
            .execute.side_effect,
        ),
        patch.object(
            gcp,
            "_sync_project_policy",
            side_effect=HttpError(
                Response({"status": "403"}),
                b'{"error":{"message":"Permission denied"}}',
            ),
        ),
    ):
        with pytest.raises(RuntimeError, match="All GCP"):
            gcp.start_gcp_ingestion(
                graph,
                SimpleNamespace(update_tag=UPDATE_TAG),
                SimpleNamespace(uid=project),
                sdk,
                object(),
            )


def test_azure_total_service_failure_is_fatal(graph, azure_cloud):
    subscription, sdk, _, clients = azure_cloud
    for client in clients[1:]:
        client.side_effect = HttpResponseError("Forbidden")
    with pytest.raises(RuntimeError, match="All Azure"):
        azure.start_azure_ingestion(
            graph,
            SimpleNamespace(update_tag=UPDATE_TAG),
            SimpleNamespace(uid=subscription),
            sdk,
            object(),
        )


@pytest.mark.parametrize("provider", ["aws", "gcp", "azure"])
def test_normalized_lists_are_materialized_and_provider_isolated(provider):
    config = PROVIDER_CONFIGS[provider]
    spec = config.normalized_lists[0]
    record = {
        "labels": [spec.source_label],
        "props": {spec.source_property: ["value"]},
        "element_id": "node-1",
    }
    _, parent, children, relationships = sync._node_to_sync_dict(
        record,
        "provider-1",
        sync._build_catalog_index(config.normalized_lists),
    )
    assert spec.source_property not in parent["props"]
    assert children[0]["row"]["props"]["value"] == "value"
    assert relationships[0]["rel_type"] == spec.rel_type
    assert parent["provider_element_id"].startswith("provider-1:")
