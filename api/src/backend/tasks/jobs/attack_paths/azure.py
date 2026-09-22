"""Subscription-scoped Azure inventory and RBAC configuration for Attack Paths."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.resource.subscriptions import SubscriptionClient
from azure.mgmt.storage import StorageManagementClient
from cartography.client.core.tx import load
from cartography.intel.azure import compute, key_vaults, rbac, storage, subscription
from cartography.models.azure.storage.blobcontainer import (
    AzureStorageBlobContainerSchema,
)
from tasks.jobs.attack_paths import azure_extended
from tasks.jobs.attack_paths.inventory import collect_each, load_resources, run_steps

if TYPE_CHECKING:
    import neo4j
    from api.models import AttackPathsScan, Provider
    from cartography.config import Config
    from prowler.providers.azure.azure_provider import AzureProvider

logger = logging.getLogger(__name__)


def normalize_uid(uid: str) -> str:
    return uid.lower()


def _sync_compute(session, credentials, subscription_id, update_tag, client_kwargs):
    client = ComputeManagementClient(credentials, subscription_id, **client_kwargs)
    vms = [vm.as_dict() for vm in client.virtual_machines.list_all()]
    identities = []
    for vm in vms:
        vm["id"] = normalize_uid(vm["id"])
        vm["resource_group"] = vm["id"].split("/")[4]
        identity = vm.get("identity") or {}
        principal_ids = [identity.get("principal_id")]
        principal_ids.extend(
            value.get("principal_id")
            for value in (identity.get("user_assigned_identities") or {}).values()
        )
        identities.extend(
            {"vm_id": vm["id"], "principal_id": principal_id.lower()}
            for principal_id in principal_ids
            if principal_id
        )
    compute.load_vms(session, subscription_id, vms, update_tag)
    neo4j_rows = [
        {
            "id": vm["id"],
            "network_interface_ids": [
                nic["id"].lower()
                for nic in (vm.get("network_profile") or {}).get(
                    "network_interfaces", []
                )
            ],
        }
        for vm in vms
    ]
    session.run(
        "UNWIND $rows AS row MATCH (vm:AzureVirtualMachine {id: row.id}) "
        "SET vm.network_interface_ids = row.network_interface_ids",
        rows=neo4j_rows,
    ).consume()
    session.run(
        """
        UNWIND $identities AS identity
        MATCH (vm:AzureVirtualMachine {id: identity.vm_id})
        MERGE (principal:AzurePrincipal {id: identity.principal_id})
        ON CREATE SET principal.firstseen = $update_tag
        SET principal.lastupdated = $update_tag
        MERGE (vm)-[:RUNS_AS]->(principal)
        WITH principal
        MATCH (subscription:AzureSubscription {id: $subscription_id})
        MERGE (subscription)-[:RESOURCE]->(principal)
        """,
        identities=identities,
        subscription_id=subscription_id,
        update_tag=update_tag,
    ).consume()


def _sync_rbac(session, credentials, subscription_id, update_tag, client_kwargs):
    client = AuthorizationManagementClient(
        credentials, subscription_id, **client_kwargs
    )
    scope = f"/subscriptions/{subscription_id}"
    assignments = [
        assignment.as_dict()
        for assignment in client.role_assignments.list_for_subscription()
    ]
    # Keep only assignments directly inside this subscription. Management-group
    # inheritance, PIM, directory groups, deny assignments and ABAC aren't evaluated.
    assignments = [
        assignment
        for assignment in assignments
        if assignment.get("scope", "").lower() == scope.lower()
        or assignment.get("scope", "").lower().startswith(scope.lower() + "/")
    ]
    _load_rbac(session, client, subscription_id, update_tag, assignments)


def _sync_inherited_rbac(
    session, credentials, subscription_id, update_tag, client_kwargs
):
    client = AuthorizationManagementClient(
        credentials, subscription_id, **client_kwargs
    )
    assignments = [
        row.as_dict()
        for row in client.role_assignments.list_for_scope(
            f"/subscriptions/{subscription_id}",
            filter="atScope()",
        )
    ]
    # atScope() returns assignments at this scope or ancestors, not arbitrary
    # management groups in the tenant. Keep their original scope as evidence.
    for row in assignments:
        row["inherited_to_subscription"] = (
            row["scope"].lower() != f"/subscriptions/{subscription_id}".lower()
        )
    _load_rbac(session, client, subscription_id, update_tag, assignments)


def _load_rbac(session, client, subscription_id, update_tag, assignments):
    definitions = []
    for role_id in sorted({row["role_definition_id"] for row in assignments}):
        role = client.role_definitions.get_by_id(role_id).as_dict()
        role["id"] = normalize_uid(role["id"])
        role["subscription_id"] = subscription_id
        definitions.append(role)
    rbac.load_permissions(
        session,
        rbac.transform_permissions(definitions),
        subscription_id,
        update_tag,
    )
    rbac.load_role_definitions(
        session,
        rbac.transform_role_definitions(definitions),
        subscription_id,
        update_tag,
    )
    load_resources(
        session,
        "AzureSubscription",
        subscription_id,
        "AzureRoleDefinition",
        [
            {
                "id": role["id"],
                "custom_role": role.get("role_type") == "CustomRole",
                **{
                    capability: azure_extended.role_allows(
                        role.get("permissions", []), action, data
                    )
                    for capability, (
                        action,
                        data,
                    ) in azure_extended.CAPABILITIES.items()
                },
            }
            for role in definitions
        ],
        update_tag,
    )
    for row in assignments:
        for key in ("id", "scope", "role_definition_id", "principal_id"):
            if row.get(key):
                row[key] = normalize_uid(row[key])
        row["subscription_id"] = subscription_id
    rbac.load_role_assignments(
        session,
        rbac.transform_role_assignments(assignments),
        subscription_id,
        update_tag,
    )
    session.run(
        "UNWIND $rows AS row MATCH (a:AzureRoleAssignment {id: row.id}) "
        "SET a.inherited_to_subscription = row.inherited",
        rows=[
            {"id": row["id"], "inherited": row.get("inherited_to_subscription", False)}
            for row in assignments
        ],
    ).consume()
    session.run(
        """
        MATCH (subscription:AzureSubscription {id: $subscription_id})-[:RESOURCE]->(a:AzureRoleAssignment)
        WHERE a.principal_id IS NOT NULL
        MERGE (scope:AzureScope {id: 'rbac-scope:' + a.scope})
        SET scope.scope = a.scope, scope.lastupdated = $update_tag
        MERGE (subscription)-[:RESOURCE]->(scope)
        MERGE (a)-[:SCOPED_AT]->(scope)
        MERGE (principal:AzurePrincipal {id: a.principal_id})
        ON CREATE SET principal.firstseen = $update_tag
        SET principal.lastupdated = $update_tag, principal.type = a.principal_type
        MERGE (subscription)-[:RESOURCE]->(principal)
        MERGE (principal)-[:HAS_ROLE_ASSIGNMENT]->(a)
        """,
        subscription_id=subscription_id,
        update_tag=update_tag,
    ).consume()


def _sync_storage(session, credentials, subscription_id, update_tag, client_kwargs):
    client = StorageManagementClient(credentials, subscription_id, **client_kwargs)

    def collect(account_object):
        account = account_object.as_dict()
        account["id"] = normalize_uid(account["id"])
        group = account["id"].split("/")[4]
        account["resourceGroup"] = group
        storage.load_storage_account_data(
            session, subscription_id, [account], update_tag
        )
        session.run(
            "MATCH (a:AzureStorageAccount {id: $id}) "
            "SET a.allow_blob_public_access = $public, a.public_network_access = $network, "
            "a.network_default_action = $action",
            id=account["id"],
            public=account.get("allow_blob_public_access"),
            network=account.get("public_network_access"),
            action=(account.get("network_rule_set") or {}).get("default_action"),
        ).consume()
        containers = [
            container.as_dict()
            for container in client.blob_containers.list(group, account["name"])
        ]
        for container in containers:
            container["id"] = normalize_uid(container["id"])
        load(
            session,
            AzureStorageBlobContainerSchema(),
            containers,
            lastupdated=update_tag,
            AZURE_SUBSCRIPTION_ID=subscription_id,
        )
        session.run(
            """
            MATCH (account:AzureStorageAccount {id: $account_id})
            SET account.allow_blob_public_access = $allow_public,
                account.public_network_access = $network_access,
                account.network_default_action = $default_action
            WITH account
            UNWIND $container_ids AS container_id
            MATCH (container:AzureStorageBlobContainer {id: container_id})
            MERGE (account)-[:CONTAINS]->(container)
            """,
            account_id=account["id"],
            container_ids=[container["id"] for container in containers],
            allow_public=account.get("allow_blob_public_access"),
            network_access=account.get("public_network_access"),
            default_action=(account.get("network_rule_set") or {}).get(
                "default_action"
            ),
        ).consume()

    collect_each(client.storage_accounts.list(), collect, azure_extended.CLOUD_ERRORS)


def _sync_vaults(session, credentials, subscription_id, update_tag, client_kwargs):
    client = KeyVaultManagementClient(credentials, subscription_id, **client_kwargs)
    vaults = [vault.as_dict() for vault in client.vaults.list_by_subscription()]
    for vault in vaults:
        vault["id"] = normalize_uid(vault["id"])
    key_vaults.load_key_vaults(
        session,
        key_vaults.transform_key_vaults(vaults),
        subscription_id,
        update_tag,
    )

    def collect(vault):
        row = client.vaults.get(vault["id"].split("/")[4], vault["name"]).as_dict()
        properties = row.get("properties") or {}
        session.run(
            "MATCH (v:AzureKeyVault {id: $id}) SET v.rbac_authorization = $rbac, "
            "v.public_network_access = $network, v.network_default_action = $action",
            id=vault["id"],
            rbac=properties.get("enable_rbac_authorization", False),
            network=properties.get("public_network_access"),
            action=(properties.get("network_acls") or {}).get("default_action"),
        ).consume()
        policies = [
            {
                "id": f"{vault['id']}/accessPolicy/{policy['object_id'].lower()}",
                "vault_id": vault["id"],
                "principal_id": policy["object_id"].lower(),
                "secret_get": "get"
                in (policy.get("permissions") or {}).get("secrets", []),
                "key_decrypt": "decrypt"
                in (policy.get("permissions") or {}).get("keys", []),
                "application_id": policy.get("application_id"),
            }
            for policy in properties.get("access_policies", [])
        ]
        load_resources(
            session,
            "AzureSubscription",
            subscription_id,
            "AzureVaultAccessPolicy",
            policies,
            update_tag,
        )
        session.run(
            """
            MATCH (s:AzureSubscription {id: $subscription})-[:RESOURCE]->(policy:AzureVaultAccessPolicy {vault_id: $vault})
            MATCH (s)-[:RESOURCE]->(v:AzureKeyVault {id: $vault})
            MERGE (p:AzurePrincipal {id: policy.principal_id}) SET p.lastupdated = $tag
            MERGE (s)-[:RESOURCE]->(p)
            MERGE (p)-[:HAS_VAULT_POLICY]->(policy)
            MERGE (policy)-[:SCOPE_CONTAINS]->(v)
            """,
            subscription=subscription_id,
            vault=vault["id"],
            tag=update_tag,
        ).consume()

    collect_each(vaults, collect, azure_extended.CLOUD_ERRORS)


def start_azure_ingestion(
    neo4j_session: neo4j.Session,
    cartography_config: Config,
    prowler_api_provider: Provider,
    prowler_sdk_provider: AzureProvider,
    attack_paths_scan: AttackPathsScan,
) -> dict[str, str]:
    from tasks.jobs.attack_paths import db_utils

    subscription_id = str(prowler_api_provider.uid)
    if subscription_id.lower() not in {
        key.lower() for key in prowler_sdk_provider.identity.subscriptions
    }:
        raise ValueError(
            f"Azure subscription {subscription_id} is not in the credential's scan scope"
        )
    credentials = prowler_sdk_provider.session
    if credentials is None:
        raise ValueError("Azure Attack Paths requires connected-provider credentials")
    region = prowler_sdk_provider.region_config
    client_kwargs = {
        "base_url": region.base_url,
        "credential_scopes": region.credential_scopes,
    }
    selected = SubscriptionClient(credentials, **client_kwargs).subscriptions.get(
        subscription_id
    )
    if selected.subscription_id.lower() != subscription_id.lower():
        raise ValueError(
            "Azure subscription response does not match the connected provider"
        )
    subscription.load_azure_subscriptions(
        neo4j_session,
        selected.tenant_id,
        [
            {
                "id": selected.id,
                "subscriptionId": subscription_id,
                "displayName": selected.display_name,
                "state": selected.state,
            }
        ],
        cartography_config.update_tag,
    )
    steps = [
        ("compute", _sync_compute),
        ("storage", _sync_storage),
        ("key_vaults", _sync_vaults),
        ("rbac", _sync_rbac),
        ("inherited_rbac", _sync_inherited_rbac),
    ]
    steps = [
        (
            name,
            lambda sync=sync: sync(
                neo4j_session,
                credentials,
                subscription_id,
                cartography_config.update_tag,
                client_kwargs,
            ),
        )
        for name, sync in steps
    ]
    steps += azure_extended.steps(
        neo4j_session,
        credentials,
        subscription_id,
        cartography_config.update_tag,
        client_kwargs,
        region,
    )
    errors = run_steps(
        neo4j_session,
        "AzureSubscription",
        subscription_id,
        steps,
        azure_extended.CLOUD_ERRORS,
        cartography_config.update_tag,
        lambda progress: db_utils.update_attack_paths_scan_progress(
            attack_paths_scan, progress
        ),
    )
    neo4j_session.run(
        """
        MATCH (p:AzureSubscription {id: $subscription_id})-[:RESOURCE]->(r)
        SET r._prowler_uid = toLower(r.id)
        """,
        subscription_id=subscription_id,
    ).consume()
    neo4j_session.run(
        """
        MATCH (p:AzureSubscription {id: $subscription_id})-[:RESOURCE]->(a:AzureRoleAssignment)
        MATCH (p)-[:RESOURCE*0..1]->(r)
        WHERE r <> a AND (toLower(r.id) = a.scope OR toLower(r.id) STARTS WITH a.scope + '/'
            OR a.inherited_to_subscription = true
            OR (r = p AND a.scope = '/subscriptions/' + toLower($subscription_id)))
        MERGE (a)-[:SCOPE_CONTAINS]->(r)
        """,
        subscription_id=subscription_id,
    ).consume()
    return errors
