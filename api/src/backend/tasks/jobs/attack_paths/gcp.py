"""Project-scoped GCP inventory and IAM configuration for Attack Paths."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from cartography.intel.gcp import compute, iam, policy_bindings, secretsmanager, storage
from cartography.intel.gcp.clients import build_client
from cartography.intel.gcp.crm.projects import load_gcp_projects
from google.cloud.asset_v1 import AssetServiceClient
from google.protobuf.json_format import MessageToDict
from tasks.jobs.attack_paths import gcp_extended
from tasks.jobs.attack_paths.inventory import run_steps

if TYPE_CHECKING:
    import neo4j
    from api.models import AttackPathsScan, Provider
    from cartography.config import Config
    from prowler.providers.gcp.gcp_provider import GcpProvider

logger = logging.getLogger(__name__)


def normalize_uid(uid: str) -> str:
    if uid.startswith(("https://", "//")):
        path = urlsplit(uid).path.lstrip("/")
        if path.startswith("compute/v1/"):
            return path.removeprefix("compute/v1/")
        return path
    return uid


def _list_pages(resource, method: str, key: str, **kwargs) -> list[dict]:
    rows = []
    request = getattr(resource, method)(**kwargs)
    while request is not None:
        response = request.execute(num_retries=3)
        rows.extend(response.get(key, []))
        request = getattr(resource, f"{method}_next")(request, response)
    return rows


def _sync_service_accounts(session, credentials, project_id, update_tag):
    client = build_client("iam", "v1", credentials=credentials)
    accounts = _list_pages(
        client.projects().serviceAccounts(),
        "list",
        "accounts",
        name=f"projects/{project_id}",
    )
    iam.load_gcp_service_accounts(
        session,
        iam.transform_gcp_service_accounts(accounts, project_id),
        project_id,
        update_tag,
    )
    session.run(
        "MATCH (p:GCPProject {id: $project_id})-[:RESOURCE]->(s:GCPServiceAccount) "
        "SET s._prowler_uid = s.email",
        project_id=project_id,
    ).consume()


def _sync_compute(session, credentials, project_id, update_tag):
    client = build_client("compute", "v1", credentials=credentials)
    resource = client.instances()
    request = resource.aggregatedList(project=project_id)
    responses = []
    aliases = []
    while request is not None:
        response = request.execute(num_retries=3)
        for zone, data in response.get("items", {}).items():
            instances = data.get("instances", [])
            if instances:
                prefix = f"projects/{project_id}/{zone}/instances"
                responses.append({"id": prefix, "items": instances})
                aliases.extend(
                    {
                        "id": f"{prefix}/{vm['name']}",
                        "uid": str(vm["id"]),
                        "target_tags": (vm.get("tags") or {}).get("items", []),
                        "service_account_emails": [
                            sa["email"] for sa in vm.get("serviceAccounts", [])
                        ],
                        "oauth_scopes": sorted(
                            {
                                scope
                                for sa in vm.get("serviceAccounts", [])
                                for scope in sa.get("scopes", [])
                            }
                        ),
                        "network_ids": [
                            normalize_uid(nic["network"])
                            for nic in vm.get("networkInterfaces", [])
                            if nic.get("network")
                        ],
                        "has_public_ip": any(
                            config.get("natIP")
                            for nic in vm.get("networkInterfaces", [])
                            for config in nic.get("accessConfigs", [])
                        ),
                    }
                    for vm in instances
                )
        request = resource.aggregatedList_next(request, response)
    compute.load_gcp_instances(
        session,
        compute.transform_gcp_instances(responses),
        update_tag,
        project_id,
    )
    session.run(
        "UNWIND $aliases AS alias MATCH (n:GCPInstance {id: alias.id}) "
        "SET n._prowler_uid = alias.uid, n.target_tags = alias.target_tags, "
        "n.service_account_emails = alias.service_account_emails, "
        "n.oauth_scopes = alias.oauth_scopes, n.network_ids = alias.network_ids, "
        "n.has_public_ip = alias.has_public_ip",
        aliases=aliases,
    ).consume()


def _sync_storage(session, credentials, project_id, update_tag):
    client = build_client("storage", "v1", credentials=credentials)
    buckets = _list_pages(
        client.buckets(),
        "list",
        "items",
        project=project_id,
        projection="full",
    )
    data, labels = storage.transform_gcp_buckets_and_labels({"items": buckets})
    storage.load_gcp_buckets(session, data, project_id, update_tag)
    storage.load_gcp_bucket_labels(session, labels, project_id, update_tag)


def _sync_secrets(session, credentials, project_id, update_tag):
    client = build_client("secretmanager", "v1", credentials=credentials)
    secrets = _list_pages(
        client.projects().secrets(),
        "list",
        "secrets",
        parent=f"projects/{project_id}",
    )
    secretsmanager.load_secrets(
        session,
        secretsmanager.transform_secrets(secrets),
        project_id,
        update_tag,
    )


def _sync_policies(session, credentials, project_id, update_tag):
    # Search only this project's direct policies. Organization-wide effective
    # policy enumeration would expand the connected provider's authorization scope.
    client = AssetServiceClient(credentials=credentials)
    policies = []
    for result in client.search_all_iam_policies(
        request={"scope": f"projects/{project_id}"},
    ):
        data = MessageToDict(result._pb, preserving_proto_field_name=True)
        resource = data["resource"]
        policies.append(
            {
                "policies": [
                    {"attached_resource": resource, "policy": data.get("policy", {})}
                ],
            }
        )
    load_policies(session, project_id, update_tag, policies)


def _sync_project_policy(session, credentials, project_id, update_tag):
    # Keep project IAM independent from CAI permissions/API availability.
    crm = build_client("cloudresourcemanager", "v1", credentials=credentials)
    project_policy = (
        crm.projects()
        .getIamPolicy(
            resource=project_id,
            body={"options": {"requestedPolicyVersion": 3}},
        )
        .execute(num_retries=3)
    )
    load_policies(
        session,
        project_id,
        update_tag,
        [
            {
                "policies": [
                    {
                        "attached_resource": f"//cloudresourcemanager.googleapis.com/projects/{project_id}",
                        "policy": project_policy,
                    }
                ]
            }
        ],
    )


def load_policies(session, project_id, update_tag, policies):
    bindings = policy_bindings.transform_bindings(
        {
            "project_id": project_id,
            "policy_results": policies,
        }
    )
    # Only service accounts are independently inventoried. Other direct members
    # are references, not expanded directory identities or group memberships.
    members = sorted({member for binding in bindings for member in binding["members"]})
    session.run(
        """
        UNWIND $members AS email
        MERGE (principal:GCPPrincipal {email: email})
        ON CREATE SET principal.id = email, principal.firstseen = $update_tag
        SET principal.lastupdated = $update_tag
        WITH principal
        MATCH (project:GCPProject {id: $project_id})
        MERGE (project)-[:RESOURCE]->(principal)
        """,
        members=members,
        project_id=project_id,
        update_tag=update_tag,
    ).consume()
    kinds = [
        {"email": member.split(":", 1)[1], "kind": member.split(":", 1)[0]}
        for result in policies
        for policy in result.get("policies", [])
        for binding in policy.get("policy", {}).get("bindings", [])
        for member in binding.get("members", [])
        if member.startswith(("user:", "group:", "serviceAccount:"))
    ]
    session.run(
        "UNWIND $members AS member MATCH (p:GCPProject {id: $project})-[:RESOURCE]->(n:GCPPrincipal {email: member.email}) "
        "SET n.kind = member.kind",
        project=project_id,
        members=kinds,
    ).consume()
    policy_bindings.load_bindings(session, bindings, project_id, update_tag)
    session.run(
        """
        MATCH (p:GCPProject {id: $project_id})-[:RESOURCE]->(b:GCPPolicyBinding)
        WHERE b.resource = '//cloudresourcemanager.googleapis.com/projects/' + toString(p.projectnumber)
        MERGE (b)-[:APPLIES_TO]->(p)
        """,
        project_id=project_id,
    ).consume()
    # Cartography SA ids are numeric, whereas CAI addresses them by email.
    session.run(
        """
        MATCH (:GCPProject {id: $project_id})-[:RESOURCE]->(b:GCPPolicyBinding)
        MATCH (s:GCPServiceAccount)
        WHERE b.resource ENDS WITH '/serviceAccounts/' + s.email
        MERGE (b)-[:APPLIES_TO]->(s)
        """,
        project_id=project_id,
    ).consume()


def start_gcp_ingestion(
    neo4j_session: neo4j.Session,
    cartography_config: Config,
    prowler_api_provider: Provider,
    prowler_sdk_provider: GcpProvider,
    attack_paths_scan: AttackPathsScan,
) -> dict[str, str]:
    from tasks.jobs.attack_paths import db_utils

    project_id = str(prowler_api_provider.uid)
    if project_id not in prowler_sdk_provider.projects:
        raise ValueError(
            f"GCP project {project_id} is not in the credential's scan scope"
        )
    credentials = prowler_sdk_provider.session
    if credentials is None:
        raise ValueError("GCP Attack Paths requires connected-provider credentials")
    crm = build_client("cloudresourcemanager", "v1", credentials=credentials)
    project = dict(crm.projects().get(projectId=project_id).execute(num_retries=3))
    if project.get("projectId") != project_id:
        raise ValueError("GCP project response does not match the connected provider")
    parent = project.get("parent") or {}
    project["parent"] = f"{parent.get('type', '')}s/{parent.get('id', '')}"
    load_gcp_projects(neo4j_session, [project], cartography_config.update_tag, "")

    base_steps = [
        ("iam", _sync_service_accounts),
        ("compute", _sync_compute),
        ("storage", _sync_storage),
        ("secretmanager", _sync_secrets),
    ]

    def bound(sync):
        return lambda: sync(
            neo4j_session, credentials, project_id, cartography_config.update_tag
        )

    extended = gcp_extended.steps(
        neo4j_session, credentials, project_id, cartography_config.update_tag
    )
    steps = [(name, bound(sync)) for name, sync in base_steps]
    steps += extended[3:]
    steps += [
        ("project_iam", bound(_sync_project_policy)),
        ("policy_bindings", bound(_sync_policies)),
    ]
    steps += extended[:3]
    errors = run_steps(
        neo4j_session,
        "GCPProject",
        project_id,
        steps,
        gcp_extended.CLOUD_ERRORS,
        cartography_config.update_tag,
        lambda progress: db_utils.update_attack_paths_scan_progress(
            attack_paths_scan, progress
        ),
    )
    neo4j_session.run(
        """
        MATCH (p:GCPProject {id: $project})-[:RESOURCE]->(b:GCPPolicyBinding)
        MATCH (p)-[:RESOURCE*0..1]->(target)
        WHERE (b)-[:APPLIES_TO]->(target)
           OR (b)-[:APPLIES_TO]->(p)
           OR (b)-[:INHERITED_BY]->(p)
        MERGE (b)-[:SCOPE_CONTAINS]->(target)
        """,
        project=project_id,
    ).consume()
    neo4j_session.run(
        """
        MATCH (p:GCPProject {id: $project_id})-[:RESOURCE]->(r)
        SET r._prowler_uid = coalesce(r._prowler_uid, r.id)
        """,
        project_id=project_id,
    ).consume()
    return errors
