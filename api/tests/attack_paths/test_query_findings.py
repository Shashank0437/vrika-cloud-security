from types import SimpleNamespace
from unittest.mock import patch

import pytest
from api.attack_paths.queries.findings import return_paths_with_findings
from api.attack_paths.queries.registry import get_queries_for_provider
from api.attack_paths.views_helpers import execute_query
from tasks.jobs.attack_paths.config import get_provider_label

PROVIDER_ID = "11111111-1111-1111-1111-111111111111"
OTHER_PROVIDER_ID = "22222222-2222-2222-2222-222222222222"


def query(provider, query_id):
    return next(q for q in get_queries_for_provider(provider) if q.id == query_id)


@pytest.fixture(params=["gcp", "azure"])
def permission_graph(graph, request):
    provider = request.param
    if provider == "gcp":
        graph.run("""
            CREATE (root:GCPProject {id: 'scope'}),
              (principal:GCPPrincipal {id: 'principal'}),
              (binding:GCPPolicyBinding {id: 'binding', has_condition: false}),
              (role:GCPRole {id: 'role', token_create: true, deleted: false}),
              (target:GCPServiceAccount {id: 'target'}),
              (root)-[:RESOURCE]->(binding),
              (principal)-[:HAS_ALLOW_POLICY]->(binding),
              (binding)-[:GRANTS_ROLE]->(role),
              (binding)-[:SCOPE_CONTAINS]->(target)
        """).consume()
        definition = query(provider, "gcp-permission-token-create")
    else:
        graph.run("""
            CREATE (root:AzureSubscription {id: 'scope'}),
              (principal:AzurePrincipal {id: 'principal'}),
              (binding:AzureRoleAssignment {id: 'binding'}),
              (role:AzureRoleDefinition {id: 'role', vm_run_command: true}),
              (target:AzureVirtualMachine {id: 'target'}),
              (root)-[:RESOURCE]->(binding),
              (principal)-[:HAS_ROLE_ASSIGNMENT]->(binding),
              (binding)-[:ROLE_ASSIGNED]->(role),
              (binding)-[:SCOPE_CONTAINS]->(target)
        """).consume()
        definition = query(provider, "azure-permission-vm-run-command")
    label = get_provider_label(PROVIDER_ID)
    graph.run(f"MATCH (n) SET n:`{label}`").consume()
    return graph, definition


def api_result(graph, definition, provider_id=PROVIDER_ID):
    backend = SimpleNamespace(
        execute_read_query=lambda database, cypher, parameters: graph.run(
            cypher, parameters
        ).graph(),
    )
    with patch(
        "api.attack_paths.views_helpers.sink_module.get_backend_for_scan",
        return_value=backend,
    ):
        return execute_query(
            "neo4j", definition, {"provider_uid": "scope"}, provider_id, object()
        )


def test_permission_query_returns_related_findings_in_api_graph(permission_graph):
    graph, definition = permission_graph
    label = get_provider_label(PROVIDER_ID)
    graph.run(f"""
        MATCH (target {{id: 'target'}}), (principal {{id: 'principal'}})
        CREATE (finding:ProwlerFinding:`{label}` {{id: 'failed', status: 'FAIL', muted: false}}),
          (pass:ProwlerFinding:`{label}` {{id: 'passed', status: 'PASS', muted: false}}),
          (muted:ProwlerFinding:`{label}` {{id: 'muted', status: 'FAIL', muted: true}}),
          (outside:`{label}` {{id: 'outside'}}),
          (unrelated:ProwlerFinding:`{label}` {{id: 'unrelated', status: 'FAIL', muted: false}}),
          (target)-[:HAS_FINDING]->(finding), (principal)-[:HAS_FINDING]->(finding),
          (target)-[:HAS_FINDING]->(pass), (target)-[:HAS_FINDING]->(muted),
          (outside)-[:HAS_FINDING]->(unrelated)
    """).consume()
    result = api_result(graph, definition)
    finding_nodes = [
        node for node in result["nodes"] if "ProwlerFinding" in node["labels"]
    ]
    assert [node["properties"]["id"] for node in finding_nodes] == ["failed"]
    edges = [edge for edge in result["relationships"] if edge["label"] == "HAS_FINDING"]
    assert len(edges) == 2
    assert all(edge["target"] == finding_nodes[0]["id"] for edge in edges)
    ids = {node["properties"]["id"]: node["id"] for node in result["nodes"]}
    assert {edge["source"] for edge in edges} == {ids["target"], ids["principal"]}
    assert len(result["nodes"]) == len({node["id"] for node in result["nodes"]})
    assert result["total_nodes"] == len(result["nodes"])


def test_paths_without_findings_remain_visible(permission_graph):
    graph, definition = permission_graph
    result = api_result(graph, definition)
    assert {node["properties"]["id"] for node in result["nodes"]} == {
        "principal",
        "binding",
        "role",
        "target",
    }
    assert len(result["relationships"]) == 3
    assert not list(graph.run(definition.cypher, provider_uid="missing-scope"))
    assert api_result(graph, definition, OTHER_PROVIDER_ID)["nodes"] == []


def test_related_findings_remain_provider_isolated(permission_graph):
    graph, definition = permission_graph
    other_label = get_provider_label(OTHER_PROVIDER_ID)
    graph.run(f"""
        MATCH (target {{id: 'target'}})
        CREATE (foreign:ProwlerFinding:`{other_label}` {{id: 'foreign', status: 'FAIL', muted: false}}),
          (target)-[:HAS_FINDING]->(foreign)
    """).consume()
    result = api_result(graph, definition)
    assert not any("ProwlerFinding" in node["labels"] for node in result["nodes"])
    assert not any(edge["label"] == "HAS_FINDING" for edge in result["relationships"])


def test_nullable_optional_path_is_preserved(graph):
    graph.run("""
        CREATE (project:GCPProject {id: 'scope'}),
          (principal:GCPPrincipal {id: 'principal'}),
          (binding:GCPPolicyBinding {id: 'binding'}),
          (principal)-[:HAS_ALLOW_POLICY]->(binding)-[:INHERITED_BY]->(project)
    """).consume()
    result = graph.run(
        query("gcp", "gcp-inherited-iam").cypher, provider_uid="scope"
    ).graph()
    assert {node["id"] for node in result.nodes} == {"scope", "principal", "binding"}
    assert len(result.relationships) == 2


@pytest.mark.parametrize("provider", ["gcp", "azure"])
def test_all_predefined_queries_include_findings(provider):
    for definition in get_queries_for_provider(provider):
        assert (
            "collect(DISTINCT finding_relationship) AS finding_relationships"
            in definition.cypher
        ), definition.id


@pytest.mark.parametrize("names", [(), ("path; DELETE n",), ("path.name",)])
def test_invalid_enrichment_identifiers_fail(names):
    with pytest.raises(ValueError, match="path variable"):
        return_paths_with_findings(*names)
