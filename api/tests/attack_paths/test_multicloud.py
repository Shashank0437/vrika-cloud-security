from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from api.attack_paths.queries.registry import get_queries_for_provider
from tasks.jobs.attack_paths import azure, gcp
from tasks.jobs.attack_paths.config import (
    get_cartography_ingestion_function,
    is_provider_available,
)


@pytest.mark.parametrize("provider", ["aws", "gcp", "azure"])
def test_provider_registered_with_queries(provider):
    assert is_provider_available(provider)
    assert callable(get_cartography_ingestion_function(provider))
    queries = get_queries_for_provider(provider)
    assert queries
    assert all(query.provider == provider for query in queries)
    assert all("$provider_uid" in query.cypher for query in queries)
    assert len({query.id for query in queries}) == len(queries)


def test_unsupported_provider_stays_disabled():
    assert not is_provider_available("github")
    assert get_cartography_ingestion_function("github") is None


@pytest.mark.parametrize(
    ("uid", "expected"),
    [
        (
            "https://www.googleapis.com/compute/v1/projects/p/zones/z/instances/vm",
            "projects/p/zones/z/instances/vm",
        ),
        (
            "//compute.googleapis.com/projects/p/zones/z/instances/vm",
            "projects/p/zones/z/instances/vm",
        ),
        ("projects/p/zones/z/instances/vm", "projects/p/zones/z/instances/vm"),
        ("123456789", "123456789"),
        ("bucket-name", "bucket-name"),
    ],
)
def test_gcp_uid_preserves_scope(uid, expected):
    assert gcp.normalize_uid(uid) == expected


def test_azure_uid_is_case_insensitive_without_losing_scope():
    assert azure.normalize_uid("/subscriptions/S/resourceGroups/R/providers/X/Vm") == (
        "/subscriptions/s/resourcegroups/r/providers/x/vm"
    )


@pytest.mark.parametrize("provider", ["gcp", "azure"])
def test_ingestion_rejects_wrong_scope_before_graph_write(provider):
    module = gcp if provider == "gcp" else azure
    sdk = SimpleNamespace(
        session=object(),
        projects={"other-project": object()},
        identity=SimpleNamespace(subscriptions={"other-subscription": "Other"}),
    )
    session = MagicMock()
    with pytest.raises(ValueError, match="scope|project|subscription"):
        getattr(module, f"start_{provider}_ingestion")(
            session,
            SimpleNamespace(update_tag=1),
            SimpleNamespace(uid="wanted"),
            sdk,
            MagicMock(),
        )
    session.run.assert_not_called()
