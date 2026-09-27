import hashlib
import hmac
import json
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest
from api.models import (
    Membership,
    Provider,
    ProviderGroup,
    ProviderGroupMembership,
    Role,
    Scan,
    Task,
    User,
    UserRoleRelationship,
)
from api.rbac.vrika import permits, prepare_role
from api.rbac.vrika_sync import resolve_provider_projects, sync_access, verify_bridge
from api.rls import Tenant
from django.test import RequestFactory
from rest_framework.exceptions import (
    AuthenticationFailed,
    PermissionDenied,
    NotFound,
    ValidationError,
)
from rest_framework.test import APIClient

pytestmark = pytest.mark.django_db


def test_authoritative_provider_project_lookup_is_tenant_scoped(cloud):
    tenant, _, provider, other = cloud
    data = {"data": {"attributes": {
        "tenant_id": str(tenant.pk), "provider_id": str(provider.pk),
    }}}
    assert resolve_provider_projects(data)["project_ids"] == []
    group = ProviderGroup.objects.create(tenant=tenant, name="vrika-project:p1")
    ProviderGroupMembership.objects.create(tenant=tenant, provider=provider, provider_group=group)
    assert resolve_provider_projects(data)["project_ids"] == ["p1"]
    data["data"]["attributes"]["provider_id"] = str(other.pk)
    assert resolve_provider_projects(data)["project_ids"] == []
    data["data"]["attributes"]["tenant_id"] = str(uuid4())
    with pytest.raises(NotFound):
        resolve_provider_projects(data)


def test_ambiguous_project_groups_are_not_silently_selected(cloud):
    tenant, _, provider, _ = cloud
    for name in ("vrika-project:p1", "vrika-project:p2", "unrelated-group"):
        group = ProviderGroup.objects.create(tenant=tenant, name=name)
        ProviderGroupMembership.objects.create(tenant=tenant, provider=provider, provider_group=group)
    result = resolve_provider_projects({"data": {"attributes": {
        "tenant_id": str(tenant.pk), "provider_id": str(provider.pk),
    }}})
    assert result["project_ids"] == ["p1", "p2"]


def test_project_lookup_endpoint_requires_signed_request(cloud, monkeypatch):
    tenant, _, provider, _ = cloud
    monkeypatch.setenv("VRIKA_INTERNAL_CONFIG_SECRET", "test-only")
    client = APIClient()
    body = json.dumps({"data": {"type": "vrika-provider-projects", "attributes": {
        "tenant_id": str(tenant.pk), "provider_id": str(provider.pk),
    }}})
    url = "/api/v1/internal/vrika-provider-projects"
    assert client.post(url, data=body, content_type="application/vnd.api+json").status_code in (401, 403)
    timestamp = str(int(time.time()))
    signature = hmac.new(
        b"test-only", timestamp.encode() + b"." + body.encode(), hashlib.sha256,
    ).hexdigest()
    response = client.post(
        url, data=body, content_type="application/vnd.api+json",
        HTTP_X_VRIKA_TIMESTAMP=timestamp, HTTP_X_VRIKA_SIGNATURE=signature,
    )
    assert response.status_code == 200, response.data
    assert response.data["data"]["attributes"]["provider_id"] == str(provider.pk)
    assert not Role.objects.filter(tenant=tenant).exists()


def binding(role, scope_type, scope_id=None):
    return {"role": role, "scope_type": scope_type, "scope_id": scope_id}


@pytest.fixture
def cloud():
    tenant = Tenant.objects.create(name="RBAC test")
    user = User.objects.create(email=f"{uuid4()}@example.test", name="Test User")
    Membership.objects.create(user=user, tenant=tenant)
    provider = Provider.objects.create(
        tenant=tenant, provider="aws", uid="123456789012"
    )
    other = Provider.objects.create(tenant=tenant, provider="aws", uid="123456789013")
    return tenant, user, provider, other


def payload(cloud, bindings, **extra):
    tenant, user, _, _ = cloud
    return {
        "data": {
            "type": "vrika-access",
            "attributes": {
                "tenant_id": str(tenant.pk),
                "email": user.email,
                "vrika_user_id": "test-vrika-user",
                "bindings": bindings,
                "projects": ["p1", "p2"],
                **extra,
            },
        }
    }


def role_for(cloud):
    tenant, user, _, _ = cloud
    return Role.objects.get(tenant=tenant, users=user)


def request_for(
    user, method="GET", path="/api/v1/providers", data=None, project_id=None
):
    return SimpleNamespace(
        method=method,
        path=path,
        user=user,
        auth={"vrika_project_id": project_id},
        data=data or {},
    )


def test_union_is_action_scoped():
    bindings = [binding("viewer", "global"), binding("lead", "project", "p1")]
    assert permits(bindings, "view", project_id="p2")
    assert not permits(bindings, "edit", project_id="p2")
    assert permits(bindings, "edit", project_id="p1")
    assert not permits(bindings, "manage_roles", project_id="p1")


@pytest.mark.parametrize("role", ["viewer", "analyst"])
def test_explicit_module_binding_does_not_grant_other_module_or_admin(role, cloud):
    _, user, _, _ = cloud
    bindings = [binding(role, "module", "cloud_security")]
    sync_access(payload(cloud, bindings))
    assert permits(bindings, "view")
    assert not permits(bindings, "view", module="web_security")
    assert not permits(bindings, "view", module=None)
    with pytest.raises(PermissionDenied):
        prepare_role(
            request_for(user, "GET", "/api/v1/roles"),
            SimpleNamespace(queryset=Role.objects.all(), kwargs={}),
            role_for(cloud),
        )


@pytest.mark.parametrize("role", ["viewer", "analyst"])
def test_explicit_project_binding_enters_cloud_and_restricts_providers(role, cloud):
    _, user, provider, other = cloud
    result = sync_access(payload(
        cloud, [binding(role, "project", "p1")], issue_tokens=True,
        provider_assignment={"project_id": "p1", "provider_ids": [str(provider.id)]},
    ))
    assert role_for(cloud).manage_scans == (role == "analyst")
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {result['access']}")
    response = client.get("/api/v1/providers")
    assert response.status_code == 200, response.content
    assert [row["id"] for row in response.json()["data"]] == [str(provider.id)]
    assert client.get(f"/api/v1/providers/{other.id}").status_code == 403
    assert client.delete(f"/api/v1/providers/{other.id}").status_code == 403
    assert client.get("/api/v1/roles").status_code == 403
    write = request_for(user, "PATCH", f"/api/v1/providers/{provider.id}", project_id="p1")
    view = SimpleNamespace(queryset=Provider.objects.all(), kwargs={"pk": str(provider.id)})
    if role == "viewer":
        with pytest.raises(PermissionDenied):
            prepare_role(write, view, role_for(cloud))
    else:
        assert prepare_role(write, view, role_for(cloud)).manage_providers


def test_signed_bridge_rejects_missing_stale_and_modified_signatures(monkeypatch):
    monkeypatch.setenv("VRIKA_INTERNAL_CONFIG_SECRET", "test-secret")
    factory = RequestFactory()
    body = b'{"data":{}}'
    timestamp = str(int(time.time()))
    signature = hmac.new(
        b"test-secret", timestamp.encode() + b"." + body, hashlib.sha256
    ).hexdigest()
    good = factory.post(
        "/",
        data=body,
        content_type="application/vnd.api+json",
        HTTP_X_VRIKA_TIMESTAMP=timestamp,
        HTTP_X_VRIKA_SIGNATURE=signature,
    )
    verify_bridge(good)
    for stamp, sig, content in [
        ("", "", body),
        ("1", signature, body),
        (timestamp, signature, b"{}"),
    ]:
        bad = factory.post(
            "/",
            data=content,
            content_type="application/vnd.api+json",
            HTTP_X_VRIKA_TIMESTAMP=stamp,
            HTTP_X_VRIKA_SIGNATURE=sig,
        )
        with pytest.raises(AuthenticationFailed):
            verify_bridge(bad)


def test_sync_replaces_native_admin_and_revokes_old_access(cloud):
    tenant, user, provider, _ = cloud
    admin = Role.objects.create(tenant=tenant, name="admin", manage_account=True)
    UserRoleRelationship.objects.create(tenant=tenant, user=user, role=admin)
    sync_access(payload(cloud, [binding("viewer", "global")]))
    assert user.roles.count() == 1
    role = role_for(cloud)
    assert role.unlimited_visibility
    assert not role.manage_scans
    with pytest.raises(PermissionDenied):
        prepare_role(
            request_for(user, "DELETE", f"/api/v1/providers/{provider.id}"),
            SimpleNamespace(
                queryset=Provider.objects.all(), kwargs={"pk": str(provider.id)}
            ),
            role,
        )


def test_lead_cannot_touch_other_provider_or_mixed_relationship(cloud):
    _, user, provider, other = cloud
    sync_access(
        payload(
            cloud,
            [binding("lead", "project", "p1")],
            provider_assignment={
                "project_id": "p1",
                "provider_ids": [str(provider.id)],
            },
        )
    )
    view = SimpleNamespace(
        queryset=Provider.objects.all(), kwargs={"pk": str(other.id)}
    )
    with pytest.raises(PermissionDenied):
        prepare_role(
            request_for(user, "DELETE", f"/api/v1/providers/{other.id}"),
            view,
            role_for(cloud),
        )
    view = SimpleNamespace(queryset=Scan.objects.all(), kwargs={})
    with pytest.raises(PermissionDenied):
        prepare_role(
            request_for(
                user,
                "POST",
                "/api/v1/scans",
                {"provider": {"type": "providers", "id": str(other.id)}},
            ),
            view,
            role_for(cloud),
        )
    allowed = prepare_role(
        request_for(
            user,
            "POST",
            "/api/v1/scans",
            {"provider": {"type": "providers", "id": str(provider.id)}},
        ),
        view,
        role_for(cloud),
    )
    assert allowed.manage_scans
    assert not allowed.unlimited_visibility


def test_global_viewer_and_lead_union_does_not_write_other_projects(cloud):
    _, user, provider, other = cloud
    sync_access(
        payload(
            cloud,
            [binding("viewer", "global"), binding("lead", "project", "p1")],
            provider_assignment={
                "project_id": "p1",
                "provider_ids": [str(provider.id)],
            },
        )
    )
    view = SimpleNamespace(
        queryset=Provider.objects.all(), kwargs={"pk": str(other.id)}
    )
    with pytest.raises(PermissionDenied):
        prepare_role(
            request_for(user, "DELETE", f"/api/v1/providers/{other.id}"),
            view,
            role_for(cloud),
        )
    read = prepare_role(
        request_for(user),
        SimpleNamespace(queryset=Provider.objects.all(), kwargs={}),
        role_for(cloud),
    )
    assert read.unlimited_visibility


def test_web_only_user_is_denied_cloud_even_with_old_token(cloud):
    _, user, _, _ = cloud
    sync_access(payload(cloud, [binding("analyst", "module", "web_security")]))
    with pytest.raises(PermissionDenied):
        prepare_role(
            request_for(user),
            SimpleNamespace(queryset=Provider.objects.all(), kwargs={}),
            role_for(cloud),
        )


def test_cloud_analyst_cannot_change_native_roles(cloud):
    _, user, _, _ = cloud
    sync_access(payload(cloud, [binding("analyst", "module", "cloud_security")]))
    with pytest.raises(PermissionDenied):
        prepare_role(
            request_for(user, "PATCH", "/api/v1/roles/role1"),
            SimpleNamespace(queryset=Role.objects.all(), kwargs={"pk": "role1"}),
            role_for(cloud),
        )


def test_signed_endpoint_contract(cloud, monkeypatch):
    monkeypatch.setenv("VRIKA_INTERNAL_CONFIG_SECRET", "test-secret")
    body = json.dumps(payload(cloud, [binding("viewer", "global")])).encode()
    timestamp = str(int(time.time()))
    signature = hmac.new(
        b"test-secret", timestamp.encode() + b"." + body, hashlib.sha256
    ).hexdigest()
    client = APIClient()
    response = client.post(
        "/api/v1/internal/vrika-access",
        data=body,
        content_type="application/vnd.api+json",
        HTTP_X_VRIKA_TIMESTAMP=timestamp,
        HTTP_X_VRIKA_SIGNATURE=signature,
    )
    assert response.status_code == 200, response.content
    assert response.json()["data"]["attributes"]["synced"]


def test_real_cloud_endpoints_enforce_scoped_roles(cloud):
    _, _, provider, other = cloud
    result = sync_access(
        payload(
            cloud,
            [binding("lead", "project", "p1")],
            issue_tokens=True,
            project_id="p1",
            provider_assignment={
                "project_id": "p1",
                "provider_ids": [str(provider.id)],
            },
        )
    )
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {result['access']}")
    response = client.get("/api/v1/providers")
    assert response.status_code == 200, response.content
    assert [row["id"] for row in response.json()["data"]] == [str(provider.id)]
    assert client.get(f"/api/v1/providers/{other.id}").status_code == 403
    assert client.delete(f"/api/v1/providers/{other.id}").status_code == 403
    assert client.get("/api/v1/users/me").status_code == 200
    denied = client.post(
        "/api/v1/scans",
        data=json.dumps(
            {
                "data": {
                    "type": "scans",
                    "attributes": {"name": "Denied"},
                    "relationships": {
                        "provider": {"data": {"type": "providers", "id": str(other.id)}}
                    },
                },
            }
        ),
        content_type="application/vnd.api+json",
    )
    assert denied.status_code == 403, denied.content


def test_project_token_cannot_expand_scope_and_legacy_tokens_revoke(cloud):
    _, _, provider, _ = cloud
    result = sync_access(
        payload(cloud, [binding("admin", "global")], issue_tokens=True)
    )
    old_access = result["access"]
    sync_access(payload(cloud, [binding("viewer", "global")], access_version=1))
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {old_access}")
    assert client.delete(f"/api/v1/providers/{provider.id}").status_code == 403
    assert client.get("/api/v1/providers").status_code == 200
    sync_access(
        payload(cloud, [binding("analyst", "module", "web_security")], access_version=2)
    )
    assert client.get("/api/v1/providers").status_code == 403


def test_cross_tenant_assignment_is_atomic(cloud):
    foreign = Tenant.objects.create(name="Other organization")
    provider = Provider.objects.create(
        tenant=foreign, provider="aws", uid="111111111111"
    )
    sync_access(payload(cloud, [binding("viewer", "global")]))
    with pytest.raises(ValidationError):
        sync_access(
            payload(
                cloud,
                [binding("admin", "global")],
                access_version=1,
                provider_assignment={
                    "project_id": "p1",
                    "provider_ids": [str(provider.id)],
                },
            )
        )
    assert role_for(cloud).vrika_policy["bindings"] == [binding("viewer", "global")]
    assert not provider.provider_groups.exists()


@pytest.mark.parametrize(
    "invalid", [None, [], {"data": None}, {"data": {"attributes": {"tenant_id": 123}}}]
)
def test_malformed_payload_is_rejected(invalid):
    with pytest.raises(ValidationError):
        sync_access(invalid)


def test_stale_and_conflicting_revisions_cannot_restore_permissions(cloud):
    sync_access(payload(cloud, [binding("viewer", "global")], access_version=2))
    for revision in (1, 2):
        with pytest.raises(ValidationError):
            sync_access(
                payload(cloud, [binding("admin", "global")], access_version=revision)
            )
    assert not role_for(cloud).manage_account


def test_project_selected_admin_is_still_provider_scoped(cloud):
    _, _, provider, other = cloud
    result = sync_access(
        payload(
            cloud,
            [binding("admin", "global")],
            issue_tokens=True,
            project_id="p1",
            provider_assignment={
                "project_id": "p1",
                "provider_ids": [str(provider.id)],
            },
        )
    )
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {result['access']}")
    response = client.get("/api/v1/providers")
    assert response.status_code == 200, response.content
    assert [row["id"] for row in response.json()["data"]] == [str(provider.id)]
    assert client.get(f"/api/v1/providers/{other.id}").status_code == 403


def test_project_lead_creates_assigned_provider_and_reads_only_scoped_tasks(cloud):
    tenant, _, provider, other = cloud
    result = sync_access(
        payload(
            cloud,
            [binding("lead", "project", "p1")],
            issue_tokens=True,
            project_id="p1",
            provider_assignment={
                "project_id": "p1",
                "provider_ids": [str(provider.id)],
            },
        )
    )
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {result['access']}")
    response = client.post(
        "/api/v1/providers",
        data=json.dumps(
            {
                "data": {
                    "type": "providers",
                    "attributes": {
                        "provider": "aws",
                        "uid": "123456789099",
                        "alias": "Project provider",
                    },
                }
            }
        ),
        content_type="application/vnd.api+json",
    )
    assert response.status_code == 201, response.content
    created = Provider.objects.get(pk=response.json()["data"]["id"])
    assert created.provider_groups.filter(name="vrika-project:p1").exists()
    own_task = Task.objects.create(tenant=tenant, vrika_provider_ids=[str(provider.id)])
    other_task = Task.objects.create(tenant=tenant, vrika_provider_ids=[str(other.id)])
    assert client.get(f"/api/v1/tasks/{own_task.id}").status_code == 200
    assert client.get(f"/api/v1/tasks/{other_task.id}").status_code == 403
    response = client.get("/api/v1/compliance-frameworks?filter[provider_type]=aws")
    assert response.status_code == 200, response.content


def test_cloud_provision_retry_reuses_only_same_account(cloud):
    _, user, _, _ = cloud
    user.set_password("test-only-provision-password")
    user.save()
    attributes = {"name": user.name, "password": "test-only-provision-password"}
    first = sync_access(
        payload(cloud, [binding("viewer", "global")], provision=attributes)
    )
    assert first["synced"]
    assert sync_access(
        payload(cloud, [binding("viewer", "global")], provision=attributes)
    )["synced"]
    with pytest.raises(ValidationError):
        sync_access(
            payload(
                cloud,
                [binding("viewer", "global")],
                provision={"name": user.name, "password": "different-test-password"},
            )
        )
