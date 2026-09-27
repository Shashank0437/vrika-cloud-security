import hashlib
import hmac
import os
import time
from uuid import UUID

from api.db_router import MainRouter
from api.db_utils import rls_transaction
from api.models import (
    Membership,
    Provider,
    ProviderGroup,
    ProviderGroupMembership,
    Role,
    User,
    UserRoleRelationship,
)
from django.contrib.auth.hashers import make_password
from rest_framework.exceptions import AuthenticationFailed, NotFound, ValidationError
from rest_framework_simplejwt.tokens import RefreshToken


def verify_bridge(request):
    secret = (
        os.environ.get("VRIKA_INTERNAL_CONFIG_SECRET")
        or os.environ.get("VRIKA_BRIDGE_SECRET")
        or os.environ.get("PROWLER_BRIDGE_SECRET")
    )
    if not secret:
        raise AuthenticationFailed("Vrika bridge is not configured.")
    timestamp = request.headers.get("X-Vrika-Timestamp", "")
    signature = request.headers.get("X-Vrika-Signature", "")
    try:
        fresh = abs(time.time() - int(timestamp)) < 60
    except ValueError:
        fresh = False
    expected = hmac.new(
        secret.encode(),
        timestamp.encode() + b"." + request.body,
        hashlib.sha256,
    ).hexdigest()
    if not fresh or not hmac.compare_digest(expected, signature):
        raise AuthenticationFailed("Invalid Vrika bridge signature.")


def resolve_provider_projects(payload):
    """Read the authoritative project groups without changing users or permissions."""
    try:
        attrs = payload["data"]["attributes"]
        tenant_id = str(UUID(attrs["tenant_id"]))
        provider_id = str(UUID(attrs["provider_id"]))
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise ValidationError("Invalid provider project lookup payload.") from exc
    with rls_transaction(tenant_id):
        if not Provider.objects.filter(tenant_id=tenant_id, id=provider_id).exists():
            raise NotFound("Provider not found in the requested tenant.")
        names = ProviderGroup.objects.filter(
            tenant_id=tenant_id,
            providers__id=provider_id,
            name__startswith="vrika-project:",
        ).order_by("name").values_list("name", flat=True)[:2]
        return {
            "tenant_id": tenant_id,
            "provider_id": provider_id,
            "project_ids": [name.removeprefix("vrika-project:") for name in names],
        }


def sync_access(payload):
    try:
        attrs = payload["data"]["attributes"]
        if not isinstance(attrs["tenant_id"], str):
            raise TypeError
        tenant_id = str(UUID(attrs["tenant_id"]))
        user_id = str(attrs["vrika_user_id"])
        email = attrs["email"]
        bindings = attrs["bindings"]
        projects = attrs.get("projects", [])
        version = attrs.get("access_version", 0)
        if type(version) is not int or version < 0:
            raise ValueError
        if not user_id or len(user_id) > 128 or not isinstance(email, str):
            raise ValueError
        if not isinstance(bindings, list) or not isinstance(projects, list):
            raise TypeError
        if any(
            not isinstance(project, str) or not project or len(project) > 128
            for project in projects
        ):
            raise ValueError
        provision = attrs.get("provision")
        if provision is not None and (
            not isinstance(provision, dict)
            or not isinstance(provision.get("name"), str)
            or not isinstance(provision.get("password"), str)
            or not provision["password"]
        ):
            raise ValueError
        assignment = attrs.get("provider_assignment")
        if assignment is not None:
            if (
                not isinstance(assignment, dict)
                or assignment.get("project_id") not in projects
            ):
                raise ValueError
            if not isinstance(assignment.get("provider_ids"), list):
                raise ValueError
            for identifier in assignment["provider_ids"]:
                if not isinstance(identifier, str):
                    raise TypeError
                UUID(identifier)
        for b in bindings:
            valid = (
                b["role"] in {"viewer", "admin"}
                and b["scope_type"] == "global"
                and b.get("scope_id") is None
                or b["role"] in {"viewer", "analyst"}
                and b["scope_type"] == "module"
                and b["scope_id"] in {"web_security", "cloud_security"}
                or b["role"] in {"viewer", "analyst", "lead"}
                and b["scope_type"] == "project"
                and b["scope_id"] in projects
            )
            if not valid:
                raise ValueError
    except (KeyError, TypeError, ValueError) as exc:
        raise ValidationError("Invalid access synchronization payload.") from exc
    with rls_transaction(tenant_id):
        provision = attrs.get("provision")
        if provision:
            existing = (
                User.objects.using(MainRouter.admin_db).filter(email=email).first()
            )
            if existing is not None and not (
                existing.check_password(provision["password"])
                and Membership.objects.using(MainRouter.admin_db)
                .filter(user=existing, tenant_id=tenant_id)
                .exists()
            ):
                raise ValidationError(
                    "Cloud account already exists; an administrator must link it."
                )
            if existing is None:
                user = User.objects.using(MainRouter.admin_db).create(
                    email=email,
                    name=provision["name"],
                    password=make_password(provision["password"]),
                )
                Membership.objects.using(MainRouter.admin_db).create(
                    user=user, tenant_id=tenant_id
                )
        user = User.objects.get(email=email, membership__tenant_id=tenant_id)
        # The signed bridge owns this per-user role; it is not accepted from a browser.
        role, _ = Role.objects.get_or_create(
            tenant_id=tenant_id,
            name=f"vrika-user:{user_id}",
        )
        role = Role.objects.select_for_update().get(pk=role.pk)
        previous = role.vrika_policy
        if previous and (
            version < previous.get("version", 0)
            or version == previous.get("version", 0)
            and bindings != previous["bindings"]
        ):
            raise ValidationError("Stale access revision; reload your permissions.")
        role.vrika_policy = {"bindings": bindings, "version": version}
        for project_id in projects:
            ProviderGroup.objects.get_or_create(
                tenant_id=tenant_id,
                name=f"vrika-project:{project_id}",
            )
        UserRoleRelationship.objects.filter(user=user, tenant_id=tenant_id).delete()
        UserRoleRelationship.objects.create(user=user, tenant_id=tenant_id, role=role)
        from api.rbac.vrika import permits

        # Persist native flags for the cloud UI's permission controls. Requests
        # re-evaluate scope and object access independently using vrika_policy.
        admin = permits(bindings, "manage_roles")
        write = permits(bindings, "edit") or any(
            b["scope_type"] == "project"
            and permits(bindings, "edit", project_id=b["scope_id"])
            for b in bindings
        )
        for field in role.PERMISSION_FIELDS:
            setattr(
                role,
                field,
                admin
                or (
                    write
                    and field
                    not in {"manage_users", "manage_account", "manage_billing"}
                ),
            )
        role.unlimited_visibility = permits(bindings, "view")
        role.save()
        result = {"synced": True}
        assignment = attrs.get("provider_assignment")
        if assignment:
            project_id = assignment["project_id"]
            if project_id not in projects:
                raise ValidationError("Unknown project.")
            identifiers = set(assignment["provider_ids"])
            providers = Provider.objects.filter(tenant_id=tenant_id, pk__in=identifiers)
            if providers.count() != len(identifiers):
                raise ValidationError("All providers must belong to this tenant.")
            group = ProviderGroup.objects.get(
                tenant_id=tenant_id, name=f"vrika-project:{project_id}"
            )
            ProviderGroupMembership.objects.filter(
                tenant_id=tenant_id, provider_group=group
            ).delete()
            ProviderGroupMembership.objects.filter(
                tenant_id=tenant_id,
                provider_id__in=identifiers,
                provider_group__name__startswith="vrika-project:",
            ).delete()
            ProviderGroupMembership.objects.bulk_create(
                [
                    ProviderGroupMembership(
                        tenant_id=tenant_id, provider_group=group, provider=provider
                    )
                    for provider in providers
                ]
            )
        if attrs.get("list_providers"):
            result["providers"] = [
                {
                    "id": str(p.id),
                    "alias": p.alias or p.uid,
                    "provider": p.provider,
                    "project_id": next(
                        (
                            g.name.removeprefix("vrika-project:")
                            for g in p.provider_groups.all()
                            if g.name.startswith("vrika-project:")
                        ),
                        None,
                    ),
                }
                for p in Provider.objects.filter(tenant_id=tenant_id).prefetch_related(
                    "provider_groups"
                )
            ]
        if attrs.get("issue_tokens"):
            project_id = attrs.get("project_id")
            if project_id and project_id not in projects:
                raise ValidationError("Unknown project.")
            if not permits(bindings, "view", project_id=project_id) and (
                project_id
                or not any(
                    b["scope_type"] == "project"
                    and permits(bindings, "view", project_id=b["scope_id"])
                    for b in bindings
                )
            ):
                raise ValidationError("No Cloud Security access.")
            refresh = RefreshToken.for_user(user)
            refresh["tenant_id"] = tenant_id
            if project_id:
                refresh["vrika_project_id"] = project_id
            result.update(access=str(refresh.access_token), refresh=str(refresh))
        return result
