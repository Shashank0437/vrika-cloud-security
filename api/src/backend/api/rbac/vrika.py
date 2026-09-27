"""Scoped access for Vrika-managed roles, layered over native provider filtering."""

from api.models import AttackPathsScan, Finding, Provider, Resource, Scan, Task
from django.core.exceptions import FieldDoesNotExist
from django.db.models import Q
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import SAFE_METHODS


def permits(bindings, action, module="cloud_security", project_id=None):
    actions = {
        "admin": {"view", "execute", "edit", "manage_members", "manage_roles"},
        "viewer": {"view"},
        "analyst": {"view", "execute", "edit"},
        "lead": {"view", "execute", "edit", "manage_members"},
    }
    for binding in bindings:
        if action not in actions.get(binding.get("role"), set()):
            continue
        scope = binding.get("scope_type")
        if scope == "global":
            return True
        if scope == "module" and binding.get("scope_id") == module:
            return True
        if scope == "project" and project_id and binding.get("scope_id") == project_id:
            return True
    return False


def provider_lookup(model, visited=()):
    if model is Provider:
        return "pk"
    if model in visited:
        return None
    for name in ("provider", "scan", "resource", "finding", "triage"):
        try:
            field = model._meta.get_field(name)
        except FieldDoesNotExist:
            continue
        if field.is_relation and field.related_model:
            child = provider_lookup(field.related_model, (*visited, model))
            if child:
                return f"{name}__{child}"
    return None


def check_references(value, tenant_id, provider_ids):
    models = {
        "providers": Provider,
        "scans": Scan,
        "findings": Finding,
        "resources": Resource,
        "attack-paths-scans": AttackPathsScan,
    }
    checked = 0
    if isinstance(value, list):
        return sum(check_references(item, tenant_id, provider_ids) for item in value)
    if not isinstance(value, dict):
        return 0
    if value.get("type") in models and value.get("id"):
        model = models[value["type"]]
        if not model.objects.filter(
            tenant_id=tenant_id,
            pk=value["id"],
            **{f"{provider_lookup(model)}__in": provider_ids},
        ).exists():
            raise PermissionDenied("Related resource is outside your project scope.")
        checked += 1
    for key, child in value.items():
        base = key.removesuffix("_ids").removesuffix("_id")
        if key.endswith(("_id", "_ids")) and f"{base}s" in models:
            identifiers = child if isinstance(child, list) else [child]
            for identifier in identifiers:
                checked += check_references(
                    {"type": f"{base}s", "id": identifier},
                    tenant_id,
                    provider_ids,
                )
        else:
            checked += check_references(child, tenant_id, provider_ids)
    return checked


def scoped_tasks(queryset, provider_ids):
    strings = [str(pid) for pid in provider_ids]
    scan_tasks = Scan.objects.filter(provider_id__in=provider_ids).values("task_id")
    return queryset.filter(
        Q(pk__in=scan_tasks)
        | (Q(vrika_provider_ids__contained_by=strings) & ~Q(vrika_provider_ids=[]))
    )


def prepare_role(request, view, role):
    policy = role.vrika_policy
    if policy is None:
        return role
    bindings = policy["bindings"]
    admin = permits(bindings, "manage_roles")
    action = (
        "view"
        if request.method in SAFE_METHODS
        else (
            "execute"
            if "scans" in request.path or "attack-paths" in request.path
            else "edit"
        )
    )
    project_id = request.auth.get("vrika_project_id") if request.auth else None
    if project_id and not permits(bindings, action, project_id=project_id):
        raise PermissionDenied("Access to this project has been revoked.")
    project_ids = [
        b["scope_id"]
        for b in bindings
        if b["scope_type"] == "project"
        and permits(bindings, action, project_id=b["scope_id"])
        and (not project_id or b["scope_id"] == project_id)
    ]
    if project_id:
        project_ids = [project_id]
    unrestricted = permits(bindings, action) and not project_id
    if not unrestricted and not project_ids:
        raise PermissionDenied(f"Missing {action} permission in Cloud Security.")

    allowed = Provider.objects.filter(
        tenant_id=role.tenant_id,
        provider_groups__name__in=[f"vrika-project:{pid}" for pid in project_ids],
    ).values_list("pk", flat=True)
    role._vrika_provider_ids = list(allowed)
    role.unlimited_visibility = unrestricted
    role._vrika_project_id = project_id
    role._vrika_action = action
    request.user._vrika_request_role = role
    write = permits(bindings, "edit", project_id=project_id) or (
        action != "view" and bool(project_ids)
    )
    for field in role.PERMISSION_FIELDS:
        setattr(
            role,
            field,
            admin
            or (
                write
                and field
                in {
                    "manage_providers",
                    "manage_scans",
                    "manage_triage",
                    "manage_triage_exceptions",
                    "manage_integrations",
                }
            ),
        )
    admin_paths = {
        "roles",
        "memberships",
        "invitations",
        "tenants",
        "api-keys",
        "users",
        "saml-config",
    }
    if (
        action == "view"
        and not permits(bindings, "view", module=None)
        and any(part in admin_paths for part in request.path.split("/"))
        and not request.path.rstrip("/").endswith("/users/me")
    ):
        raise PermissionDenied("Global read access required for administration.")
    # Native role/account mutation would bypass Vrika's single manage_roles gate.
    if (
        not admin
        and request.method not in SAFE_METHODS
        and any(
            part in request.path.split("/")
            for part in (
                "roles",
                "memberships",
                "invitations",
                "tenants",
                "api-keys",
                "provider-groups",
                "saml-config",
            )
        )
    ):
        raise PermissionDenied("Manage role bindings and memberships in Vrika.")

    queryset = getattr(view, "queryset", None)
    model = queryset.model if queryset is not None else None
    pk = view.kwargs.get("pk")
    finding_uid = view.kwargs.get("finding_uid")
    if action == "view" and request.path.rstrip("/").endswith("/compliance-frameworks"):
        return role
    if not unrestricted:
        if finding_uid:
            from api.triage import resolve_finding

            resolve_finding(request, finding_uid)
        lookup = provider_lookup(model) if model else None
        if model is Task:
            tasks = scoped_tasks(
                Task.objects.filter(tenant_id=role.tenant_id), role._vrika_provider_ids
            )
            if pk and not tasks.filter(pk=pk).exists():
                raise PermissionDenied("Task is outside your project scope.")
        elif lookup and pk:
            if not model.objects.filter(
                pk=pk,
                tenant_id=role.tenant_id,
                **{f"{lookup}__in": role._vrika_provider_ids},
            ).exists():
                raise PermissionDenied("Resource is outside your project scope.")
        elif model is Provider and request.method == "POST" and not pk and project_id:
            pass
        elif not lookup and not (
            action == "view" and request.path.rstrip("/").endswith("/users/me")
        ):
            raise PermissionDenied("This resource requires module-wide access.")
        if request.method not in SAFE_METHODS:
            checked = check_references(
                request.data, role.tenant_id, role._vrika_provider_ids
            )
            creating_provider = model is Provider and not pk and project_id
            if not pk and not finding_uid and not checked and not creating_provider:
                raise PermissionDenied("A project-scoped resource is required.")
    return role


def filter_scoped_queryset(request, queryset):
    role = getattr(request.user, "_vrika_request_role", None)
    if role is None or role.vrika_policy is None or role.unlimited_visibility:
        return queryset
    if queryset.model is Task:
        return scoped_tasks(queryset, role._vrika_provider_ids)
    lookup = provider_lookup(queryset.model)
    if not lookup:
        return queryset.none()
    return queryset.filter(**{f"{lookup}__in": role._vrika_provider_ids})
