from enum import Enum

from api.db_router import MainRouter
from api.models import Provider, Role, User
from django.db.models import QuerySet
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import BasePermission


class Permissions(Enum):
    MANAGE_USERS = "manage_users"
    MANAGE_ACCOUNT = "manage_account"
    MANAGE_BILLING = "manage_billing"
    MANAGE_PROVIDERS = "manage_providers"
    MANAGE_INTEGRATIONS = "manage_integrations"
    MANAGE_SCANS = "manage_scans"
    MANAGE_TRIAGE = "manage_triage"
    MANAGE_TRIAGE_EXCEPTIONS = "manage_triage_exceptions"
    UNLIMITED_VISIBILITY = "unlimited_visibility"


class HasPermissions(BasePermission):
    """
    Custom permission to check if the user's role has the required permissions.
    The required permissions should be specified in the view as a list in `required_permissions`.
    """

    def has_permission(self, request, view):
        required_permissions = getattr(view, "required_permissions", [])
        if not required_permissions and not request.auth:
            return True
        tenant_id = getattr(request, "tenant_id", None)
        if not tenant_id:
            tenant_id = request.auth.get("tenant_id") if request.auth else None
        if not tenant_id:
            return False

        user_roles = (
            User.objects.using(MainRouter.admin_db)
            .get(id=request.user.id)
            .roles.using(MainRouter.admin_db)
            .filter(tenant_id=tenant_id)
        )
        if not user_roles:
            return not required_permissions
        role = user_roles[0]
        if role.vrika_policy is not None:
            from api.rbac.vrika import prepare_role

            role = prepare_role(request, view, role)
            request.user._vrika_request_role = role
            if request.method in ("GET", "HEAD", "OPTIONS") and role.unlimited_visibility:
                return True
            cloud_configuration = any(
                part in request.path.split("/")
                for part in ("lighthouse", "lighthouse-configurations", "processors")
            )
            if cloud_configuration and role.unlimited_visibility:
                return True

        for perm in required_permissions:
            if not getattr(role, perm.value, False):
                return False

        return True


def get_role(user: User, tenant_id: str) -> Role:
    """
    Retrieve the role assigned to the given user in the specified tenant.

    Raises:
        PermissionDenied: If the user has no role in the given tenant.
    """
    role = getattr(user, "_vrika_request_role", None)
    if role is not None and str(role.tenant_id) == str(tenant_id):
        return role
    role = user.roles.using(MainRouter.admin_db).filter(tenant_id=tenant_id).first()
    if role is None:
        raise PermissionDenied("User has no role in this tenant.")
    return role


def get_providers(role: Role) -> QuerySet[Provider]:
    """
    Return a distinct queryset of Providers accessible by the given role.

    If the role has no associated provider groups, an empty queryset is returned.

    Args:
        role: A Role instance.

    Returns:
        A QuerySet of Provider objects filtered by the role's provider groups.
        If the role has no provider groups, returns an empty queryset.
    """
    tenant_id = role.tenant_id
    if hasattr(role, "_vrika_provider_ids"):
        return Provider.objects.filter(tenant_id=tenant_id, pk__in=role._vrika_provider_ids)
    provider_groups = role.provider_groups.all()
    if not provider_groups.exists():
        return Provider.objects.none()

    return Provider.objects.filter(
        tenant_id=tenant_id, provider_groups__in=provider_groups
    ).distinct()
