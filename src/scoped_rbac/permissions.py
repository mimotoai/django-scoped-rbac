from rest_framework import permissions
from .models import RoleAssignment
from . import policy
from .rbac_contexts import DEFAULT_CONTEXT, SOME_CONTEXT
from .conf import policy_for_authenticated, policy_for_staff, policy_for_unauthenticated


NOT_ALLOWED = policy.RootPolicy().add_policy(policy.POLICY_FALSE)
ALLOWED = policy.RootPolicy().add_policy(policy.POLICY_TRUE)


def sum_policies(total_policy, additional_policy):
    """Add the `additional_policy` to the `total_policy` and also cache the permissions
    granted by `additional_policy` as also granted in `SOME_CONTEXT`.
    """
    total_policy.add_policy(additional_policy)
    if isinstance(additional_policy, policy.PolicyDict):
        policy_dict = additional_policy
    elif isinstance(additional_policy, policy.CompoundPolicy):
        policy_dict = additional_policy.policy_dict
    else:
        policy_dict = policy.PolicyDict({})
    for context, p in policy_dict.policies.items():
        total_policy.add_policy_for_context(p, SOME_CONTEXT)


def policy_for(request):
    # TODO figure out caching for this
    if request.user.is_superuser:
        return ALLOWED
    total_policy = policy.RootPolicy()
    if request.user is None or request.user.is_anonymous:
        sum_policies(total_policy, policy_for_unauthenticated())
    else:
        sum_policies(total_policy, policy_for_authenticated())
        if request.user.is_staff:
            sum_policies(total_policy, policy_for_staff())
        role_assignments = RoleAssignment.objects.filter(
            user=request.user
        ).prefetch_related("role")
        policy_by_role = dict()
        for role_assignment in role_assignments.all():
            role = role_assignment.role
            if role not in policy_by_role:
                policy_by_role[role] = role.as_policy
            policy_for_role = policy_by_role[role]
            total_policy.add_policy_for_context(
                policy_for_role, role_assignment.rbac_context
            )
            total_policy.add_policy_for_context(policy_for_role, SOME_CONTEXT)
    return total_policy


def http_action_iri_for(request):
    method = request.method
    if method == "HEAD":
        method = "GET"
    return f"http.{method}"


class IsAuthorized(permissions.BasePermission):
    """
    Custom permission handling using the `rbac` model.
    """

    def has_object_permission(self, request, view, obj):
        """
        Requires that the object is `AccessControlled`.
        """
        if not hasattr(view, "resource_type_iri_for"):
            return True
        effective_policy = policy_for(request)
        permission = policy.Permission(
                http_action_iri_for(request), obj.resource_type.iri),
        permitted = effective_policy.should_allow(
            policy.Permission(http_action_iri_for(request), obj.resource_type.iri),
            obj.rbac_context,
            obj,
        )
        return permitted

    def has_permission(self, request, view):
        """
        Requires the view to be an `AccessControlledAPIView`.
        """
        if not hasattr(view, "resource_type_iri_for"):
            return True
        effective_policy = policy_for(request)
        if request.method in ("PUT", "POST"):
            resource = request.data if request.method in ("PUT", "POST") else None
            rbac_context = resource.get("rbac_context", DEFAULT_CONTEXT)
        else:
            resource = None
            rbac_context = SOME_CONTEXT
        permission = policy.Permission(
            http_action_iri_for(request), view.resource_type_iri_for(request)
        )
        permitted = effective_policy.should_allow(
            permission,
            rbac_context,
            resource,
        )
        return permitted
