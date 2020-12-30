from rest_framework import permissions
from .models import RoleAssignment
from . import policy
from .rbac_contexts import DEFAULT_CONTEXT, SOME_CONTEXT
from .conf import policy_for_unauthenticated, policy_for_staff


NOT_ALLOWED = policy.RootPolicy().add_policy(policy.POLICY_FALSE)
ALLOWED = policy.RootPolicy().add_policy(policy.POLICY_TRUE)


def policy_for(request):
    # TODO figure out caching for this
    if request.user is None or request.user.is_anonymous:
        return policy.RootPolicy().add_policy(policy_for_unauthenticated())
    if request.user.is_superuser:
        return ALLOWED
    role_assignments = RoleAssignment.objects.filter(
        user=request.user
    ).prefetch_related("role")
    total_policy = policy.RootPolicy()
    if request.user.is_staff:
        staff_policy = policy_for_staff()
        total_policy.add_policy(staff_policy)
        policy_dict = policy.PolicyDict({})
        if isinstance(staff_policy, policy.PolicyDict):
            policy_dict = staff_policy
        elif isinstance(staff_policy, policy.CompoundPolicy):
            policy_dict = staff_policy.policy_dict
        for context, p in policy_dict.policies.items():
            total_policy.add_policy_for_context(p, SOME_CONTEXT)
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
    return f"http.{request.method}"


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
        permitted = effective_policy.should_allow(
            policy.Permission(
                http_action_iri_for(request), view.resource_type_iri_for(request)
            ),
            rbac_context,
            resource,
        )
        return permitted
