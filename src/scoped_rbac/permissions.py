from rest_framework import permissions

from . import policy
from .conf import policy_for_authenticated, policy_for_staff, policy_for_unauthenticated
from .models import RoleAssignment
from .rbac_contexts import DEFAULT_CONTEXT, SOME_CONTEXT

NOT_ALLOWED = policy.RootPolicy().add_policy(policy.POLICY_FALSE)
ALLOWED = policy.RootPolicy().add_policy(policy.POLICY_TRUE)


def sum_policies(total_policy, additional_policy):
    """Add the `additional_policy` to the `total_policy` and also cache the permissions
    granted by `additional_policy` as also granted in `SOME_CONTEXT`.
    """
    total_policy.add_policy(additional_policy)
    # Only the grants under each context are copied: a top-level condition or
    # allow-all already applies in every context, SOME_CONTEXT included.
    for context, p in policy.as_node(additional_policy).children.items():
        total_policy.add_policy_for_context(p, SOME_CONTEXT)


_POLICY_CACHE_ATTR = "_scoped_rbac_policy"


def policy_for(request):
    """
    Return the effective `RootPolicy` for `request.user`.

    It is computed once per request and cached on the request, so every check made
    while handling a request uses the grants the user had when it was first
    computed. In particular, the checks `AccessControlledModelViewSet` makes after
    saving an update are not affected by changes the update itself made to the
    user's `RoleAssignment`s.
    """
    cached = getattr(request, _POLICY_CACHE_ATTR, None)
    if cached is not None and cached[0] is request.user:
        return cached[1]
    effective_policy = _build_policy_for(request)
    try:
        setattr(request, _POLICY_CACHE_ATTR, (request.user, effective_policy))
    except AttributeError:
        pass
    return effective_policy


def _build_policy_for(request):
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


def _object_contexts(obj):
    """
    Return the rbac contexts of `obj`: its `rbac_contexts` if it defines them (which
    may be empty, granting nothing), else `[obj.rbac_context]`.
    """
    contexts = getattr(obj, "rbac_contexts", None)
    if contexts is None:
        return [obj.rbac_context]
    return list(contexts)


class IsAuthorized(permissions.BasePermission):
    """
    Custom permission handling using the `rbac` model.
    """

    def contexts_for(self, obj):
        return _object_contexts(obj)

    def contexts_from(self, view, content):
        if hasattr(view.serializer_class, "contexts_from"):
            return view.serializer_class.contexts_from(content)
        return [content.get("rbac_context", DEFAULT_CONTEXT)]

    def has_object_permission(self, request, view, obj):
        """
        Requires that the object is `AccessControlled`.
        """
        if not hasattr(view, "resource_type_iri_for"):
            return True
        contexts = self.contexts_for(obj)
        if not contexts:
            # An object with no contexts is granted by no role; only superusers
            # (whose policy_for allows everything) may act on it.
            return bool(request.user.is_superuser)
        return any(
            self.has_context_permission(request, view, obj, context)
            for context in contexts
        )

    def has_context_permission(self, request, view, obj, context):
        """
        True if the request's action on `obj`'s resource type is allowed in
        `context`, with `obj` as the resource for any condition.
        """
        if not hasattr(view, "resource_type_iri_for"):
            return True
        return policy_for(request).should_allow(
            policy.Permission(http_action_iri_for(request), obj.resource_type.iri),
            context,
            obj,
        )

    def has_permission(self, request, view):
        """
        Requires the view to be an `AccessControlledAPIView`.
        """
        if not hasattr(view, "resource_type_iri_for"):
            return True
        effective_policy = policy_for(request)
        if request.method in ("PUT", "POST"):
            resource = request.data if request.method in ("PUT", "POST") else None
            rbac_contexts = self.contexts_from(view, resource)
        else:
            resource = None
            rbac_contexts = [SOME_CONTEXT]
        permission = policy.Permission(
            http_action_iri_for(request), view.resource_type_iri_for(request)
        )
        for context in rbac_contexts:
            if effective_policy.should_allow(
                permission,
                context,
                resource,
            ):
                return True
        return False
