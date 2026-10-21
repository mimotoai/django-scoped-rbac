from rest_framework.filters import BaseFilterBackend

from .permissions import http_action_iri_for, policy_for
from .policy import Permission


class RbacFilter(BaseFilterBackend):
    """
    Filter that only allows users to see the objects they're authorized to access for
    the request.
    """

    def filter_queryset(self, request, queryset, view):
        if request.method == "GET":
            return self.filter_queryset_for_get(request, queryset, view)
        else:
            return queryset

    def filter_queryset_for_get(self, request, queryset, view):
        policy = policy_for(request)
        contexts = policy.get_contexts_for(
            Permission(
                http_action_iri_for(request), view.resource_type_iri_for(request)
            )
        )
        if contexts is None:
            return queryset
        if not contexts:
            return queryset.none()
        return queryset.filter(rbac_context__in=contexts)
