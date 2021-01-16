from rest_framework.authentication import BaseAuthentication
from .conf import policy_for_unauthenticated
from .permissions import http_action_iri_for
from .rbac_contexts import SOME_CONTEXT


class ConditionalAnonymousAuthentication(BaseAuthentication):
    def authenticate(self, request):
        if "HTTP_AUTHORIZATION" in request.META:
            return None
        policy = policy_for_unauthenticated()
        if policy.should_allow(
                policy.Permission(
                    http_action_iri_for(request), view.resource_type_iri_for(request)
                ),
                SOME_CONTEXT,
                None):
            return AnonymousUser(), None
        return None
