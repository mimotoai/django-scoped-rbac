"""Shared helpers for the update-authorization tests (GitLab issue #1)."""

from django.db import router
from django.test import override_settings
from django.utils.http import http_date, quote_etag
from django.utils.timezone import now
from rest_framework.permissions import BasePermission
from rest_framework.test import APIClient, APIRequestFactory, force_authenticate
from scrudful import __version__ as scrudful_version

from scoped_rbac.models import Role, RoleAssignment
from scoped_rbac.permissions import IsAuthorized
from scoped_rbac.rest import AccessControlledModelViewSet

from .models import (
    ExampleAccessControlledModel,
    ExampleCachedContextsModel,
    ExampleContextTag,
    ExampleDerivedContextModel,
    ExampleFolder,
    ExampleProjectModel,
    ExampleTaggedContextsModel,
    ExampleWithMultipleContexts,
)
from .serializers import ExampleProjectModelSerializer

RA = "rbac.RoleAssignment"
ROLE = "rbac.Role"
DERIVED = ExampleDerivedContextModel.resource_type.iri
TAGGED = ExampleTaggedContextsModel.resource_type.iri
CACHED = ExampleCachedContextsModel.resource_type.iri
EXAMPLE = ExampleAccessControlledModel.resource_type.iri
MULTI = ExampleWithMultipleContexts.resource_type.iri
PROJECT = ExampleProjectModel.resource_type.iri

RA_URL = "/api/scoped-rbac/role-assignments/{}/"
RA_LIST_URL = "/api/scoped-rbac/role-assignments/"
ROLE_URL = "/api/scoped-rbac/roles/{}/"
DERIVED_URL = "/api/example-derived-context-models/{}/"
DERIVED_LIST_URL = "/api/example-derived-context-models/"
TAGGED_URL = "/api/example-tagged-contexts-models/{}/"
CACHED_URL = "/api/example-cached-contexts-models/{}/"
EXAMPLE_URL = "/api/example-access-controlled-models/{}/"
MULTI_URL = "/api/example-with-multiple-contexts/{}/"

PERMISSION_DENIED = "You do not have permission to perform this action."


# Rows


def make_role(definition, rbac_context=""):
    return Role.objects.create(
        definition=definition, rbac_context=rbac_context, modified_at=now(), etag="r"
    )


def assign(user, role, rbac_context):
    return RoleAssignment.objects.create(
        user=user, role=role, rbac_context=rbac_context, modified_at=now(), etag="a"
    )


def grant(user, definition, *contexts):
    """Grant `definition` to `user` in each of `contexts`; return the Role."""
    role = make_role(definition)
    for rbac_context in contexts:
        assign(user, role, rbac_context)
    return role


def tagged(*contexts):
    obj = ExampleTaggedContextsModel.objects.create()
    obj.tags.set([ExampleContextTag.objects.create(ctx=c) for c in contexts])
    return obj


def multi(context_1, context_2):
    return ExampleWithMultipleContexts.objects.create(
        context_1=context_1, context_2=context_2
    )


def derived(name="doc", ctx="A"):
    return ExampleDerivedContextModel.objects.create(
        name=name, folder=ExampleFolder.objects.create(ctx=ctx)
    )


def role_link(role):
    return f"http://testserver{ROLE_URL.format(role.pk)}"


def user_link(user):
    return f"http://testserver/api/users/{user.pk}/"


# Requests


def client_for(user):
    client = APIClient()
    client.force_authenticate(user)
    return client


VIEW_ACTIONS = {
    "patch": "partial_update",
    "put": "update",
    "post": "create",
    "delete": "destroy",
}


def call_view(viewset, user, method, data=None, pk=None):
    """Call `viewset`'s action for `method` directly (no URL routing) as `user`."""
    request = getattr(APIRequestFactory(), method)("/", data, format="json")
    force_authenticate(request, user=user)
    view = viewset.as_view({method: VIEW_ACTIONS[method]})
    kwargs = {} if pk is None else {"pk": str(pk)}
    return view(request, **kwargs).render()


def scrudful_preconditions(role):
    return {
        "HTTP_IF_MATCH": quote_etag(role.etag + scrudful_version),
        "HTTP_IF_UNMODIFIED_SINCE": http_date(role.modified_at.timestamp()),
    }


# Assertions


def assert_permission_denied(response):
    assert response.status_code == 403, response.content
    assert response.data["detail"] == PERMISSION_DENIED
    assert response.data["detail"].code == "permission_denied"


def assert_reserved_context_rejected(response):
    assert response.status_code == 400, response.content
    assert [error.code for error in response.data] == ["reserved_rbac_context"]


# Permissions and views


class DenyAll(BasePermission):
    def has_permission(self, request, view):
        return False

    def has_object_permission(self, request, view, obj):
        return False


class AllowAll(BasePermission):
    def has_permission(self, request, view):
        return True

    def has_object_permission(self, request, view, obj):
        return True


class ProjectIsAuthorized(IsAuthorized):
    """The object's (and the request body's) context is its `project`."""

    def contexts_for(self, obj):
        return [obj.project]

    def contexts_from(self, view, content):
        return [content.get("project", "")]


class ProjectViewSet(AccessControlledModelViewSet):
    queryset = ExampleProjectModel.objects.all()
    serializer_class = ExampleProjectModelSerializer
    resource_type_iri = ExampleProjectModel.resource_type.iri
    permission_classes = [ProjectIsAuthorized]


def with_permissions(viewset, *permission_classes):
    """A subclass of `viewset` using `permission_classes`."""
    return type(
        viewset.__name__, (viewset,), {"permission_classes": list(permission_classes)}
    )


# Database routers


class ReadReplicaRouter:
    """Primary/replica: every read goes to the replica, every write to the primary."""

    def db_for_read(self, model, **hints):
        return "replica"

    def db_for_write(self, model, **hints):
        return "default"

    def allow_relation(self, obj1, obj2, **hints):
        return True


class OtherDatabaseRouter:
    """Routes the derived-context models (reads and writes) to "other"."""

    routed = (ExampleDerivedContextModel, ExampleFolder)

    def db_for_read(self, model, **hints):
        return "other" if model in self.routed else None

    db_for_write = db_for_read


def installed_routers(*routers):
    """Install `routers` for the duration; check Django resets them afterwards."""
    with override_settings(DATABASE_ROUTERS=list(routers)):
        assert router.routers == list(routers)
        yield
    assert router.routers == []
