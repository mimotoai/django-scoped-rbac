"""Update checks with DRF's composed permissions (&, |, ~)."""

import pytest
from rest_framework.permissions import IsAuthenticated

from scoped_rbac.permissions import IsAuthorized
from scoped_rbac.rbac_contexts import SOME_CONTEXT
from scoped_rbac.rest import RoleAssignmentViewSet

from .helpers import (
    PROJECT,
    DenyAll,
    ProjectIsAuthorized,
    ProjectViewSet,
    assert_permission_denied,
    assert_reserved_context_rejected,
    call_view,
    grant,
    with_permissions,
)
from .models import (
    ExampleProjectModel,
)


class ComposedPermissionRoleAssignmentViewSet(RoleAssignmentViewSet):
    permission_classes = [IsAuthenticated & IsAuthorized]


@pytest.mark.django_db
def test_patch_through_composed_permission_classes_checks_saved_context(
    user, ra_patcher_in_a
):
    response = call_view(
        ComposedPermissionRoleAssignmentViewSet,
        user,
        "patch",
        {"rbac_context": "V"},
        pk=ra_patcher_in_a.pk,
    )

    assert_permission_denied(response)
    ra_patcher_in_a.refresh_from_db()
    assert ra_patcher_in_a.rbac_context == "A"


PROJECT_PERMISSIONS = {
    "plain": [ProjectIsAuthorized],
    "and": [ProjectIsAuthorized & IsAuthenticated],
    "not-not": [~~ProjectIsAuthorized],
    "or": [ProjectIsAuthorized | DenyAll],
}


@pytest.fixture(params=sorted(PROJECT_PERMISSIONS))
def project_view(request):
    viewset = with_permissions(ProjectViewSet, *PROJECT_PERMISSIONS[request.param])

    def call(user, method, data, pk=None):
        return call_view(viewset, user, method, data, pk=pk)

    return call


@pytest.mark.django_db
def test_patch_into_reserved_context_via_composed_permission_is_rejected(
    user, project_view
):
    grant(user, {"http.PATCH": [PROJECT]}, "A")
    target = ExampleProjectModel.objects.create(project="A")

    response = project_view(user, "patch", {"project": SOME_CONTEXT}, pk=target.pk)

    assert_reserved_context_rejected(response)
    target.refresh_from_db()
    assert target.project == "A"


@pytest.mark.django_db
def test_post_into_reserved_context_via_composed_permission_is_rejected(
    user, project_view
):
    grant(user, {"http.POST": [PROJECT]}, "A")

    response = project_view(user, "post", {"project": SOME_CONTEXT})

    assert_reserved_context_rejected(response)
    assert not ExampleProjectModel.objects.exists()


@pytest.mark.django_db
def test_patch_and_post_into_granted_context_via_composed_permission_are_allowed(
    user, project_view
):
    grant(user, {"http.PATCH": [PROJECT], "http.POST": [PROJECT]}, "A", "B")
    target = ExampleProjectModel.objects.create(project="A")

    patched = project_view(user, "patch", {"project": "B"}, pk=target.pk)
    created = project_view(user, "post", {"project": "A"})

    assert patched.status_code == 200, patched.content
    assert created.status_code == 201, created.content
    target.refresh_from_db()
    assert target.project == "B"
    assert ExampleProjectModel.objects.filter(project="A").count() == 1
