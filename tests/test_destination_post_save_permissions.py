"""After an update, only the RBAC permissions are checked against the saved object."""

import pytest
from rest_framework.permissions import BasePermission, IsAuthenticated

from scoped_rbac.models import RoleAssignment
from scoped_rbac.permissions import IsAuthorized
from scoped_rbac.rest import RoleAssignmentViewSet

from .helpers import (
    BOTH_CONTEXTS,
    EXAMPLE,
    AllowAll,
    BothContextsViewSet,
    DenyAll,
    NamedModelViewSet,
    assert_permission_denied,
    call_view,
    grant,
    with_permissions,
)
from .models import ExampleAccessControlledModel, ExampleBothContextsModel


class NotLocked(BasePermission):
    """An application object permission: locked objects cannot be edited."""

    def has_object_permission(self, request, view, obj):
        return obj.name != "locked"


@pytest.mark.django_db
def test_app_object_permissions_are_not_rechecked_after_the_save(user):
    grant(user, {"http.PATCH": [EXAMPLE]}, "A")
    target = ExampleAccessControlledModel.objects.create(name="draft", rbac_context="A")
    viewset = with_permissions(NamedModelViewSet, IsAuthorized, NotLocked)

    response = call_view(viewset, user, "patch", {"name": "locked"}, pk=target.pk)

    assert response.status_code == 200, response.content
    target.refresh_from_db()
    assert target.name == "locked"


@pytest.mark.parametrize(
    "permissions",
    [[IsAuthenticated & IsAuthorized], [DenyAll | IsAuthorized]],
    ids=["and", "or"],
)
@pytest.mark.django_db
def test_composed_rbac_permission_still_checks_the_destination(
    user, ra_patcher_in_a, permissions
):
    viewset = with_permissions(RoleAssignmentViewSet, *permissions)

    response = call_view(
        viewset, user, "patch", {"rbac_context": "V"}, pk=ra_patcher_in_a.pk
    )

    assert_permission_denied(response)
    ra_patcher_in_a.refresh_from_db()
    assert ra_patcher_in_a.rbac_context == "A"


@pytest.mark.django_db
def test_destination_requires_rbac_even_when_another_permission_allows(
    user, ra_patcher_in_a
):
    # AllowAll | IsAuthorized: DRF's OR short-circuits at AllowAll before and
    # after the save, so policy_for is first called by the post-save RBAC check.
    # It must still see the grants from before the update (PATCH in A only), not
    # those of the moved assignment itself (PATCH in V).
    viewset = with_permissions(RoleAssignmentViewSet, AllowAll | IsAuthorized)

    response = call_view(
        viewset, user, "patch", {"rbac_context": "V"}, pk=ra_patcher_in_a.pk
    )

    assert_permission_denied(response)
    assert RoleAssignment.objects.get(pk=ra_patcher_in_a.pk).rbac_context == "A"


class NoPostSaveChecksViewSet(RoleAssignmentViewSet):
    def get_post_save_permissions(self):
        return []


@pytest.mark.django_db
def test_overriding_post_save_permissions_to_none_skips_the_check(
    user, ra_patcher_in_a
):
    response = call_view(
        NoPostSaveChecksViewSet,
        user,
        "patch",
        {"rbac_context": "V"},
        pk=ra_patcher_in_a.pk,
    )

    assert response.status_code == 200, response.content
    ra_patcher_in_a.refresh_from_db()
    assert ra_patcher_in_a.rbac_context == "V"


# A model with an rbac_context column and rbac_contexts: RbacFilter lists objects
# by the column, so moving the column needs permission in its new value too.


@pytest.mark.django_db
def test_moving_rbac_context_column_to_unauthorized_context_is_forbidden(user):
    grant(user, {"http.PATCH": [BOTH_CONTEXTS]}, "A")
    target = ExampleBothContextsModel.objects.create(ctx_a="A", rbac_context="A")

    response = call_view(
        BothContextsViewSet, user, "patch", {"rbac_context": "Z"}, pk=target.pk
    )

    assert_permission_denied(response)
    target.refresh_from_db()
    assert (target.ctx_a, target.rbac_context) == ("A", "A")


@pytest.mark.django_db
def test_moving_rbac_context_column_to_granted_context_is_allowed(user):
    grant(user, {"http.PATCH": [BOTH_CONTEXTS]}, "A", "Z")
    target = ExampleBothContextsModel.objects.create(ctx_a="A", rbac_context="A")

    response = call_view(
        BothContextsViewSet, user, "patch", {"rbac_context": "Z"}, pk=target.pk
    )

    assert response.status_code == 200, response.content
    target.refresh_from_db()
    assert target.rbac_context == "Z"


@pytest.mark.parametrize(
    "granted, new_ctx_a, status",
    [(("A",), "Z", 403), (("A", "B"), "B", 200)],
    ids=["ungranted", "granted"],
)
@pytest.mark.django_db
def test_unchanged_rbac_context_column_follows_rbac_contexts(
    user, granted, new_ctx_a, status
):
    # rbac_context "C" is ungranted but unchanged, so only ctx_a decides.
    grant(user, {"http.PATCH": [BOTH_CONTEXTS]}, *granted)
    target = ExampleBothContextsModel.objects.create(ctx_a="A", rbac_context="C")

    response = call_view(
        BothContextsViewSet, user, "patch", {"ctx_a": new_ctx_a}, pk=target.pk
    )

    assert response.status_code == status, response.content
    target.refresh_from_db()
    assert target.ctx_a == (new_ctx_a if status == 200 else "A")
    assert target.rbac_context == "C"
