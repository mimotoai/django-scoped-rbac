"""Updates must be authorized against the ``rbac_context`` the object will be saved
in, not only the context it currently has (GitLab issue #1).
"""

from types import SimpleNamespace

import pytest
from django.utils.timezone import now
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import AllowAny
from rest_framework.request import Request
from rest_framework.test import APIClient, APIRequestFactory

from scoped_rbac.models import Role, RoleAssignment
from scoped_rbac.permissions import IsAuthorized
from scoped_rbac.rest import RoleAssignmentViewSet, RoleViewSet
from scoped_rbac.serializers import RoleSerializer

RA = "rbac.RoleAssignment"
ROLE = "rbac.Role"
RA_URL = "/api/scoped-rbac/role-assignments/{}/"
ROLE_URL = "/api/scoped-rbac/roles/{}/"


def make_role(definition, rbac_context=""):
    return Role.objects.create(
        definition=definition, rbac_context=rbac_context, modified_at=now(), etag="r"
    )


def assign(user, role, rbac_context):
    return RoleAssignment.objects.create(
        user=user, role=role, rbac_context=rbac_context, modified_at=now(), etag="a"
    )


def role_link(role):
    return f"http://testserver{ROLE_URL.format(role.pk)}"


def user_link(user):
    return f"http://testserver/api/users/{user.pk}/"


def client_for(user):
    client = APIClient()
    client.force_authenticate(user)
    return client


def destination_check_request(user):
    request = Request(APIRequestFactory().patch("/"))
    request.user = user
    return request


@pytest.fixture
def user(django_user_model):
    return django_user_model.objects.create(username="context-a-admin")


@pytest.fixture
def ra_patcher_in_a(user):
    """`user` may PATCH and GET RoleAssignments in context A only; returns the
    user's own RoleAssignment (in A)."""
    role = make_role({"http.PATCH": [RA], "http.GET": [RA]}, "A")
    return assign(user, role, "A")


@pytest.mark.django_db
def test_patch_moving_role_assignment_to_unauthorized_context_is_forbidden(
    user, ra_patcher_in_a
):
    powerful_role = make_role(True, "V")
    original_role_id = ra_patcher_in_a.role_id

    response = client_for(user).patch(
        RA_URL.format(ra_patcher_in_a.pk),
        {"rbac_context": "V", "role": role_link(powerful_role)},
        format="json",
    )

    assert response.status_code == 403, response.content
    ra_patcher_in_a.refresh_from_db()
    assert ra_patcher_in_a.rbac_context == "A"
    assert ra_patcher_in_a.role_id == original_role_id


@pytest.mark.xfail(
    raises=TypeError,
    strict=True,
    reason="PATCH on RoleViewSet crashes before authorization: scrudful forwards "
    "partial=True to RoleViewSet.Meta.etag_func, which does not accept it.",
)
@pytest.mark.django_db
def test_patch_moving_role_to_unauthorized_context_is_forbidden(user):
    assign(user, make_role({"http.PATCH": [ROLE], "http.GET": [ROLE]}, "A"), "A")
    target = make_role({"http.GET": [RA]}, "A")

    response = client_for(user).patch(
        ROLE_URL.format(target.pk), {"rbac_context": "V"}, format="json"
    )

    assert response.status_code == 403, response.content
    target.refresh_from_db()
    assert target.rbac_context == "A"


@pytest.mark.django_db
def test_role_update_moving_to_unauthorized_context_is_denied_without_saving(user):
    # Drives RoleViewSet.perform_update directly, since PATCH over HTTP currently
    # crashes in scrudful (see the xfail above).
    assign(user, make_role({"http.PATCH": [ROLE], "http.GET": [ROLE]}, "A"), "A")
    target = make_role({"http.GET": [RA]}, "A")
    request = destination_check_request(user)
    view = RoleViewSet(
        request=request, action="partial_update", kwargs={}, format_kwarg=None
    )
    serializer = RoleSerializer(
        target, data={"rbac_context": "V"}, partial=True, context={"request": request}
    )
    serializer.is_valid(raise_exception=True)

    with pytest.raises(PermissionDenied):
        view.perform_update(serializer)

    target.refresh_from_db()
    assert target.rbac_context == "A"


@pytest.mark.django_db
def test_put_moving_role_assignment_to_unauthorized_context_is_forbidden(user):
    # Regression guard: has_permission already checks the PUT body's context.
    role = make_role({"http.PUT": [RA], "http.GET": [RA]}, "A")
    own_assignment = assign(user, role, "A")

    response = client_for(user).put(
        RA_URL.format(own_assignment.pk),
        {"user": user_link(user), "role": role_link(role), "rbac_context": "V"},
        format="json",
    )

    assert response.status_code == 403, response.content
    own_assignment.refresh_from_db()
    assert own_assignment.rbac_context == "A"


@pytest.mark.django_db
def test_put_keeping_context_is_allowed(user):
    role = make_role({"http.PUT": [RA], "http.GET": [RA]}, "A")
    own_assignment = assign(user, role, "A")

    response = client_for(user).put(
        RA_URL.format(own_assignment.pk),
        {"user": user_link(user), "role": role_link(role), "rbac_context": "A"},
        format="json",
    )

    assert response.status_code == 200, response.content


@pytest.mark.django_db
def test_patch_omitting_context_is_allowed(user, ra_patcher_in_a):
    response = client_for(user).patch(
        RA_URL.format(ra_patcher_in_a.pk),
        {"role": role_link(ra_patcher_in_a.role)},
        format="json",
    )

    assert response.status_code == 200, response.content
    ra_patcher_in_a.refresh_from_db()
    assert ra_patcher_in_a.rbac_context == "A"


@pytest.mark.django_db
def test_patch_keeping_same_context_is_allowed(user, ra_patcher_in_a):
    response = client_for(user).patch(
        RA_URL.format(ra_patcher_in_a.pk), {"rbac_context": "A"}, format="json"
    )

    assert response.status_code == 200, response.content
    ra_patcher_in_a.refresh_from_db()
    assert ra_patcher_in_a.rbac_context == "A"


@pytest.mark.django_db
def test_patch_changing_role_within_own_context_is_allowed(user, ra_patcher_in_a):
    other_role = make_role({"http.GET": [ROLE]}, "A")

    response = client_for(user).patch(
        RA_URL.format(ra_patcher_in_a.pk),
        {"role": role_link(other_role)},
        format="json",
    )

    assert response.status_code == 200, response.content
    ra_patcher_in_a.refresh_from_db()
    assert ra_patcher_in_a.rbac_context == "A"
    assert ra_patcher_in_a.role_id == other_role.pk


@pytest.mark.django_db
def test_patch_moving_to_context_with_grant_in_both_contexts_is_allowed(user):
    patcher = make_role({"http.PATCH": [RA], "http.GET": [RA]}, "")
    assign(user, patcher, "A")
    assign(user, patcher, "V")
    target = assign(user, make_role({"http.GET": [ROLE]}, "A"), "A")

    response = client_for(user).patch(
        RA_URL.format(target.pk), {"rbac_context": "V"}, format="json"
    )

    assert response.status_code == 200, response.content
    target.refresh_from_db()
    assert target.rbac_context == "V"


@pytest.mark.django_db
def test_superuser_patch_moving_context_is_allowed(django_user_model, user):
    superuser = django_user_model.objects.create_superuser("su", "su@x.test", "pw")
    target = assign(user, make_role({"http.GET": [ROLE]}, "A"), "A")

    response = client_for(superuser).patch(
        RA_URL.format(target.pk), {"rbac_context": "V"}, format="json"
    )

    assert response.status_code == 200, response.content
    target.refresh_from_db()
    assert target.rbac_context == "V"


@pytest.mark.django_db
def test_destination_permission_allows_when_any_one_context_is_authorized(user):
    assign(user, make_role({"http.PATCH": [RA]}, "A"), "A")
    request = destination_check_request(user)
    view = RoleAssignmentViewSet()

    allowed = SimpleNamespace(rbac_contexts=["V", "A"], rbac_context="V")
    denied = SimpleNamespace(rbac_contexts=["V", "W"], rbac_context="A")

    assert IsAuthorized().has_destination_permission(request, view, allowed)
    assert not IsAuthorized().has_destination_permission(request, view, denied)


@pytest.mark.django_db
def test_destination_check_skips_permissions_without_destination_hook(user):
    view = RoleAssignmentViewSet(permission_classes=[AllowAny])
    request = destination_check_request(user)

    # No grants at all: would be denied if IsAuthorized were consulted.
    view.check_destination_permissions(request, SimpleNamespace(rbac_context="V"))


@pytest.mark.django_db
def test_update_candidate_applies_fields_without_touching_instance_or_m2m(user):
    from django.contrib.auth.models import Group

    from scoped_rbac.rest import AccessControlledModelViewSet

    group = Group.objects.create(name="g")
    own_assignment = assign(user, make_role({}, "A"), "A")
    original_role = own_assignment.role  # populates the FK cache
    new_role = make_role({}, "V")

    candidate = AccessControlledModelViewSet.update_candidate(
        SimpleNamespace(
            instance=own_assignment,
            validated_data={"rbac_context": "V", "role": new_role, "note": "x"},
        )
    )
    assert (candidate.rbac_context, candidate.role, candidate.note) == (
        "V",
        new_role,
        "x",
    )
    assert own_assignment.rbac_context == "A"
    assert own_assignment.role == original_role

    # Assigning a many-to-many directly raises TypeError, so it must be skipped.
    user_candidate = AccessControlledModelViewSet.update_candidate(
        SimpleNamespace(
            instance=user, validated_data={"username": "renamed", "groups": [group]}
        )
    )
    assert user_candidate.username == "renamed"
    assert list(user.groups.all()) == []
