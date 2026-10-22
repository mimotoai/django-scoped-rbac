"""Updating RoleAssignments: the original exploit (GitLab issue #1) and its allowed
counterparts.
"""

import pytest
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory

from scoped_rbac.models import RoleAssignment
from scoped_rbac.permissions import policy_for
from scoped_rbac.policy import Permission

from .helpers import (
    RA,
    RA_LIST_URL,
    RA_URL,
    ROLE,
    assert_permission_denied,
    assign,
    client_for,
    grant,
    make_role,
    role_link,
    user_link,
)


@pytest.mark.parametrize("request_format", ["json", "multipart"])
@pytest.mark.django_db
def test_patch_moving_role_assignment_to_unauthorized_context_is_forbidden(
    user, ra_patcher_in_a, request_format
):
    powerful_role = make_role(True, "V")
    original_role_id = ra_patcher_in_a.role_id

    response = client_for(user).patch(
        RA_URL.format(ra_patcher_in_a.pk),
        {"rbac_context": "V", "role": role_link(powerful_role)},
        format=request_format,
    )

    assert_permission_denied(response)
    ra_patcher_in_a.refresh_from_db()
    assert ra_patcher_in_a.rbac_context == "A"
    assert ra_patcher_in_a.role_id == original_role_id


@pytest.mark.django_db
def test_moving_own_assignment_is_checked_against_grants_from_before_the_update(
    user, ra_patcher_in_a
):
    # After the save, this very assignment would grant PATCH in V.
    response = client_for(user).patch(
        RA_URL.format(ra_patcher_in_a.pk), {"rbac_context": "V"}, format="json"
    )

    assert_permission_denied(response)
    ra_patcher_in_a.refresh_from_db()
    assert ra_patcher_in_a.rbac_context == "A"


@pytest.mark.django_db
def test_patch_moving_role_assignment_to_context_with_only_get_is_forbidden(user):
    grant(user, {"http.PATCH": [RA], "http.GET": [RA]}, "A")
    grant(user, {"http.GET": [RA]}, "V")
    target = assign(user, make_role({"http.GET": [ROLE]}), "A")

    response = client_for(user).patch(
        RA_URL.format(target.pk), {"rbac_context": "V"}, format="json"
    )

    assert_permission_denied(response)
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

    assert_permission_denied(response)
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
    grant(user, {"http.PATCH": [RA], "http.GET": [RA]}, "A", "V")
    target = assign(user, make_role({"http.GET": [ROLE]}, "A"), "A")

    response = client_for(user).patch(
        RA_URL.format(target.pk), {"rbac_context": "V"}, format="json"
    )

    assert response.status_code == 200, response.content
    assert response.data["rbac_context"] == "V"
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
def test_post_into_granted_context_is_allowed(user):
    grant(user, {"http.POST": [RA]}, "A")

    response = client_for(user).post(
        RA_LIST_URL,
        {
            "user": user_link(user),
            "role": role_link(make_role({})),
            "rbac_context": "A",
        },
        format="json",
    )

    assert response.status_code == 201, response.content
    assert RoleAssignment.objects.filter(rbac_context="A", user=user).count() == 2


@pytest.mark.django_db
def test_policy_for_is_cached_per_request_and_user(
    user, django_user_model, django_assert_num_queries
):
    grant(user, {"http.GET": [RA]}, "A")
    other_user = django_user_model.objects.create(username="no-grants")
    request = Request(APIRequestFactory().get("/"))
    get_ra = Permission("http.GET", RA)

    request.user = other_user
    assert not policy_for(request).should_allow(get_ra, "A", None)

    request.user = user
    assert policy_for(request).should_allow(get_ra, "A", None)
    with django_assert_num_queries(0):
        assert policy_for(request).should_allow(get_ra, "A", None)
