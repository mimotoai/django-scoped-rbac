"""Updating Roles through the scrudful RoleViewSet."""

import pytest

from .helpers import (
    RA,
    ROLE,
    ROLE_URL,
    assert_permission_denied,
    client_for,
    grant,
    make_role,
    scrudful_preconditions,
)


@pytest.mark.django_db
def test_patch_moving_role_to_unauthorized_context_is_forbidden(user):
    grant(user, {"http.PATCH": [ROLE], "http.GET": [ROLE]}, "A")
    target = make_role({"http.GET": [RA]}, "A")

    response = client_for(user).patch(
        ROLE_URL.format(target.pk), {"rbac_context": "V"}, format="json"
    )

    assert_permission_denied(response)
    target.refresh_from_db()
    assert target.rbac_context == "A"


@pytest.mark.django_db
def test_patch_role_within_granted_context_is_allowed(user):
    grant(user, {"http.PATCH": [ROLE], "http.GET": [ROLE]}, "A")
    target = make_role({"http.GET": [RA]}, "A")

    response = client_for(user).patch(
        ROLE_URL.format(target.pk), {"definition": {"http.GET": [ROLE]}}, format="json"
    )

    assert response.status_code == 200, response.content
    target.refresh_from_db()
    assert (target.rbac_context, target.definition) == ("A", {"http.GET": [ROLE]})


@pytest.mark.django_db
def test_put_moving_role_to_unauthorized_context_is_forbidden(user):
    grant(user, {"http.PUT": [ROLE], "http.GET": [ROLE]}, "A")
    target = make_role({"http.GET": [RA]}, "A")

    response = client_for(user).put(
        ROLE_URL.format(target.pk),
        {"definition": {"http.GET": [RA]}, "rbac_context": "V"},
        format="json",
        **scrudful_preconditions(target),
    )

    assert_permission_denied(response)
    target.refresh_from_db()
    assert target.rbac_context == "A"


@pytest.mark.django_db
def test_put_role_keeping_context_is_allowed(user):
    grant(user, {"http.PUT": [ROLE], "http.GET": [ROLE]}, "A")
    target = make_role({"http.GET": [RA]}, "A")

    response = client_for(user).put(
        ROLE_URL.format(target.pk),
        {"definition": {"http.GET": [ROLE]}, "rbac_context": "A"},
        format="json",
        **scrudful_preconditions(target),
    )

    assert response.status_code == 200, response.content
    target.refresh_from_db()
    assert target.definition == {"http.GET": [ROLE]}
