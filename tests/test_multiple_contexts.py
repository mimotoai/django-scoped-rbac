import pytest
from rest_framework.reverse import reverse
from safetydance import Context
from safetydance_django.test import *
from safetydance_test import And, Given, Then, When, scripted_test

from .fixtures import TestUser, create_user
from .step_extensions import (
    multiple_contexts_editor_role,
    multiple_contexts_reader_role,
)
from .steps import multiple_contexts_editor_url, multiple_contexts_reader_url


@pytest.mark.parametrize(
    "rbac_context, create_role, role_url, status_code",
    [
        ("context_1", multiple_contexts_editor_role, multiple_contexts_editor_url, 201),
        ("context_2", multiple_contexts_editor_role, multiple_contexts_editor_url, 201),
        ("context_1", multiple_contexts_reader_role, multiple_contexts_reader_url, 403),
        ("context_2", multiple_contexts_reader_role, multiple_contexts_reader_url, 403),
        ("context_1", None, None, 403),
        ("context_2", None, None, 403),
    ],
)
@pytest.mark.django_db
@scripted_test
def test_create(
    django_user_model, superuser, rbac_context, create_role, role_url, status_code
):
    user = create_user(django_user_model)
    Given.http.force_authenticate(superuser.instance)
    if create_role is not None:
        create_role(context)
        url = context.get(role_url)
        And.assign_role(url, user, rbac_context)
    And.http.force_authenticate(user.instance)
    When.http.post(
        reverse("examplewithmultiplecontexts-list"),
        {"context_1": "context_1", "context_2": "context_2"},
        format="json",
    )
    Then.http.status_code_is(status_code)
