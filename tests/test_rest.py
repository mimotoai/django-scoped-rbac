import pytest
from faker import Faker
from rest_framework.reverse import reverse
from safetydance import step_data
from safetydance_django.test import *
from safetydance_test import And, Given, Then, When, scripted_test

from scoped_rbac.rbac_contexts import SOME_CONTEXT

from .policy import policy_for_unauthenticated
from .step_extensions import *


@pytest.mark.django_db
@scripted_test
def test_create_access_controlled_resource(superuser):
    Given.http.force_authenticate(user=superuser.instance)
    When.http.get(reverse("exampleaccesscontrolledmodel-list"))
    Then.http.status_code_is(200)
    And.http.response_json_is(
        {"count": 0, "next": None, "previous": None, "results": []}
    )

    When.http.post(
        reverse("exampleaccesscontrolledmodel-list"),
        {"name": "foo", "rbac_context": ""},
        format="json",
    )
    Then.http.status_code_is(201)
    When.http.get_created()
    Then.http.status_code_is(200)
    And.http.response_json_is({"name": "foo"})

    # FIXME delete after testing, add envelope testing
    # When.http.get(reverse("exampleaccesscontrolledmodel-list"))
    # print(http_response.json())
    # print(http_response._headers)
    # raise Exception("just want the trace")


fake = step_data(Faker, initializer=lambda context: Faker())


@pytest.mark.django_db
@scripted_test
def test_simple_role_assignment(superuser, editor_user, not_authorized_user):
    context_name = fake.pystr(min_chars=10, max_chars=20)

    Given.http.force_authenticate(user=superuser.instance)
    When.http.post(
        reverse("exampleaccesscontrolledmodel-list"),
        {"name": context_name},
        format="json",
    )
    Then.http.status_code_is(201)
    context_url = http_response["location"]

    # Create a role
    Given.create_editor_role(context_url)

    # Assign the role to editor_user
    And.assign_role(role_url, editor_user, context_url)

    # Switch to the editor_user
    And.http.force_authenticate(user=editor_user.instance)

    # Create a protected resource as editor_user
    protected_resource_content = {"definition": {}, "rbac_context": context_url}
    When.http.post(reverse("role-list"), protected_resource_content, format="json")
    Then.http.status_code_is(201)
    protected_resource_url = http_response["location"]

    # Get the resource
    When.http.get(protected_resource_url)
    Then.http.status_code_is(200)
    And.http.response_json_is(protected_resource_content)

    # Update the resource
    updated_content = {"definition": {"GET": True}, "rbac_context": context_url}
    When.put_safe(protected_resource_url, updated_content, format="json")
    Then.http.status_code_is(200)
    When.http.get(protected_resource_url)
    Then.http.status_code_is(200)
    And.http.response_json_is(updated_content)

    # Get the resource list as the editor_user
    When.http.get(reverse("role-list"))
    Then.http.status_code_is(200)

    # Try creating a resource in an unauthorized context
    When.http.post(
        reverse("role-list"),
        {"definition": {}, "rbac_context": fake.pystr(min_chars=10, max_chars=20)},
        format="json",
    )
    Then.http.status_code_is(403)

    # Switch to the not_authorized_user
    Given.http.force_authenticate(user=not_authorized_user.instance)

    # Get the resource list as the not_authorized_user
    # check that it failed
    When.http.get(reverse("role-list"))
    Then.http.status_code_is(403)

    # Get the resource as the not_authorized_user
    # check that it failed
    When.http.get(protected_resource_url)
    Then.http.status_code_is(403)

    # Update the resource
    # check that it failed
    When.http.put(protected_resource_url, {})
    Then.http.status_code_is(403)

    # Delete the resource
    # check that it failed
    When.http.delete(protected_resource_url)
    Then.http.status_code_is(403)

    # Create a resource
    # check that it failed
    When.http.post(reverse("role-list"), {}, format="json")
    Then.http.status_code_is(403)

    # Switch to the editor_user
    # delete the resource
    Given.http.force_authenticate(user=editor_user.instance)
    And.http.get(protected_resource_url)
    And.delete_safe(protected_resource_url)
    Then.http.status_code_is_one_of(200, 204)

    # double check it's gone
    When.http.get(protected_resource_url)
    Then.http.status_code_is(404)


@pytest.mark.django_db
@scripted_test
def test_list_filtering(superuser, editor_user):
    context1_name = fake.pystr(min_chars=10, max_chars=20)
    context2_name = fake.pystr(min_chars=10, max_chars=20)

    Given.http.force_authenticate(user=superuser.instance)
    And.create_editor_role(context1_name)
    role_in_context1_url = role_url
    And.create_editor_role(context2_name)
    role_in_context2_url = role_url

    # validate superuser sees both roles in listing
    When.get_role_list()
    Then.role_list_contains(role_in_context1_url, role_in_context2_url)

    # validate editor_user sees only role in context1 in listing
    When.assign_role(role_in_context1_url, editor_user, context1_name)
    And.http.force_authenticate(user=editor_user.instance)
    And.get_role_list()
    Then.role_list_contains(role_in_context1_url)
    And.role_list_does_not_contain(role_in_context2_url)


def wire_json_of_grants(definition):
    """The policy wire format of a role `definition` of the form
    {action: [resource type]}."""
    return {
        action: {resource_type: True for resource_type in grants}
        for action, grants in definition.items()
    }


@pytest.mark.django_db
@scripted_test
def test_get_user_rbac_policy(superuser, editor_user):
    Given.http.force_authenticate(user=superuser.instance)
    When.get_user_rbac_policy()
    Then.http.status_code_is(200)
    And.http.response_json_is({"*": {"*": {"*": True}}})

    # TODO more comprehensive testing
    context1_name = fake.pystr(min_chars=10, max_chars=20)
    context2_name = fake.pystr(min_chars=10, max_chars=20)

    Given.http.force_authenticate(user=superuser.instance)
    And.create_editor_role(context1_name)
    role_in_context1_url = role_url
    And.create_editor_role(context2_name)
    role_in_context2_url = role_url

    # validate editor_user sees only role in context1 in listing
    Given.assign_role(role_in_context1_url, editor_user, context1_name)
    And.assign_role(role_in_context2_url, editor_user, context2_name)
    And.http.get(role_in_context1_url)
    role_in_context1_json = http_response.json()
    And.http.get(role_in_context2_url)
    role_in_context2_json = http_response.json()
    When.http.force_authenticate(user=editor_user.instance)
    And.get_user_rbac_policy()
    Then.http.response_json_is(
        {
            context: wire_json_of_grants(role_in_context1_json["definition"])
            for context in (context1_name, context2_name, SOME_CONTEXT)
        }
    )


@pytest.mark.django_db
@scripted_test
def test_get_unauthenticated_user_policy():
    When.get_user_rbac_policy()
    Then.http.status_code_is(200)
    # tests.policy.policy_for_unauthenticated, also granted in SOME_CONTEXT.
    grants = {
        "http.GET": {"rbac.ExampleAccessControlledModel": True},
        "http.POST": {"rbac.ExampleAccessControlledModel": True},
    }
    And.http.response_json_is({"": grants, SOME_CONTEXT: grants})


@pytest.mark.django_db
@scripted_test
def test_unauthenticated_user():
    # unauthenticated users may post this resource type in the DEFAULT_CONTEXT per the
    # POLICY_FOR_UNATHENTICATED provided in settings (conftest.py).
    When.http.post(
        reverse("exampleaccesscontrolledmodel-list"),
        {"name": "foo"},
        format="json",
    )
    Then.http.status_code_is(201)
    location = http_response["location"]

    When.http.get(location)
    Then.http.status_code_is(200)
    When.http.head(location)
    Then.http.status_code_is(200)

    When.http.put(location, {"name": "bar"}, format="json")
    Then.http.status_code_is(403)

    When.http.delete(location)
    Then.http.status_code_is(403)

    When.http.get(reverse("exampleaccesscontrolledmodel-list"))
    Then.http.status_code_is(403)
    When.http.head(reverse("exampleaccesscontrolledmodel-list"))
    Then.http.status_code_is(403)


@pytest.mark.django_db
@scripted_test
def test_staff_user(superuser, staff_user):
    # staff users may get list and detail views of this resource type in the
    # DEFAULT_CONTEXT per the POLICY_FOR_UNATHENTICATED provided in settings
    # (conftest.py).

    # first, create a resource in the collection
    Given.http.force_authenticate(user=superuser.instance)
    When.http.post(
        reverse("exampleaccesscontrolledmodel-list"),
        {"name": "foo"},
        format="json",
    )
    Then.http.status_code_is(201)
    resource_instance_url = http_response["location"]

    Given.http.force_authenticate(user=staff_user.instance)
    When.http.get(reverse("exampleaccesscontrolledmodel-list"))
    Then.http.status_code_is(200)
    When.http.head(reverse("exampleaccesscontrolledmodel-list"))
    Then.http.status_code_is(200)

    When.http.get(resource_instance_url)
    Then.http.status_code_is(200)
    When.http.head(resource_instance_url)
    Then.http.status_code_is(200)

    When.http.post(
        reverse("exampleaccesscontrolledmodel-list"),
        {"name": "foo"},
        format="json",
    )
    Then.http.status_code_is(403)

    When.http.put(resource_instance_url, {"name": "bar"}, format="json")
    Then.http.status_code_is(403)

    When.http.delete(resource_instance_url)
    Then.http.status_code_is(403)


@pytest.mark.django_db
@scripted_test
def test_put_permissions(superuser, editor_user):
    context1_name = fake.pystr(min_chars=10, max_chars=20)
    context2_name = fake.pystr(min_chars=10, max_chars=20)

    Given.http.force_authenticate(user=superuser.instance)
    And.create_editor_role(context1_name)
    role_in_context1_url = role_url
    And.create_editor_role(context2_name)
    role_in_context2_url = role_url

    Given.assign_role(role_in_context1_url, editor_user, context1_name)
    And.http.force_authenticate(user=editor_user.instance)
    And.http.get(role_in_context1_url)
    role_content = http_response.json()
    role_content["rbac_context"] = context2_name
    When.put_safe(role_in_context1_url, role_content, format="json")
    # Should be forbidden since the user isn't authorized to put in the target
    # rbac_context
    Then.http.status_code_is(403)

    Given.http.force_authenticate(user=superuser.instance)
    And.http.get(role_in_context2_url)
    etag = http_response["etag"]
    last_modified = http_response["last-modified"]
    And.http.force_authenticate(user=editor_user.instance)
    role_content["rbac_context"] = context1_name
    When.http.put(
        role_in_context2_url,
        role_content,
        HTTP_IF_MATCH=etag,
        HTTP_IF_UNMODIFIED_SINCE=last_modified,
        format="json",
    )
    # Should be forbidden since the user isn't authorized to put in the
    # rbac_context for the resource state current in the server
    Then.http.status_code_is(403)

    Given.http.force_authenticate(user=superuser.instance)
    And.assign_role(role_in_context2_url, editor_user, context2_name)
    And.http.force_authenticate(user=editor_user.instance)
    role_content["rbac_context"] = context1_name
    When.http.put(
        role_in_context2_url,
        role_content,
        HTTP_IF_MATCH=etag,
        HTTP_IF_UNMODIFIED_SINCE=last_modified,
        format="json",
    )
    # Should be allowed since the user is authorized to put in the rbac_context for the
    # resource state current in the server and for the target context
    Then.http.status_code_is(200)
