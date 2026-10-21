"""Updates must be authorized against the object as it is saved, not only as it was
before the update (GitLab issue #1).
"""

import pytest
from django.db.models.signals import post_save
from django.utils.http import http_date, quote_etag
from django.utils.timezone import now
from rest_framework.permissions import IsAuthenticated
from rest_framework.test import APIClient, APIRequestFactory, force_authenticate
from scrudful import __version__ as scrudful_version

from scoped_rbac.models import Role, RoleAssignment
from scoped_rbac.permissions import IsAuthorized
from scoped_rbac.rbac_contexts import SOME_CONTEXT
from scoped_rbac.rest import RoleAssignmentViewSet

from .models import (
    ExampleContextTag,
    ExampleDerivedContextModel,
    ExampleFolder,
    ExampleTaggedContextsModel,
    ExampleWithMultipleContexts,
)

RA = "rbac.RoleAssignment"
ROLE = "rbac.Role"
DERIVED = ExampleDerivedContextModel.resource_type.iri
TAGGED = ExampleTaggedContextsModel.resource_type.iri
MULTI = ExampleWithMultipleContexts.resource_type.iri
RA_URL = "/api/scoped-rbac/role-assignments/{}/"
RA_LIST_URL = "/api/scoped-rbac/role-assignments/"
ROLE_URL = "/api/scoped-rbac/roles/{}/"
DERIVED_URL = "/api/example-derived-context-models/{}/"
TAGGED_URL = "/api/example-tagged-contexts-models/{}/"
MULTI_URL = "/api/example-with-multiple-contexts/{}/"
PERMISSION_DENIED = "You do not have permission to perform this action."


def make_role(definition, rbac_context=""):
    return Role.objects.create(
        definition=definition, rbac_context=rbac_context, modified_at=now(), etag="r"
    )


def assign(user, role, rbac_context):
    return RoleAssignment.objects.create(
        user=user, role=role, rbac_context=rbac_context, modified_at=now(), etag="a"
    )


def grant(user, definition, *contexts):
    role = make_role(definition)
    for rbac_context in contexts:
        assign(user, role, rbac_context)
    return role


def role_link(role):
    return f"http://testserver{ROLE_URL.format(role.pk)}"


def user_link(user):
    return f"http://testserver/api/users/{user.pk}/"


def client_for(user):
    client = APIClient()
    client.force_authenticate(user)
    return client


def scrudful_preconditions(role):
    return {
        "HTTP_IF_MATCH": quote_etag(role.etag + scrudful_version),
        "HTTP_IF_UNMODIFIED_SINCE": http_date(role.modified_at.timestamp()),
    }


def assert_permission_denied(response):
    assert response.status_code == 403, response.content
    assert response.data["detail"] == PERMISSION_DENIED
    assert response.data["detail"].code == "permission_denied"


def assert_reserved_context_rejected(response):
    assert response.status_code == 400, response.content
    assert SOME_CONTEXT in str(response.data)
    assert "reserved" in str(response.data)


@pytest.fixture
def user(django_user_model):
    return django_user_model.objects.create(username="context-a-admin")


@pytest.fixture
def ra_patcher_in_a(user):
    """`user` may PATCH and GET RoleAssignments in context A only; returns the
    user's own RoleAssignment (in A)."""
    role = make_role({"http.PATCH": [RA], "http.GET": [RA]}, "A")
    return assign(user, role, "A")


# RoleAssignment: the original exploit and its allowed counterparts


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


# Bypass: DRF's composed permissions (AND/OR/NOT) only proxy the standard hooks


class ComposedPermissionRoleAssignmentViewSet(RoleAssignmentViewSet):
    permission_classes = [IsAuthenticated & IsAuthorized]


@pytest.mark.django_db
def test_patch_through_composed_permission_classes_checks_saved_context(
    user, ra_patcher_in_a
):
    view = ComposedPermissionRoleAssignmentViewSet.as_view({"patch": "partial_update"})
    request = APIRequestFactory().patch(
        RA_URL.format(ra_patcher_in_a.pk), {"rbac_context": "V"}, format="json"
    )
    force_authenticate(request, user=user)

    response = view(request, pk=str(ra_patcher_in_a.pk)).render()

    assert_permission_denied(response)
    ra_patcher_in_a.refresh_from_db()
    assert ra_patcher_in_a.rbac_context == "A"


# Bypass: the reserved SOME_CONTEXT, in which every grant is also registered


@pytest.mark.django_db
def test_patch_into_reserved_some_context_is_rejected(user, ra_patcher_in_a):
    powerful_role = make_role(True)
    original_role_id = ra_patcher_in_a.role_id

    response = client_for(user).patch(
        RA_URL.format(ra_patcher_in_a.pk),
        {"rbac_context": SOME_CONTEXT, "role": role_link(powerful_role)},
        format="json",
    )

    assert_reserved_context_rejected(response)
    ra_patcher_in_a.refresh_from_db()
    assert ra_patcher_in_a.rbac_context == "A"
    assert ra_patcher_in_a.role_id == original_role_id


@pytest.mark.django_db
def test_post_into_reserved_some_context_is_rejected(user):
    grant(user, {"http.POST": [RA]}, "A")
    powerful_role = make_role(True)
    count_before = RoleAssignment.objects.count()

    response = client_for(user).post(
        RA_LIST_URL,
        {
            "user": user_link(user),
            "role": role_link(powerful_role),
            "rbac_context": SOME_CONTEXT,
        },
        format="json",
    )

    assert_reserved_context_rejected(response)
    assert RoleAssignment.objects.count() == count_before
    assert not RoleAssignment.objects.filter(rbac_context=SOME_CONTEXT).exists()


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


# Bypass: a context derived by the model's save() is invisible before saving


@pytest.mark.django_db
def test_patch_whose_save_derives_unauthorized_context_is_forbidden(user):
    grant(user, {"http.PATCH": [DERIVED]}, "A")
    folder_a = ExampleFolder.objects.create(ctx="A")
    folder_v = ExampleFolder.objects.create(ctx="V")
    target = ExampleDerivedContextModel.objects.create(name="doc", folder=folder_a)

    response = client_for(user).patch(
        DERIVED_URL.format(target.pk), {"folder": folder_v.pk}, format="json"
    )

    assert_permission_denied(response)
    target.refresh_from_db()
    assert (target.folder_id, target.rbac_context) == (folder_a.pk, "A")


@pytest.mark.django_db
def test_patch_whose_save_derives_granted_context_is_allowed(user):
    grant(user, {"http.PATCH": [DERIVED]}, "A", "V")
    folder_a = ExampleFolder.objects.create(ctx="A")
    folder_v = ExampleFolder.objects.create(ctx="V")
    target = ExampleDerivedContextModel.objects.create(name="doc", folder=folder_a)

    response = client_for(user).patch(
        DERIVED_URL.format(target.pk), {"folder": folder_v.pk}, format="json"
    )

    assert response.status_code == 200, response.content
    assert response.data["rbac_context"] == "V"
    target.refresh_from_db()
    assert target.rbac_context == "V"


@pytest.fixture
def post_save_moves_escaping_objects_to_v():
    def handler(sender, instance, **kwargs):
        if instance.name == "escape":
            sender.objects.filter(pk=instance.pk).update(rbac_context="V")

    post_save.connect(handler, sender=ExampleDerivedContextModel, weak=False)
    yield
    post_save.disconnect(handler, sender=ExampleDerivedContextModel)


@pytest.mark.django_db
def test_patch_whose_signal_persists_unauthorized_context_is_forbidden(
    user, post_save_moves_escaping_objects_to_v
):
    grant(user, {"http.PATCH": [DERIVED]}, "A")
    target = ExampleDerivedContextModel.objects.create(
        name="doc", folder=ExampleFolder.objects.create(ctx="A")
    )

    response = client_for(user).patch(
        DERIVED_URL.format(target.pk), {"name": "escape"}, format="json"
    )

    assert_permission_denied(response)
    target.refresh_from_db()
    assert (target.name, target.rbac_context) == ("doc", "A")


# Bypass: contexts derived from a many-to-many relation


def tagged(*contexts):
    obj = ExampleTaggedContextsModel.objects.create()
    obj.tags.set([ExampleContextTag.objects.create(ctx=c) for c in contexts])
    return obj


@pytest.mark.django_db
def test_patch_replacing_m2m_contexts_with_unauthorized_ones_is_forbidden(user):
    grant(user, {"http.PATCH": [TAGGED]}, "A")
    target = tagged("A")
    original_tags = list(target.tags.all())
    tag_v = ExampleContextTag.objects.create(ctx="V")

    response = client_for(user).patch(
        TAGGED_URL.format(target.pk), {"tags": [tag_v.pk]}, format="json"
    )

    assert_permission_denied(response)
    assert list(target.tags.all()) == original_tags


@pytest.mark.django_db
def test_patch_removing_every_m2m_context_is_forbidden(user):
    grant(user, {"http.PATCH": [TAGGED]}, "A")
    target = tagged("A")

    response = client_for(user).patch(
        TAGGED_URL.format(target.pk), {"tags": []}, format="json"
    )

    assert_permission_denied(response)
    assert target.rbac_contexts == ["A"]


@pytest.mark.django_db
def test_patch_adding_m2m_context_while_keeping_a_granted_one_is_allowed(user):
    grant(user, {"http.PATCH": [TAGGED]}, "A")
    target = tagged("A")
    tag_a = target.tags.get()
    tag_v = ExampleContextTag.objects.create(ctx="V")

    response = client_for(user).patch(
        TAGGED_URL.format(target.pk), {"tags": [tag_a.pk, tag_v.pk]}, format="json"
    )

    assert response.status_code == 200, response.content
    assert sorted(response.data["tags"]) == sorted([tag_a.pk, tag_v.pk])
    assert sorted(target.rbac_contexts) == ["A", "V"]


@pytest.mark.django_db
def test_patch_on_object_with_no_contexts_is_denied(user):
    grant(user, {"http.PATCH": [TAGGED]}, "A")
    target = tagged()

    response = client_for(user).patch(
        TAGGED_URL.format(target.pk), {"tags": []}, format="json"
    )

    assert_permission_denied(response)


@pytest.mark.django_db
def test_patch_adding_reserved_m2m_context_is_rejected(user):
    grant(user, {"http.PATCH": [TAGGED]}, "A")
    target = tagged("A")
    tag_a = target.tags.get()
    tag_some = ExampleContextTag.objects.create(ctx=SOME_CONTEXT)

    response = client_for(user).patch(
        TAGGED_URL.format(target.pk), {"tags": [tag_a.pk, tag_some.pk]}, format="json"
    )

    assert_reserved_context_rejected(response)
    assert target.rbac_contexts == ["A"]


# Multiple contexts: permission in any one of the object's contexts suffices


def multi(context_1, context_2):
    return ExampleWithMultipleContexts.objects.create(
        context_1=context_1, context_2=context_2
    )


@pytest.mark.django_db
def test_patch_moving_one_of_two_contexts_to_a_granted_context_is_allowed(user):
    grant(user, {"http.PATCH": [MULTI]}, "A", "B")
    target = multi("A", "X")

    response = client_for(user).patch(
        MULTI_URL.format(target.pk), {"context_1": "B"}, format="json"
    )

    assert response.status_code == 200, response.content
    target.refresh_from_db()
    assert target.rbac_contexts == ["B", "X"]


@pytest.mark.django_db
def test_patch_changing_other_context_while_keeping_granted_one_is_allowed(user):
    grant(user, {"http.PATCH": [MULTI]}, "A")
    target = multi("A", "X")

    response = client_for(user).patch(
        MULTI_URL.format(target.pk), {"context_2": "Y"}, format="json"
    )

    assert response.status_code == 200, response.content
    target.refresh_from_db()
    assert target.rbac_contexts == ["A", "Y"]


@pytest.mark.django_db
def test_patch_moving_every_context_out_of_granted_contexts_is_forbidden(user):
    grant(user, {"http.PATCH": [MULTI]}, "A")
    target = multi("A", "X")

    response = client_for(user).patch(
        MULTI_URL.format(target.pk), {"context_1": "Y"}, format="json"
    )

    assert_permission_denied(response)
    target.refresh_from_db()
    assert target.rbac_contexts == ["A", "X"]


# Role (scrudful viewset)


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
