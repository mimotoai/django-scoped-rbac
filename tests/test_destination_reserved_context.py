"""Writes into the reserved context namespace are rejected with 400."""

import uuid

import pytest
from django.db.models.signals import post_save
from rest_framework.permissions import AllowAny

from scoped_rbac import rest
from scoped_rbac.models import RoleAssignment
from scoped_rbac.permissions import IsAuthorized
from scoped_rbac.rbac_contexts import SOME_CONTEXT
from scoped_rbac.rest import RoleAssignmentViewSet, UserViewSet

from .helpers import (
    BOTH_CONTEXTS,
    DERIVED_LIST_URL,
    RA,
    RA_LIST_URL,
    RA_URL,
    TAGGED,
    TAGGED_URL,
    BothContextsViewSet,
    assert_reserved_context_rejected,
    call_view,
    client_for,
    derived,
    grant,
    make_role,
    role_link,
    tagged,
    user_link,
    with_permissions,
)
from .models import (
    ExampleBothContextsModel,
    ExampleContextTag,
    ExampleDerivedContextModel,
    ExampleFolder,
)
from .rest import ExampleDerivedContextModelViewSet


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


@pytest.mark.parametrize(
    "variant",
    [
        "__some_context__",
        "__\uff33OME_CONTEXT__",  # fullwidth S, NFKC-equivalent
        " __SOME_CONTEXT__ ",
        "__SOME_CONTEXT__\n",
    ],
)
@pytest.mark.django_db
def test_patch_into_reserved_context_variant_is_rejected(
    user, ra_patcher_in_a, variant
):
    # A grant in the variant context, so only the reserved-context check can refuse.
    grant(user, {"http.PATCH": [RA]}, variant)

    response = client_for(user).patch(
        RA_URL.format(ra_patcher_in_a.pk), {"rbac_context": variant}, format="json"
    )

    assert_reserved_context_rejected(response)
    ra_patcher_in_a.refresh_from_db()
    assert ra_patcher_in_a.rbac_context == "A"


class RoleContextIsAuthorized(IsAuthorized):
    """Treats a RoleAssignment as living in its role's context."""

    def contexts_for(self, obj):
        if isinstance(obj, RoleAssignment):
            return [obj.role.rbac_context]
        return super().contexts_for(obj)


class RoleContextRoleAssignmentViewSet(RoleAssignmentViewSet):
    permission_classes = [RoleContextIsAuthorized]


@pytest.mark.django_db
def test_reserved_context_check_uses_permission_contexts_for(user, ra_patcher_in_a):
    reserved_role = make_role({}, SOME_CONTEXT)
    response = call_view(
        RoleContextRoleAssignmentViewSet,
        user,
        "patch",
        {"role": role_link(reserved_role)},
        pk=ra_patcher_in_a.pk,
    )

    assert_reserved_context_rejected(response)
    ra_patcher_in_a.refresh_from_db()
    assert ra_patcher_in_a.role_id != reserved_role.pk


# Every context starting with "__" (after NFKC, removing format characters and
# stripping) is reserved. These values reach the database through an m2m tag's
# `ctx`, which DRF does not trim, so trimming cannot make a test pass.

RESERVED_VARIANTS = {
    "precomposed": "__\u015cOME_CONTEXT__",  # S with circumflex
    "combining": "__S\u0301OME_CONTEXT__",  # S + combining acute
    "zwsp-leading": "\u200b__SOME_CONTEXT__",
    "zwsp-inserted": "_\u200b_SOME_CONTEXT__",
    "soft-hyphen": "_\u00ad_SOME_CONTEXT__",
    "fullwidth-underscores": "\uff3f\uff3fSOME_CONTEXT__",
    "any-suffix": "__anything",
    "padded": " __SOME_CONTEXT__ ",
    "newline": "__SOME_CONTEXT__\n",
}
ALLOWED_LOOKALIKES = {"interior": "a__b", "single": "_x", "trailing": "x__"}


@pytest.mark.parametrize(
    "variant", RESERVED_VARIANTS.values(), ids=RESERVED_VARIANTS.keys()
)
@pytest.mark.django_db
def test_m2m_context_with_reserved_prefix_is_rejected(user, variant):
    grant(user, {"http.PATCH": [TAGGED]}, "A")
    target = tagged("A")
    tag_a = target.tags.get()
    reserved = ExampleContextTag.objects.create(ctx=variant)

    response = client_for(user).patch(
        TAGGED_URL.format(target.pk), {"tags": [tag_a.pk, reserved.pk]}, format="json"
    )

    assert_reserved_context_rejected(response)
    assert target.rbac_contexts == ["A"]


@pytest.mark.parametrize(
    "value", ALLOWED_LOOKALIKES.values(), ids=ALLOWED_LOOKALIKES.keys()
)
@pytest.mark.django_db
def test_m2m_context_with_interior_underscores_is_allowed(user, value):
    grant(user, {"http.PATCH": [TAGGED]}, "A")
    target = tagged("A")
    tag_a = target.tags.get()
    other = ExampleContextTag.objects.create(ctx=value)

    response = client_for(user).patch(
        TAGGED_URL.format(target.pk), {"tags": [tag_a.pk, other.pk]}, format="json"
    )

    assert response.status_code == 200, response.content
    assert sorted(target.rbac_contexts) == sorted(["A", value])


@pytest.mark.parametrize(
    "value, reserved",
    [
        *((v, True) for v in RESERVED_VARIANTS.values()),
        (SOME_CONTEXT, True),
        *((v, False) for v in ALLOWED_LOOKALIKES.values()),
        ("A", False),
        ("", False),
        (None, False),
        (uuid.UUID(int=0), False),
        (42, False),
    ],
)
def test_reserved_context_predicate(value, reserved):
    assert rest._is_reserved_context(value) is reserved


# A model with an rbac_context column and rbac_contexts that omit it


@pytest.mark.django_db
def test_patch_rbac_context_column_into_reserved_context_is_rejected(user):
    grant(user, {"http.PATCH": [BOTH_CONTEXTS]}, "A")
    target = ExampleBothContextsModel.objects.create(ctx_a="A", rbac_context="A")

    response = call_view(
        BothContextsViewSet, user, "patch", {"rbac_context": SOME_CONTEXT}, pk=target.pk
    )

    assert_reserved_context_rejected(response)
    target.refresh_from_db()
    assert target.rbac_context == "A"


@pytest.mark.django_db
def test_post_rbac_context_column_into_reserved_context_is_rejected(user):
    grant(user, {"http.POST": [BOTH_CONTEXTS]}, "A")

    response = call_view(
        BothContextsViewSet,
        user,
        "post",
        {"ctx_a": "A", "rbac_context": SOME_CONTEXT},
    )

    assert_reserved_context_rejected(response)
    assert not ExampleBothContextsModel.objects.exists()


# Models without rbac_context(s)


@pytest.mark.django_db
def test_create_of_model_without_rbac_context_succeeds(superuser):
    response = call_view(
        UserViewSet,
        superuser.instance,
        "post",
        {"username": "new-user", "email": "new@example.com"},
    )

    assert response.status_code == 201, response.content


# The model-level check runs without any RBAC permission class


@pytest.mark.django_db
def test_reserved_context_is_rejected_without_rbac_permissions(user):
    target = derived(ctx="A")
    reserved_folder = ExampleFolder.objects.create(ctx=SOME_CONTEXT)
    viewset = with_permissions(ExampleDerivedContextModelViewSet, AllowAny)

    response = call_view(
        viewset, user, "patch", {"folder": reserved_folder.pk}, pk=target.pk
    )

    assert_reserved_context_rejected(response)
    target.refresh_from_db()
    assert target.rbac_context == "A"


@pytest.fixture
def post_save_moves_new_escaping_objects_to_some_context():
    def handler(sender, instance, created, **kwargs):
        if created and instance.name == "escape":
            sender.objects.filter(pk=instance.pk).update(rbac_context=SOME_CONTEXT)

    post_save.connect(handler, sender=ExampleDerivedContextModel, weak=False)
    yield
    post_save.disconnect(handler, sender=ExampleDerivedContextModel)


@pytest.mark.django_db
def test_create_whose_signal_persists_reserved_context_is_rejected(
    superuser, post_save_moves_new_escaping_objects_to_some_context
):
    folder = ExampleFolder.objects.create(ctx="A")

    response = client_for(superuser.instance).post(
        DERIVED_LIST_URL, {"name": "escape", "folder": folder.pk}, format="json"
    )

    assert_reserved_context_rejected(response)
    assert not ExampleDerivedContextModel.objects.exists()
