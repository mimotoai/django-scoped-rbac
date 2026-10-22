"""Writes into the reserved context namespace are rejected with 400."""

import pytest

from scoped_rbac.models import RoleAssignment
from scoped_rbac.permissions import IsAuthorized
from scoped_rbac.rbac_contexts import SOME_CONTEXT
from scoped_rbac.rest import RoleAssignmentViewSet

from .helpers import (
    RA,
    RA_LIST_URL,
    RA_URL,
    TAGGED,
    TAGGED_URL,
    assert_reserved_context_rejected,
    call_view,
    client_for,
    grant,
    make_role,
    role_link,
    tagged,
    user_link,
)
from .models import (
    ExampleContextTag,
)


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
