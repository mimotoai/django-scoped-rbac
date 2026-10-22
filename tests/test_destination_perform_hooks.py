"""The perform_create/perform_update contract for subclasses, and post-save checks
that read the object through the view's queryset."""

import pytest
from django.db.models import F, Value
from django.db.models.functions import Coalesce, JSONArray

from scoped_rbac.permissions import IsAuthorized
from scoped_rbac.rbac_contexts import SOME_CONTEXT

from .helpers import (
    EXAMPLE,
    NamedModelViewSet,
    assert_permission_denied,
    assert_reserved_context_rejected,
    call_view,
    grant,
    with_permissions,
)
from .models import ExampleAccessControlledModel
from .serializers import ExampleNamedModelSerializer

# Save kwargs: serializer.save(owner=request.user)-style overrides


class SaveKwargsViewSet(NamedModelViewSet):
    """Overrides perform_* the usual way, passing extra kwargs to serializer.save()."""

    extra_save_kwargs = {}

    def perform_create(self, serializer):
        super().perform_create(serializer, **self.extra_save_kwargs)

    def perform_update(self, serializer):
        super().perform_update(serializer, **self.extra_save_kwargs)


def call_with_save_kwargs(user, method, data, save_kwargs, pk=None):
    viewset = type("ViewSet", (SaveKwargsViewSet,), {"extra_save_kwargs": save_kwargs})
    return call_view(viewset, user, method, data, pk=pk)


@pytest.mark.django_db
def test_create_save_kwargs_are_saved(user):
    grant(user, {"http.POST": [EXAMPLE]}, "A")

    response = call_with_save_kwargs(
        user, "post", {"name": "x", "rbac_context": "A"}, {"name": "from-kwargs"}
    )

    assert response.status_code == 201, response.content
    assert ExampleAccessControlledModel.objects.get().name == "from-kwargs"


@pytest.mark.django_db
def test_create_save_kwargs_into_reserved_context_are_rejected(user):
    grant(user, {"http.POST": [EXAMPLE]}, "A")

    response = call_with_save_kwargs(
        user,
        "post",
        {"name": "x", "rbac_context": "A"},
        {"rbac_context": SOME_CONTEXT},
    )

    assert_reserved_context_rejected(response)
    assert not ExampleAccessControlledModel.objects.exists()


@pytest.mark.django_db
def test_update_save_kwargs_into_unauthorized_context_are_forbidden(user):
    grant(user, {"http.PATCH": [EXAMPLE]}, "A")
    target = ExampleAccessControlledModel.objects.create(name="x", rbac_context="A")

    response = call_with_save_kwargs(
        user, "patch", {"name": "y"}, {"rbac_context": "Z"}, pk=target.pk
    )

    assert_permission_denied(response)
    target.refresh_from_db()
    assert (target.name, target.rbac_context) == ("x", "A")


# A serializer whose create() returns an unsaved instance: nothing to check


class UnsavedCreateSerializer(ExampleNamedModelSerializer):
    def create(self, validated_data):
        return ExampleAccessControlledModel(**validated_data)


class UnsavedCreateViewSet(NamedModelViewSet):
    serializer_class = UnsavedCreateSerializer


@pytest.mark.django_db
def test_create_returning_an_unsaved_instance_succeeds(user):
    grant(user, {"http.POST": [EXAMPLE]}, "A")

    response = call_view(
        UnsavedCreateViewSet, user, "post", {"name": "x", "rbac_context": "A"}
    )

    assert response.status_code == 201, response.content
    assert not ExampleAccessControlledModel.objects.exists()


# contexts_for reading an annotation from the view's get_queryset()


class ParentContextIsAuthorized(IsAuthorized):
    """An object's context is its parent's, annotated by the view's queryset."""

    def contexts_for(self, obj):
        return [obj.parent_ctx]


class ParentContextSerializer(ExampleNamedModelSerializer):
    class Meta(ExampleNamedModelSerializer.Meta):
        fields = ("id", "name", "rbac_context", "parent_context")


class AnnotatedViewSet(NamedModelViewSet):
    serializer_class = ParentContextSerializer
    permission_classes = [ParentContextIsAuthorized]

    def get_queryset(self):
        return ExampleAccessControlledModel.objects.annotate(
            parent_ctx=Coalesce(F("parent_context__rbac_context"), Value(""))
        )


def parent(ctx):
    return ExampleAccessControlledModel.objects.create(
        name=f"in-{ctx}", rbac_context=ctx
    )


@pytest.mark.django_db
def test_patch_checked_with_queryset_annotation_is_allowed(user):
    grant(user, {"http.PATCH": [EXAMPLE]}, "P")
    target = ExampleAccessControlledModel.objects.create(
        name="child", parent_context=parent("P")
    )

    response = call_view(AnnotatedViewSet, user, "patch", {"name": "x"}, pk=target.pk)

    assert response.status_code == 200, response.content
    target.refresh_from_db()
    assert target.name == "x"


@pytest.mark.django_db
def test_patch_checked_with_queryset_annotation_is_denied(user):
    grant(user, {"http.PATCH": [EXAMPLE]}, "P")
    target = ExampleAccessControlledModel.objects.create(
        name="child", parent_context=parent("P")
    )
    ungranted = parent("Q")

    response = call_view(
        AnnotatedViewSet, user, "patch", {"parent_context": ungranted.pk}, pk=target.pk
    )

    assert_permission_denied(response)
    target.refresh_from_db()
    assert target.parent_context.rbac_context == "P"


@pytest.mark.django_db
def test_post_checked_with_queryset_annotation_is_allowed(user):
    grant(user, {"http.POST": [EXAMPLE]}, "")

    response = call_view(
        AnnotatedViewSet,
        user,
        "post",
        {"name": "child", "parent_context": parent("P").pk},
    )

    assert response.status_code == 201, response.content
    assert ExampleAccessControlledModel.objects.filter(name="child").exists()


# An update can take the object out of the view's queryset


class UnarchivedViewSet(NamedModelViewSet):
    def get_queryset(self):
        return ExampleAccessControlledModel.objects.exclude(name="archived")


@pytest.mark.django_db
def test_update_moving_object_out_of_the_queryset_is_allowed(user):
    grant(user, {"http.PATCH": [EXAMPLE]}, "A")
    target = ExampleAccessControlledModel.objects.create(name="x", rbac_context="A")

    response = call_view(
        UnarchivedViewSet, user, "patch", {"name": "archived"}, pk=target.pk
    )

    assert response.status_code == 200, response.content
    target.refresh_from_db()
    assert target.name == "archived"


@pytest.mark.django_db
def test_update_moving_object_out_of_the_queryset_is_still_checked(user):
    # Allowed before the save (A); only the post-save re-read, which must fall
    # back to the base manager, sees the move to Z.
    grant(user, {"http.PATCH": [EXAMPLE]}, "A")
    target = ExampleAccessControlledModel.objects.create(name="x", rbac_context="A")

    response = call_view(
        UnarchivedViewSet,
        user,
        "patch",
        {"name": "archived", "rbac_context": "Z"},
        pk=target.pk,
    )

    assert_permission_denied(response)
    target.refresh_from_db()
    assert (target.name, target.rbac_context) == ("x", "A")


# The rbac_context column is checked whenever it moves, whatever contexts_for
# reports: RbacFilter lists objects by the column.


class NameIsAuthorized(IsAuthorized):
    """An object's context is its name."""

    def contexts_for(self, obj):
        return [obj.name]


class RbacContextsAnnotatedViewSet(NamedModelViewSet):
    """`rbac_contexts` comes from a queryset annotation, not the model class."""

    def get_queryset(self):
        return ExampleAccessControlledModel.objects.annotate(
            rbac_contexts=JSONArray("name")
        )


COLUMN_VIEWS = {
    "parent-annotation": AnnotatedViewSet,
    "contexts-for-name": with_permissions(NamedModelViewSet, NameIsAuthorized),
    "rbac-contexts-annotation": RbacContextsAnnotatedViewSet,
}


def column_target():
    """In A by every view's notion: name, parent and column."""
    return ExampleAccessControlledModel.objects.create(
        name="A", rbac_context="A", parent_context=parent("A")
    )


@pytest.mark.parametrize("viewset", COLUMN_VIEWS.values(), ids=COLUMN_VIEWS.keys())
@pytest.mark.django_db
def test_moving_rbac_context_column_is_checked_with_any_contexts_source(user, viewset):
    grant(user, {"http.PATCH": [EXAMPLE]}, "A")
    target = column_target()

    response = call_view(viewset, user, "patch", {"rbac_context": "Z"}, pk=target.pk)

    assert_permission_denied(response)
    target.refresh_from_db()
    assert target.rbac_context == "A"


@pytest.mark.parametrize("viewset", COLUMN_VIEWS.values(), ids=COLUMN_VIEWS.keys())
@pytest.mark.django_db
def test_moving_rbac_context_column_to_granted_context_is_allowed_with_any_source(
    user, viewset
):
    grant(user, {"http.PATCH": [EXAMPLE]}, "A", "Z")
    target = column_target()

    response = call_view(viewset, user, "patch", {"rbac_context": "Z"}, pk=target.pk)

    assert response.status_code == 200, response.content
    target.refresh_from_db()
    assert target.rbac_context == "Z"


@pytest.mark.django_db
def test_annotated_rbac_contexts_into_reserved_context_are_rejected(user):
    grant(user, {"http.PATCH": [EXAMPLE]}, "A")
    target = column_target()

    response = call_view(
        RbacContextsAnnotatedViewSet,
        user,
        "patch",
        {"name": SOME_CONTEXT},
        pk=target.pk,
    )

    assert_reserved_context_rejected(response)
    target.refresh_from_db()
    assert target.name == "A"


@pytest.mark.django_db
def test_annotated_rbac_contexts_into_granted_context_are_allowed(user):
    grant(user, {"http.PATCH": [EXAMPLE]}, "A", "B")
    target = column_target()

    response = call_view(
        RbacContextsAnnotatedViewSet, user, "patch", {"name": "B"}, pk=target.pk
    )

    assert response.status_code == 200, response.content
    target.refresh_from_db()
    assert target.name == "B"


# Bulk create (many=True): every created object is checked


class BulkSerializer(ExampleNamedModelSerializer):
    @classmethod
    def contexts_from(cls, content):
        items = content if isinstance(content, list) else [content]
        return [item.get("rbac_context", "") for item in items]


class BulkCreateViewSet(NamedModelViewSet):
    serializer_class = BulkSerializer

    def get_serializer(self, *args, **kwargs):
        if isinstance(kwargs.get("data"), list):
            kwargs["many"] = True
        return super().get_serializer(*args, **kwargs)


@pytest.mark.django_db
def test_bulk_create_into_reserved_context_is_rejected(user):
    grant(user, {"http.POST": [EXAMPLE]}, "A")

    response = call_view(
        BulkCreateViewSet,
        user,
        "post",
        [
            {"name": "ok", "rbac_context": "A"},
            {"name": "x", "rbac_context": SOME_CONTEXT},
        ],
    )

    assert_reserved_context_rejected(response)
    assert not ExampleAccessControlledModel.objects.exists()


@pytest.mark.django_db
def test_bulk_create_into_granted_context_is_allowed(user):
    grant(user, {"http.POST": [EXAMPLE]}, "A")

    response = call_view(
        BulkCreateViewSet,
        user,
        "post",
        [{"name": "x", "rbac_context": "A"}, {"name": "y", "rbac_context": "A"}],
    )

    assert response.status_code == 201, response.content
    assert ExampleAccessControlledModel.objects.filter(rbac_context="A").count() == 2
