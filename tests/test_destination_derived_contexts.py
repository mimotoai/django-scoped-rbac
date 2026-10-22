"""Updates are checked against the object as persisted: contexts derived by save(),
signals, many-to-many fields, cached properties and multiple context fields.
"""

import pytest
from django.db.models.signals import post_save

from .helpers import (
    CACHED,
    CACHED_URL,
    DERIVED,
    DERIVED_URL,
    EXAMPLE,
    EXAMPLE_URL,
    MULTI,
    MULTI_URL,
    TAGGED,
    TAGGED_URL,
    assert_permission_denied,
    client_for,
    grant,
    multi,
    tagged,
)
from .models import (
    ExampleAccessControlledModel,
    ExampleCachedContextsModel,
    ExampleContextTag,
    ExampleDerivedContextModel,
    ExampleFolder,
)


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


@pytest.mark.django_db
def test_patch_replacing_cached_property_contexts_is_forbidden(user):
    grant(user, {"http.PATCH": [CACHED]}, "A")
    target = ExampleCachedContextsModel.objects.create()
    tag_a = ExampleContextTag.objects.create(ctx="A")
    target.tags.set([tag_a])
    tag_v = ExampleContextTag.objects.create(ctx="V")

    response = client_for(user).patch(
        CACHED_URL.format(target.pk), {"tags": [tag_v.pk]}, format="json"
    )

    assert_permission_denied(response)
    assert list(target.tags.all()) == [tag_a]


@pytest.mark.django_db
def test_patch_keeping_a_granted_cached_property_context_is_allowed(user):
    grant(user, {"http.PATCH": [CACHED]}, "A")
    target = ExampleCachedContextsModel.objects.create()
    tag_a = ExampleContextTag.objects.create(ctx="A")
    target.tags.set([tag_a])
    tag_v = ExampleContextTag.objects.create(ctx="V")

    response = client_for(user).patch(
        CACHED_URL.format(target.pk), {"tags": [tag_a.pk, tag_v.pk]}, format="json"
    )

    assert response.status_code == 200, response.content
    assert sorted(t.ctx for t in target.tags.all()) == ["A", "V"]


@pytest.mark.django_db
def test_authorized_put_on_example_model_is_saved_and_returns_200(user):
    grant(user, {"http.PUT": [EXAMPLE]}, "A")
    target = ExampleAccessControlledModel.objects.create(name="x", rbac_context="A")

    response = client_for(user).put(
        EXAMPLE_URL.format(target.pk), {"name": "y", "rbac_context": "A"}, format="json"
    )

    assert response.status_code == 200, response.content
    target.refresh_from_db()
    assert target.name == "y"


@pytest.mark.django_db
def test_authorized_delete_on_example_model_returns_204(user):
    grant(user, {"http.DELETE": [EXAMPLE]}, "A")
    target = ExampleAccessControlledModel.objects.create(name="x", rbac_context="A")

    response = client_for(user).delete(EXAMPLE_URL.format(target.pk))

    assert response.status_code == 204, response.content
    assert not ExampleAccessControlledModel.objects.filter(pk=target.pk).exists()
