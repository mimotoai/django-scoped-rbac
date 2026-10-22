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
    UUID_PK,
    UuidPkViewSet,
    assert_permission_denied,
    call_view,
    client_for,
    derived,
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
    ExampleUuidPkModel,
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


@pytest.fixture
def post_save_renames_objects():
    def handler(sender, instance, **kwargs):
        if instance.name == "rename":
            sender.objects.filter(pk=instance.pk).update(name="renamed")

    post_save.connect(handler, sender=ExampleDerivedContextModel, weak=False)
    yield
    post_save.disconnect(handler, sender=ExampleDerivedContextModel)


@pytest.mark.django_db
def test_update_response_shows_the_persisted_object(user, post_save_renames_objects):
    grant(user, {"http.PATCH": [DERIVED]}, "A")
    target = derived(ctx="A")

    response = client_for(user).patch(
        DERIVED_URL.format(target.pk), {"name": "rename"}, format="json"
    )

    assert response.status_code == 200, response.content
    assert response.data["name"] == "renamed"


# A writable primary key must not let an update write another object's row


@pytest.mark.django_db
def test_patch_changing_primary_key_to_another_object_is_rejected(user):
    grant(user, {"http.PATCH": [UUID_PK]}, "A")
    mine = ExampleUuidPkModel.objects.create(name="mine", rbac_context="A")
    victim = ExampleUuidPkModel.objects.create(name="victim", rbac_context="B")

    response = call_view(
        UuidPkViewSet, user, "patch", {"id": str(victim.pk), "name": "x"}, pk=mine.pk
    )

    assert response.status_code == 400, response.content
    assert [error.code for error in response.data] == ["primary_key_changed"]
    victim.refresh_from_db()
    mine.refresh_from_db()
    assert (victim.name, victim.rbac_context) == ("victim", "B")
    assert (mine.name, mine.rbac_context) == ("mine", "A")


@pytest.mark.django_db
def test_patch_changing_primary_key_to_a_new_value_is_rejected(user):
    grant(user, {"http.PATCH": [UUID_PK]}, "A")
    mine = ExampleUuidPkModel.objects.create(name="mine", rbac_context="A")

    response = call_view(
        UuidPkViewSet,
        user,
        "patch",
        {"id": "00000000-0000-0000-0000-000000000001", "name": "x"},
        pk=mine.pk,
    )

    assert response.status_code == 400, response.content
    assert list(ExampleUuidPkModel.objects.values_list("pk", "name")) == [
        (mine.pk, "mine")
    ]


@pytest.mark.django_db
def test_patch_repeating_the_same_primary_key_is_allowed(user):
    grant(user, {"http.PATCH": [UUID_PK]}, "A")
    mine = ExampleUuidPkModel.objects.create(name="mine", rbac_context="A")

    response = call_view(
        UuidPkViewSet, user, "patch", {"id": str(mine.pk), "name": "x"}, pk=mine.pk
    )

    assert response.status_code == 200, response.content
    mine.refresh_from_db()
    assert mine.name == "x"


# Objects with no contexts: denied, except for superusers


@pytest.mark.django_db
def test_superuser_get_and_patch_on_object_with_no_contexts_are_allowed(superuser):
    target = tagged()
    tag_a = ExampleContextTag.objects.create(ctx="A")
    client = client_for(superuser.instance)

    got = client.get(TAGGED_URL.format(target.pk))
    patched = client.patch(
        TAGGED_URL.format(target.pk), {"tags": [tag_a.pk]}, format="json"
    )

    assert got.status_code == 200, got.content
    assert patched.status_code == 200, patched.content
    assert target.rbac_contexts == ["A"]


@pytest.mark.django_db
def test_grant_in_default_context_does_not_cover_object_with_no_contexts(user):
    grant(user, {"http.PATCH": [TAGGED]}, "")
    target = tagged()

    response = client_for(user).patch(
        TAGGED_URL.format(target.pk), {"tags": []}, format="json"
    )

    assert_permission_denied(response)
