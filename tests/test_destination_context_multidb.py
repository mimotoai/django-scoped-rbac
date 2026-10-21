"""Update authorization under database routers (GitLab issue #1).

The post-save checks must read the database that was written to, inside a transaction
on that database. "replica" is a separate database holding a copy of the data, so it
never sees the request's writes, like a replica that cannot see uncommitted writes on
the primary.
"""

import pytest
from django.core.exceptions import ImproperlyConfigured
from django.db import router
from django.test import override_settings
from django.utils.timezone import now
from rest_framework.test import APIRequestFactory, force_authenticate

from scoped_rbac.models import Role, RoleAssignment

from .models import (
    ExampleAccessControlledModel,
    ExampleContextTag,
    ExampleDerivedContextModel,
    ExampleFolder,
    ExampleTaggedContextsModel,
)
from .rest import ExampleAccessControlledModelViewSet
from .serializers import ExampleAccessControlledModelSerializer
from .test_destination_context import (
    DERIVED,
    DERIVED_URL,
    EXAMPLE,
    EXAMPLE_URL,
    RA,
    RA_LIST_URL,
    RA_URL,
    TAGGED,
    TAGGED_URL,
    assert_permission_denied,
    client_for,
    grant,
    role_link,
    user_link,
)

BOTH = ("default", "replica")


class ReadReplicaRouter:
    """Primary/replica: every read goes to the replica, every write to the primary."""

    def db_for_read(self, model, **hints):
        return "replica"

    def db_for_write(self, model, **hints):
        return "default"

    def allow_relation(self, obj1, obj2, **hints):
        return True


class OtherDatabaseRouter:
    """Routes the derived-context models (reads and writes) to "other"."""

    routed = (ExampleDerivedContextModel, ExampleFolder)

    def db_for_read(self, model, **hints):
        return "other" if model in self.routed else None

    db_for_write = db_for_read


def routers(*installed):
    """Install `installed` for the test only; check Django resets the routers."""
    with override_settings(DATABASE_ROUTERS=list(installed)):
        assert router.routers == list(installed)
        yield
    assert router.routers == []


@pytest.fixture
def read_replica():
    yield from routers(ReadReplicaRouter())


@pytest.fixture
def other_database():
    yield from routers(OtherDatabaseRouter())


@pytest.fixture
def user(django_user_model):
    return django_user_model.objects.create(username="context-a-admin")


def make_user(django_user_model, alias, **fields):
    return django_user_model.objects.db_manager(alias).create(pk=1, **fields)


def on_primary_and_replica(setup):
    for alias in BOTH:
        setup(alias)


@pytest.mark.django_db(databases=list(BOTH))
def test_replica_router_patch_moving_own_assignment_is_forbidden(
    django_user_model, read_replica
):
    def setup(alias):
        user = make_user(django_user_model, alias, username="u")
        patcher = Role.objects.using(alias).create(
            pk=1, definition={"http.PATCH": [RA], "http.GET": [RA]}, modified_at=now()
        )
        Role.objects.using(alias).create(pk=2, definition=True, modified_at=now())
        RoleAssignment.objects.using(alias).create(
            pk=1, user=user, role=patcher, rbac_context="A", modified_at=now()
        )

    on_primary_and_replica(setup)
    powerful_role = Role.objects.using("default").get(pk=2)
    user = django_user_model.objects.using("default").get(pk=1)

    response = client_for(user).patch(
        RA_URL.format(1),
        {"rbac_context": "V", "role": role_link(powerful_role)},
        format="json",
    )

    assert_permission_denied(response)
    on_primary = RoleAssignment.objects.using("default").get(pk=1)
    assert (on_primary.rbac_context, on_primary.role_id) == ("A", 1)


@pytest.mark.django_db(databases=list(BOTH))
def test_replica_router_patch_replacing_m2m_contexts_is_forbidden(
    django_user_model, read_replica
):
    def setup(alias):
        user = make_user(django_user_model, alias, username="u")
        role = Role.objects.using(alias).create(
            pk=1, definition={"http.PATCH": [TAGGED]}, modified_at=now()
        )
        RoleAssignment.objects.using(alias).create(
            pk=1, user=user, role=role, rbac_context="A", modified_at=now()
        )
        tag_a = ExampleContextTag.objects.using(alias).create(pk=1, ctx="A")
        ExampleContextTag.objects.using(alias).create(pk=2, ctx="V")
        tagged = ExampleTaggedContextsModel.objects.using(alias).create(pk=1)
        # Not tags.set(): the installed router would send these writes to "default".
        ExampleTaggedContextsModel.tags.through.objects.using(alias).create(
            exampletaggedcontextsmodel=tagged, examplecontexttag=tag_a
        )

    on_primary_and_replica(setup)
    user = django_user_model.objects.using("default").get(pk=1)

    response = client_for(user).patch(
        TAGGED_URL.format(1), {"tags": [2]}, format="json"
    )

    assert_permission_denied(response)
    on_primary = ExampleTaggedContextsModel.objects.using("default").get(pk=1)
    assert on_primary.rbac_contexts == ["A"]


@pytest.mark.django_db(databases=list(BOTH))
def test_replica_router_create_succeeds(django_user_model, read_replica):
    def setup(alias):
        django_user_model.objects.db_manager(alias).create_superuser(
            "su", "su@x.test", "pw", pk=1
        )
        Role.objects.using(alias).create(pk=1, definition={}, modified_at=now())

    on_primary_and_replica(setup)
    superuser = django_user_model.objects.using("default").get(pk=1)
    role = Role.objects.using("default").get(pk=1)

    response = client_for(superuser).post(
        RA_LIST_URL,
        {"user": user_link(superuser), "role": role_link(role), "rbac_context": "A"},
        format="json",
    )

    assert response.status_code == 201, response.content
    assert response.data["rbac_context"] == "A"
    assert RoleAssignment.objects.using("default").filter(rbac_context="A").exists()


@pytest.mark.django_db(databases=["default", "other"])
def test_denied_update_on_another_database_is_rolled_back(user, other_database):
    grant(user, {"http.PATCH": [DERIVED]}, "A")
    folder_a = ExampleFolder.objects.create(ctx="A")
    folder_v = ExampleFolder.objects.create(ctx="V")
    target = ExampleDerivedContextModel.objects.create(name="doc", folder=folder_a)
    assert target._state.db == "other"

    response = client_for(user).patch(
        DERIVED_URL.format(target.pk), {"folder": folder_v.pk}, format="json"
    )

    assert_permission_denied(response)
    target.refresh_from_db()
    assert (target.folder_id, target.rbac_context) == (folder_a.pk, "A")


@pytest.mark.django_db(databases=["default", "other"])
def test_allowed_update_on_another_database_is_saved(user, other_database):
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


class SavesElsewhereSerializer(ExampleAccessControlledModelSerializer):
    def update(self, instance, validated_data):
        instance.name = validated_data["name"]
        instance.save(using="other")
        return instance


class SavesElsewhereViewSet(ExampleAccessControlledModelViewSet):
    serializer_class = SavesElsewhereSerializer


@pytest.mark.django_db(databases=["default", "other"])
def test_update_saved_outside_the_write_database_fails_closed(user):
    grant(user, {"http.PATCH": [EXAMPLE]}, "A")
    target = ExampleAccessControlledModel.objects.create(name="x", rbac_context="A")
    view = SavesElsewhereViewSet.as_view({"patch": "partial_update"})
    request = APIRequestFactory().patch(
        EXAMPLE_URL.format(target.pk), {"name": "y"}, format="json"
    )
    force_authenticate(request, user=user)

    with pytest.raises(ImproperlyConfigured, match="'other'"):
        view(request, pk=str(target.pk))
