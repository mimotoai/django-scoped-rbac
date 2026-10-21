import unicodedata

from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.db import router, transaction
from django.shortcuts import get_object_or_404

# from django.urls import reverse
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.reverse import reverse
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet
from scrudful.rest_framework import scrudful_viewset

from .filters import RbacFilter
from .models import Role, RoleAssignment, UserResourceType
from .permissions import contexts_for, policy_for
from .rbac_contexts import SOME_CONTEXT
from .serializers import RoleAssignmentSerializer, RoleSerializer, UserSerializer


def _normalize_context(context):
    return unicodedata.normalize("NFKC", context).casefold().strip()


_RESERVED_CONTEXT = _normalize_context(SOME_CONTEXT)


def is_reserved_context(context):
    """True if `context` is, or is a lookalike of, the reserved `SOME_CONTEXT`."""
    return isinstance(context, str) and _normalize_context(context) == _RESERVED_CONTEXT


class DefaultPageNumberPagination(PageNumberPagination):
    page_size = 100


class AccessControlledAPIView:
    """
    This `APIView` interface is required for non-object based views in combination with
    the `IsAuthorized` permission class.
    """

    filter_backends = [RbacFilter]

    def resource_type_iri_for(self, request):
        """
        Return the resource_type_iri for the resource type indicated by this request.
        """

        if hasattr(self, "action") and self.action == "list":
            return self.list_type_iri
        else:
            return self.resource_type_iri

    @property
    def resource_type_iri(self):
        """
        Subclasses **MUST** override this method.
        Return the resource_type_iri for the base resource supported by this view.
        """

        raise NotImplementedError()

    @property
    def list_type_iri(self):
        """
        Return the list resource_type_iri for this view.
        """

        return f"{self.resource_type_iri}/list"


class AccessControlledModelViewSet(AccessControlledAPIView, ModelViewSet):
    def get_success_headers(self, instance, request=None):
        try:
            return {
                "Location": reverse(
                    self.basename + "-detail", args=[instance.id], request=request
                )
            }
        except (TypeError, KeyError):
            return {}

    def list(self, request, *args, **kwargs):
        # TODO restrict listing to authorized contexts
        return super().list(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.instance, request=request)
        # headers["etag"] = serializer.etag()
        # headers["last-modified"] = serializer.last_modified()
        # if serializer.link_header_content():
        # headers["link"] = serializer.link_header_content()
        return Response(
            serializer.data, status=status.HTTP_201_CREATED, headers=headers
        )

    def retrieve(self, request, *args, **kwargs):
        # TODO authorize
        return super().retrieve(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        # TODO authorize
        return super().update(request, *args, **kwargs)

    def perform_create(self, serializer):
        """
        Save the new object, rejecting it (and rolling the save back) if it was saved
        in the reserved `SOME_CONTEXT`. The save and the check run in a transaction
        on the model's write database (`router.db_for_write`).

        Subclasses overriding `perform_create` **MUST** call `super()`.
        """
        db = router.db_for_write(self.get_queryset().model)
        with transaction.atomic(using=db):
            super().perform_create(serializer)
            persisted = self.persisted_instance(serializer, db)
            self.check_not_reserved_context(persisted)

    def perform_update(self, serializer):
        """
        Save the update, then authorize it against the object as persisted, i.e.
        after `save()`, custom `Serializer.update()` logic, signals and
        many-to-many changes. A denial (403) or a reserved context (400) rolls the
        save back, so moving an object into another context requires permission
        there as well as in its current context (which `get_object()` checked).

        The save and the checks run in a transaction on the object's write database
        (`router.db_for_write`), and the checks use a fresh instance fetched from
        that database, never a read replica. Relation-based `rbac_contexts` must
        therefore query the instance's own database, e.g.
        `self.tags.using(self._state.db)`; otherwise a read router can answer them
        from a replica that does not see the update. Rolling a denied update back
        requires a transactional database backend (not e.g. MySQL's MyISAM).

        Subclasses overriding `perform_update` **MUST** call `super()`, or updates
        are only authorized against the object's state before the update. Side
        effects outside the database (e.g. signal handlers sending email) may run
        before a denial rolls the save back.
        """
        instance = serializer.instance
        db = router.db_for_write(type(instance), instance=instance)
        # Defensive: the checks after the save must use the grants the user had
        # before it, which policy_for caches on the request. Whenever IsAuthorized
        # is consulted, has_permission() and get_object() have already computed
        # that cache, so this line is redundant today; it keeps the guarantee for
        # permission setups that do not call policy_for before the save.
        policy_for(self.request)
        with transaction.atomic(using=db):
            super().perform_update(serializer)
            persisted = self.persisted_instance(serializer, db)
            self.check_object_permissions(self.request, persisted)
            self.check_not_reserved_context(persisted)

    def persisted_instance(self, serializer, db):
        """
        Return a fresh copy of `serializer.instance` read from `db`, and refresh
        `serializer.instance` from `db` so the response shows the persisted state.

        A fresh instance, rather than the refreshed one, is returned for the checks
        because `refresh_from_db` keeps per-instance caches such as a
        `cached_property` `rbac_contexts`.
        """
        instance = serializer.instance
        if instance._state.db != db:
            raise ImproperlyConfigured(
                f"{type(instance).__name__} was saved to database "
                f"{instance._state.db!r}, but its write database is {db!r}; the "
                "update cannot be authorized or rolled back."
            )
        instance.refresh_from_db(using=db)
        return type(instance)._base_manager.using(db).get(pk=instance.pk)

    def contexts_of(self, instance):
        """
        Return every rbac context `instance` is in: those reported by each
        permission class that defines `contexts_for` (e.g. an `IsAuthorized`
        subclass overriding it), plus the module-level `contexts_for` when the
        model has `rbac_context`/`rbac_contexts`.

        Permission classes nested in DRF's composed permissions (`&`, `|`, `~`) are
        not inspected, so their `contexts_for` overrides are not consulted here.
        """
        contexts = []
        model = type(instance)
        if hasattr(model, "rbac_contexts") or hasattr(model, "rbac_context"):
            contexts.extend(contexts_for(instance))
        for permission in self.get_permissions():
            if hasattr(permission, "contexts_for"):
                contexts.extend(permission.contexts_for(instance))
        return contexts

    def check_not_reserved_context(self, instance):
        """
        Raise a `ValidationError` if any of `instance`'s contexts is the reserved
        `SOME_CONTEXT`, under which every user's grants are also registered. Values
        that differ from it only by Unicode compatibility form (NFKC), case or
        surrounding whitespace are rejected too, since a case- or
        accent-insensitive database collation may treat them as equal.
        """
        if any(is_reserved_context(c) for c in self.contexts_of(instance)):
            raise ValidationError(
                f"{SOME_CONTEXT!r} is a reserved rbac_context and cannot be assigned "
                "to an object (this includes values that differ from it only by "
                "case, whitespace or Unicode compatibility form).",
                code="reserved_rbac_context",
            )

    def delete(self, request, *args, **kwargs):
        # TODO authorize
        return super().delete(request, *args, **kwargs)


@scrudful_viewset
class RoleViewSet(AccessControlledModelViewSet):
    """
    TODO restrict queryset to authorized contexts for user
    """

    class Meta:
        def etag_func(view_instance, request, pk: str, **kwargs):
            instance = get_object_or_404(Role, pk=int(pk))
            return instance.etag

        def last_modified_func(view_instance, request, pk: str, **kwargs):
            instance = get_object_or_404(Role, pk=int(pk))
            return instance.modified_at

    queryset = Role.objects.all()
    serializer_class = RoleSerializer
    pagination_class = DefaultPageNumberPagination

    @property
    def resource_type_iri(self):
        return Role.resource_type.iri


class RoleAssignmentViewSet(AccessControlledModelViewSet):
    """
    TODO restrict queryset to authorized contexts for user
    """

    class Meta:
        def etag_func(view_instance, request, pk: str, **kwargs):
            instance = get_object_or_404(RoleAssignment, pk=int(pk))
            return instance.etag

        def last_modified_func(view_instance, request, pk: str, **kwargs):
            instance = get_object_or_404(RoleAssignment, pk=int(pk))
            return instance.modified_at

    queryset = RoleAssignment.objects.all()
    serializer_class = RoleAssignmentSerializer
    pagination_class = DefaultPageNumberPagination

    @property
    def resource_type_iri(self):
        return RoleAssignment.resource_type.iri


class UserViewSet(AccessControlledModelViewSet):
    """
    API which allows users to be viewed or edited.
    TODO restrict queryset to authorized contexts for user
    """

    queryset = get_user_model().objects.all()
    serializer_class = UserSerializer
    pagination_class = DefaultPageNumberPagination

    @property
    def resource_type_iri(self):
        return UserResourceType.iri


class UserRbacPolicyView(APIView):
    permission_classes = [AllowAny]

    @property
    def resource_type_iri(self):
        return "rbac.Policy"

    def get(self, request):
        user_policy = policy_for(request)
        return Response(user_policy.to_json())
