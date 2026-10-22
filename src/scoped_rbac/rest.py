import unicodedata

from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.db import router, transaction
from django.shortcuts import get_object_or_404

# from django.urls import reverse
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import AND, NOT, OR, AllowAny
from rest_framework.response import Response
from rest_framework.reverse import reverse
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet
from scrudful.rest_framework import scrudful_viewset

from .filters import RbacFilter
from .models import Role, RoleAssignment, UserResourceType
from .permissions import IsAuthorized, policy_for
from .rbac_contexts import SOME_CONTEXT
from .serializers import RoleAssignmentSerializer, RoleSerializer, UserSerializer

_RESERVED_CONTEXT_PREFIX = "__"


def _is_reserved_context(context):
    """
    True if `context` is in the reserved namespace: after NFKC normalisation,
    removing format characters (Unicode category Cf, e.g. zero-width spaces and soft
    hyphens) and stripping whitespace, it starts with `_RESERVED_CONTEXT_PREFIX`.
    Non-string contexts are never reserved.
    """
    if not isinstance(context, str):
        return False
    normalized = unicodedata.normalize("NFKC", context)
    visible = "".join(c for c in normalized if unicodedata.category(c) != "Cf")
    return visible.strip().startswith(_RESERVED_CONTEXT_PREFIX)


def _leaf_permissions(permission):
    """
    Yield the permissions composed into `permission` by DRF's `&`, `|` and `~`
    (`AND`, `OR`, `NOT`), or `permission` itself if it is not composed.

    The operands are read from the undocumented `op1`/`op2` attributes; if a DRF
    version lacks them, the composed permission contributes nothing.
    """
    if isinstance(permission, (AND, OR)):
        operands = (getattr(permission, "op1", None), getattr(permission, "op2", None))
    elif isinstance(permission, NOT):
        operands = (getattr(permission, "op1", None),)
    else:
        yield permission
        return
    for operand in operands:
        if operand is not None:
            yield from _leaf_permissions(operand)


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
        Save the new object in a transaction on its write database and reject it
        (400, rolled back) if it was saved in a reserved context.

        Subclasses overriding this **MUST** call `super()`. Requires a transactional
        database backend, and `router.db_for_write` must not depend on mutable
        instance fields such as `rbac_context` (#42).
        """
        db = router.db_for_write(self.model_for(serializer))
        with transaction.atomic(using=db):
            super().perform_create(serializer)
            persisted = self.persisted_instance(serializer, db)
            self.check_not_reserved_context(persisted)

    def perform_update(self, serializer):
        """
        Save the update in a transaction on the object's write database, then check
        the persisted object: a changed primary key or a reserved context is
        rejected (400) and `check_post_save_permissions` must allow it (403); either
        rolls the save back.

        Subclasses overriding this **MUST** call `super()`. Requires a transactional
        database backend, and `router.db_for_write` must not depend on mutable
        instance fields such as `rbac_context` (#42). Relation-based `rbac_contexts`
        must query `self._state.db` (e.g. `self.tags.using(self._state.db)`), not
        the read router. The pre-save `get_object()` check runs outside the
        transaction, so a concurrent change before the save can be overwritten
        (#43).
        """
        instance = serializer.instance
        db = router.db_for_write(type(instance), instance=instance)
        pk_before = instance.pk
        # Not redundant: with e.g. `X | IsAuthorized`, DRF's OR short-circuits at X
        # before the save, so without this line the first policy_for call would be
        # the post-save check's, and it would see grants the update itself created
        # (e.g. the user's own RoleAssignment moved to another context).
        policy_for(self.request)
        with transaction.atomic(using=db):
            super().perform_update(serializer)
            if serializer.instance.pk != pk_before:
                raise ValidationError(
                    "The primary key cannot be changed by an update.",
                    code="primary_key_changed",
                )
            persisted = self.persisted_instance(serializer, db)
            self.check_post_save_permissions(self.request, persisted)
            self.check_not_reserved_context(persisted)

    def model_for(self, serializer):
        """
        The model `serializer` saves: its `Meta.model` (what a `ModelSerializer`
        creates), else the queryset's model.
        """
        meta = getattr(serializer, "Meta", None)
        return getattr(meta, "model", None) or self.get_queryset().model

    def get_post_save_permissions(self):
        """
        The permissions `check_post_save_permissions` applies to the saved object:
        by default every `IsAuthorized` (or subclass) in `get_permissions()`,
        including those nested in DRF's `&`, `|` and `~`. Other (application)
        permissions are not re-run against the new state.
        """
        return [
            leaf
            for permission in self.get_permissions()
            for leaf in _leaf_permissions(permission)
            if isinstance(leaf, IsAuthorized)
        ]

    def check_post_save_permissions(self, request, obj):
        """
        Deny (403) unless **every** post-save permission's `has_object_permission`
        allows the saved `obj`. Composition is ignored, so with `X | IsAuthorized`
        the destination still needs RBAC permission even when X allowed the
        request. Does nothing if there are no post-save permissions.
        """
        for permission in self.get_post_save_permissions():
            if not permission.has_object_permission(request, self, obj):
                self.permission_denied(
                    request,
                    message=getattr(permission, "message", None),
                    code=getattr(permission, "code", None),
                )

    def persisted_instance(self, serializer, db):
        """
        Refresh `serializer.instance` from `db` (for the response) and return a
        fresh copy read from `db` (for the checks; it has no per-instance caches).
        """
        instance = serializer.instance
        if instance._state.db != db:
            raise ImproperlyConfigured(
                f"{type(instance).__name__} was saved to database "
                f"{instance._state.db!r}, but its write database is {db!r}; the save "
                "cannot be checked or rolled back."
            )
        instance.refresh_from_db(using=db)
        return type(instance)._base_manager.using(db).get(pk=instance.pk)

    def contexts_of(self, instance):
        """
        Every rbac context of `instance`: its `rbac_context` and `rbac_contexts`
        (whichever the model has), plus those from the `contexts_for` of any
        permission (nested ones included) that overrides `IsAuthorized`'s.
        """
        contexts = []
        model = type(instance)
        if hasattr(model, "rbac_context"):
            contexts.append(instance.rbac_context)
        if hasattr(model, "rbac_contexts"):
            contexts.extend(instance.rbac_contexts or ())
        for permission in self.get_permissions():
            for leaf in _leaf_permissions(permission):
                leaf_contexts_for = getattr(type(leaf), "contexts_for", None)
                if leaf_contexts_for not in (None, IsAuthorized.contexts_for):
                    contexts.extend(leaf.contexts_for(instance))
        return contexts

    def check_not_reserved_context(self, instance):
        """
        Raise a `ValidationError` (400, code `reserved_rbac_context`) if any of
        `instance`'s contexts is reserved (starts with `__`, see
        `_is_reserved_context`).
        """
        if any(_is_reserved_context(c) for c in self.contexts_of(instance)):
            raise ValidationError(
                f"rbac contexts starting with {_RESERVED_CONTEXT_PREFIX!r} (such as "
                f"{SOME_CONTEXT!r}) are reserved and cannot be assigned to an object.",
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
