import unicodedata

from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.db import models, router, transaction
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


# Characters that render as nothing but are not in the removed categories.
_INVISIBLE_FILLERS = frozenset("\u115f\u1160\u3164\uffa0\u2800")
_INVISIBLE_CATEGORIES = frozenset({"Cf", "Cc", "Mn", "Me"})


def _is_reserved_context(context):
    """
    True if `context` is in the reserved namespace: after NFKC normalisation,
    removing invisible characters (Unicode categories Cf, Cc, Mn and Me, and the
    filler characters in `_INVISIBLE_FILLERS`) and stripping whitespace, it starts
    with `_RESERVED_CONTEXT_PREFIX`. Non-string contexts are never reserved.
    """
    if not isinstance(context, str):
        return False
    normalized = unicodedata.normalize("NFKC", context)
    visible = "".join(
        c
        for c in normalized
        if c not in _INVISIBLE_FILLERS
        and unicodedata.category(c) not in _INVISIBLE_CATEGORIES
    )
    return visible.strip().startswith(_RESERVED_CONTEXT_PREFIX)


def _is_saved_instance(instance):
    return (
        isinstance(instance, models.Model)
        and instance.pk is not None
        and not instance._state.adding
    )


_NO_RBAC_CONTEXT = object()


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

    def perform_create(self, serializer, **save_kwargs):
        """
        Call `serializer.save(**save_kwargs)` in a transaction on the model's write
        database and reject the new object (400, rolled back) if it is in a
        reserved context. With `many=True`, each created object is checked. Results
        of `save()` that are not saved model instances are not checked.

        Subclasses overriding this **MUST** call `super()`, passing any extra save
        arguments as `save_kwargs` (e.g. `owner=self.request.user`). Requires a
        transactional database backend, and `router.db_for_write` must not depend
        on mutable instance fields such as `rbac_context` (#42).
        """
        db = router.db_for_write(self.model_for(serializer))
        with transaction.atomic(using=db):
            serializer.save(**save_kwargs)
            created = serializer.instance
            if not isinstance(created, (list, tuple)):  # many=True gives a list
                created = [created]
            for instance in created:
                if _is_saved_instance(instance):
                    persisted = self._persisted_instance(instance, db)
                    self.check_not_reserved_context(persisted)

    def perform_update(self, serializer, **save_kwargs):
        """
        Call `serializer.save(**save_kwargs)` in a transaction on the object's write
        database, then check the persisted object: a changed primary key or a
        reserved context is rejected (400) and `check_post_save_permissions` must
        allow it (403); either rolls the save back.

        Subclasses overriding this **MUST** call `super()`, passing any extra save
        arguments as `save_kwargs`. Requires a transactional database backend, and
        `router.db_for_write` must not depend on mutable instance fields such as
        `rbac_context` (#42). Relation-based `rbac_contexts` must query
        `self._state.db` (e.g. `self.tags.using(self._state.db)`), not the read
        router. The pre-save `get_object()` check runs outside the transaction, so
        a concurrent change before the save can be overwritten (#43).
        """
        instance = serializer.instance
        model = type(instance)
        db = router.db_for_write(model, instance=instance)
        pk_before = instance.pk
        column_before = getattr(instance, "rbac_context", _NO_RBAC_CONTEXT)
        # Not redundant: with e.g. `X | IsAuthorized`, DRF's OR short-circuits at X
        # before the save, so without this line the first policy_for call would be
        # the post-save check's, and it would see grants the update itself created
        # (e.g. the user's own RoleAssignment moved to another context).
        policy_for(self.request)
        with transaction.atomic(using=db):
            serializer.save(**save_kwargs)
            if serializer.instance.pk != pk_before:
                raise ValidationError(
                    "The primary key cannot be changed by an update.",
                    code="primary_key_changed",
                )
            persisted = self._persisted_instance(serializer.instance, db)
            column_after = getattr(persisted, "rbac_context", _NO_RBAC_CONTEXT)
            moved_column = column_after is not _NO_RBAC_CONTEXT and (
                column_before is _NO_RBAC_CONTEXT or column_after != column_before
            )
            self.check_post_save_permissions(
                self.request,
                persisted,
                new_rbac_context=column_after if moved_column else None,
            )
            self.check_not_reserved_context(persisted)

    def model_for(self, serializer):
        """
        The model `serializer` saves: its `Meta.model` (what a `ModelSerializer`
        creates; for `many=True`, the child's), else the queryset's model.
        """
        meta = getattr(getattr(serializer, "child", serializer), "Meta", None)
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

    def check_post_save_permissions(self, request, obj, new_rbac_context=None):
        """
        Deny (403) unless **every** post-save permission's `has_object_permission`
        allows the saved `obj`. Composition is ignored, so with `X | IsAuthorized`
        the destination still needs RBAC permission even when X allowed the
        request. Does nothing if there are no post-save permissions.

        `new_rbac_context` is the new value of an `rbac_context` that the update
        changed. Each permission's `has_context_permission`, where defined, must
        then also allow the request in that context, whatever `contexts_for`
        reports (e.g. `rbac_contexts` or an override), because `RbacFilter` lists
        objects by `rbac_context`.
        """
        for permission in self.get_post_save_permissions():
            allowed = permission.has_object_permission(request, self, obj)
            if allowed and new_rbac_context is not None:
                has_context_permission = getattr(
                    permission, "has_context_permission", None
                )
                if has_context_permission is not None:
                    allowed = has_context_permission(
                        request, self, obj, new_rbac_context
                    )
            if not allowed:
                self.permission_denied(
                    request,
                    message=getattr(permission, "message", None),
                    code=getattr(permission, "code", None),
                )

    def _persisted_instance(self, instance, db):
        """
        Refresh the saved `instance` from `db` (for the response) and return a fresh
        copy read from `db` for the checks: through `get_queryset()`, so annotations
        are present, else (if it left the queryset) the base manager.
        """
        if instance._state.db != db:
            raise ImproperlyConfigured(
                f"{type(instance).__name__} was saved to database "
                f"{instance._state.db!r}, but its write database is {db!r}; the save "
                "cannot be checked or rolled back."
            )
        instance.refresh_from_db(using=db)
        model = type(instance)
        queryset = self.get_queryset()
        fresh = None
        if queryset.model is model:
            fresh = queryset.using(db).filter(pk=instance.pk).first()
        if fresh is None:
            fresh = model._base_manager.using(db).get(pk=instance.pk)
        return fresh

    def _written_contexts(self, instance):
        """
        Every rbac context of `instance`: its `rbac_context` and `rbac_contexts`
        (whichever the instance has, annotations included), plus those from the
        `contexts_for` of any permission (nested ones included) that overrides
        `IsAuthorized`'s.
        """
        contexts = []
        if hasattr(instance, "rbac_context"):
            contexts.append(instance.rbac_context)
        contexts.extend(getattr(instance, "rbac_contexts", None) or ())
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
        if any(_is_reserved_context(c) for c in self._written_contexts(instance)):
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
