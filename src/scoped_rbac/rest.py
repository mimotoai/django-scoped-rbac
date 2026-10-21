from django.contrib.auth import get_user_model
from django.db import transaction
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
        in the reserved `SOME_CONTEXT`.

        Subclasses overriding `perform_create` **MUST** call `super()`.
        """
        with transaction.atomic():
            super().perform_create(serializer)
            instance = serializer.instance
            instance.refresh_from_db()
            self.check_not_reserved_context(instance)

    def perform_update(self, serializer):
        """
        Save the update, then authorize it against the object as persisted, i.e.
        after `save()`, custom `Serializer.update()` logic, signals and
        many-to-many changes. A denial (403) or a reserved context (400) rolls the
        save back, so moving an object into another context requires permission
        there as well as in its current context (which `get_object()` checked).

        Subclasses overriding `perform_update` **MUST** call `super()`, or updates
        are only authorized against the object's state before the update. Side
        effects outside the database (e.g. signal handlers sending email) may run
        before a denial rolls the save back.
        """
        # Snapshot the user's grants before saving: the update may change their own
        # RoleAssignments, and the check below must not see grants it created.
        policy_for(self.request)
        with transaction.atomic():
            super().perform_update(serializer)
            instance = serializer.instance
            instance.refresh_from_db()
            self.check_object_permissions(self.request, instance)
            self.check_not_reserved_context(instance)

    def check_not_reserved_context(self, instance):
        """
        Raise a `ValidationError` if `instance` is in the reserved `SOME_CONTEXT`,
        under which every user's grants are also registered.
        """
        model = type(instance)
        if not (hasattr(model, "rbac_contexts") or hasattr(model, "rbac_context")):
            return
        if SOME_CONTEXT in contexts_for(instance):
            raise ValidationError(
                f"{SOME_CONTEXT!r} is a reserved rbac_context and cannot be assigned "
                "to an object.",
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
