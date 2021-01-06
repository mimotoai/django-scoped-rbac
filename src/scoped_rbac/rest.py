from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404

# from django.urls import reverse
from rest_framework import status
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.reverse import reverse
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet
from scrudful.rest_framework import scrudful_viewset
from .filters import RbacFilter
from .models import Role, RoleAssignment, UserResourceType
from .permissions import policy_for
from .serializers import RoleSerializer, RoleAssignmentSerializer, UserSerializer


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

    def delete(self, request, *args, **kwargs):
        # TODO authorize
        return super().delete(request, *args, **kwargs)


@scrudful_viewset
class RoleViewSet(AccessControlledModelViewSet):
    """
    TODO restrict queryset to authorized contexts for user
    """

    class Meta:
        def etag_func(view_instance, request, pk: str):
            instance = get_object_or_404(Role, pk=int(pk))
            return instance.etag

        def last_modified_func(view_instance, request, pk: str):
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
        def etag_func(view_instance, request, pk: str):
            instance = get_object_or_404(RoleAssignment, pk=int(pk))
            return instance.etag

        def last_modified_func(view_instance, request, pk: str):
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
    permission_classes = [IsAuthenticated]

    @property
    def resource_type_iri(self):
        return "rbac.Policy"

    def get(self, request):
        user_policy = policy_for(request)
        return Response(user_policy.to_json())
