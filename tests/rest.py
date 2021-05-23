from rest_framework import status
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework_condition import last_modified, condition
from rest_framework_extensions.etag.decorators import etag
from scoped_rbac.rest import AccessControlledModelViewSet, DefaultPageNumberPagination
from scoped_rbac.permissions import IsAuthorized
from scoped_rbac.rbac_contexts import DEFAULT_CONTEXT
from .models import ExampleAccessControlledModel, ExampleWithMultipleContexts
from .serializers import ExampleAccessControlledModelSerializer, ExampleWithMultipleContextsSerializer
import logging


class ExampleAccessControlledModelViewSet(AccessControlledModelViewSet):

    queryset = ExampleAccessControlledModel.objects.all()
    serializer_class = ExampleAccessControlledModelSerializer
    pagination_class = DefaultPageNumberPagination
    permission_classes = [IsAuthorized]

    def context_id_for(self, request):
        return DEFAULT_CONTEXT

    @property
    def resource_type_iri(self):
        return f"{ExampleAccessControlledModel.resource_type.iri}"

    @condition(
        last_modified_func=ExampleAccessControlledModelSerializer.collection_last_modified,
        etag_func=ExampleAccessControlledModelSerializer.collection_etag,
    )
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.instance)
        logging.debug(headers)
        headers["etag"] = serializer.etag()
        headers["last-modified"] = serializer.last_modified()
        if serializer.link_header_content():
            headers["link"] = serializer.link_header_content()
        return Response(
            serializer.data, status=status.HTTP_201_CREATED, headers=headers
        )

    @condition(
        last_modified_func=ExampleAccessControlledModelSerializer.last_modified_for,
        etag_func=ExampleAccessControlledModelSerializer.etag_for,
    )
    def retrieve(self, request, *args, **kwargs):
        ret = super().retrieve(request, *args, **kwargs)
        serializer = self.get_serializer()
        if serializer.link_header_content():
            ret["link"] = serializer.link_header_content(**kwargs)
        return ret

    @condition(
        last_modified_func=ExampleAccessControlledModelSerializer.last_modified_for,
        etag_func=ExampleAccessControlledModelSerializer.etag_for,
    )
    def update(self, request, *args, **kwargs):
        ret = super().update(request, *args, **kwargs)
        headers["etag"] = serializer.etag()
        headers["last-modified"] = serializer.last_modified()
        return ret

    @condition(
        last_modified_func=ExampleAccessControlledModelSerializer.last_modified_for,
        etag_func=ExampleAccessControlledModelSerializer.etag_for,
    )
    def destroy(self, request, *args, **kwargs):
        return super().delete(request, *args, **kwargs)


class ExampleMultipleContextsModelViewSet(AccessControlledModelViewSet):

    type_iri = f"{ExampleWithMultipleContexts.resource_type.iri}"
    queryset = ExampleWithMultipleContexts.objects.all()
    serializer_class = ExampleWithMultipleContextsSerializer
    pagination_class = DefaultPageNumberPagination
    permission_classes = [IsAuthorized]

    def context_id_for(self, request):
        return DEFAULT_CONTEXT

    @property
    def resource_type_iri(self):
        return self.type_iri

    @condition(
        last_modified_func=ExampleWithMultipleContextsSerializer.collection_last_modified,
        etag_func=ExampleAccessControlledModelSerializer.collection_etag,
    )
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.instance)
        logging.debug(headers)
        headers["etag"] = serializer.etag()
        headers["last-modified"] = serializer.last_modified()
        if serializer.link_header_content():
            headers["link"] = serializer.link_header_content()
        return Response(
            serializer.data, status=status.HTTP_201_CREATED, headers=headers
        )

    @condition(
        last_modified_func=ExampleAccessControlledModelSerializer.last_modified_for,
        etag_func=ExampleAccessControlledModelSerializer.etag_for,
    )
    def retrieve(self, request, *args, **kwargs):
        ret = super().retrieve(request, *args, **kwargs)
        serializer = self.get_serializer()
        if serializer.link_header_content():
            ret["link"] = serializer.link_header_content(**kwargs)
        return ret

    @condition(
        last_modified_func=ExampleAccessControlledModelSerializer.last_modified_for,
        etag_func=ExampleAccessControlledModelSerializer.etag_for,
    )
    def update(self, request, *args, **kwargs):
        ret = super().update(request, *args, **kwargs)
        headers["etag"] = serializer.etag()
        headers["last-modified"] = serializer.last_modified()
        return ret

    @condition(
        last_modified_func=ExampleAccessControlledModelSerializer.last_modified_for,
        etag_func=ExampleAccessControlledModelSerializer.etag_for,
    )
    def destroy(self, request, *args, **kwargs):
        return super().delete(request, *args, **kwargs)
