from django.urls import include, re_path
from rest_framework.routers import DefaultRouter
from rest_framework.schemas import get_schema_view

import scoped_rbac.urls
from scoped_rbac.rest import UserViewSet

from . import rest

# from . import rest

router = DefaultRouter()
router.register(r"users", UserViewSet)
router.register(
    r"example-access-controlled-models", rest.ExampleAccessControlledModelViewSet
)
router.register(
    r"example-with-multiple-contexts", rest.ExampleMultipleContextsModelViewSet
)

# router.registry.extend(scoped_rbac.urls.router.registry)
schema_view = get_schema_view("Test Scoped RBAC API")

urlpatterns = [
    re_path(r"^api/", include(router.urls), name="api"),
    re_path(r"^api/scoped-rbac/", include(scoped_rbac.urls), name="scoped-rbac"),
    re_path(r"^api/schema", schema_view, name="api-schema"),
    re_path(
        r"^api/rest-framework/auth",
        include("rest_framework.urls", namespace="rest_framework"),
    ),
]
