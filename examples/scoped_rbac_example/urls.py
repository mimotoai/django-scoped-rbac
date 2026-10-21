"""scoped_rbac_example URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.contrib import admin
from django.urls import include, path, re_path
from rest_framework.routers import DefaultRouter
from rest_framework.schemas import get_schema_view

import scoped_rbac.urls

router = DefaultRouter()
router.registry.extend(scoped_rbac.urls.router.registry)
schema_view = get_schema_view("Example Django Scoped RBAC API")

urlpatterns = [
    path("admin/", admin.site.urls),
    re_path(r"^api/", include(router.urls), name="api"),
    re_path(r"^api/schemas", schema_view, name="api-schema"),
    re_path(
        r"^api/rest-framework/auth",
        include("rest_framework.urls", namespace="rest_framework"),
    ),
]
