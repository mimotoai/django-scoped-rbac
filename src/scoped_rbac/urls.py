from django.urls import path
from rest_framework.routers import DefaultRouter
from . import rest

router = DefaultRouter()
router.register(r"role-assignments", rest.RoleAssignmentViewSet)
router.register(r"roles", rest.RoleViewSet)

urlpatterns = router.urls + [
    path(
        "user-rbac-policy/", rest.UserRbacPolicyView.as_view(), name="user-rbac-policy"
    )
]
