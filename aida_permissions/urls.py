from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import PermissionCategoryViewSet, PermissionViewSet, RoleViewSet, UserPermissionViewSet, UserRoleViewSet

router = DefaultRouter()
router.register(r"permissions", PermissionViewSet)
router.register(r"permission-categories", PermissionCategoryViewSet)
router.register(r"roles", RoleViewSet)
router.register(r"user-roles", UserRoleViewSet)
router.register(r"user-permissions", UserPermissionViewSet, basename="user-permissions")

app_name = "aida_permissions"

urlpatterns = [
    path("", include(router.urls)),
]
