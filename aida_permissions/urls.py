from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    PermissionViewSet, PermissionCategoryViewSet,
    RoleViewSet, UserRoleViewSet, UserPermissionViewSet
)

router = DefaultRouter()
router.register(r'permissions', PermissionViewSet)
router.register(r'permission-categories', PermissionCategoryViewSet)
router.register(r'roles', RoleViewSet)
router.register(r'user-roles', UserRoleViewSet)
router.register(r'user-permissions', UserPermissionViewSet, basename='user-permissions')

app_name = 'aida_permissions'

urlpatterns = [
    path('', include(router.urls)),
]